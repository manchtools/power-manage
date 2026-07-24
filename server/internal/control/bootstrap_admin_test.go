package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manchtools/power-manage/server/internal/auth"
)

const bootstrapTestEmail = "admin@example.test"

func TestBootstrapAdmin_FirstBootMintsHashOnlySingleUseSession(t *testing.T) {
	refresh, _, verifier, clock, eventStore, pool := newTestRefreshService(t)
	entropy := bootstrapTestEntropy()
	minter, err := auth.NewBootstrapAdminMinter(eventStore, bytes.NewReader(entropy), clock.Now)
	if err != nil {
		t.Fatalf("create bootstrap admin minter: %v", err)
	}
	loginURL, err := minter.Mint(
		t.Context(),
		strings.ToUpper(bootstrapTestEmail),
		"https://control.example.test/break-glass",
	)
	if err != nil {
		t.Fatalf("mint first-boot login URL: %v", err)
	}
	rawToken := bootstrapTokenFromURL(t, loginURL)

	var userCreated, adminGranted, loginMinted int
	var persistedPayloads string
	if err := pool.QueryRow(t.Context(), `
		SELECT
			count(*) FILTER (WHERE event_type = 'UserCreated'),
			count(*) FILTER (WHERE event_type = 'BootstrapAdminRoleGranted'),
			count(*) FILTER (WHERE event_type = 'BootstrapLoginMinted'),
			string_agg(payload::text, '')
		FROM events`).Scan(&userCreated, &adminGranted, &loginMinted, &persistedPayloads); err != nil {
		t.Fatalf("inspect bootstrap audit events: %v", err)
	}
	if userCreated != 1 || adminGranted != 1 || loginMinted != 1 {
		t.Fatalf(
			"bootstrap events = (user %d, grant %d, mint %d); want one each",
			userCreated,
			adminGranted,
			loginMinted,
		)
	}
	if strings.Contains(persistedPayloads, rawToken) {
		t.Fatal("raw bootstrap secret persisted in event payloads")
	}

	consumer, err := auth.NewBootstrapAdminConsumer(eventStore, refresh, clock.Now)
	if err != nil {
		t.Fatalf("create bootstrap admin consumer: %v", err)
	}
	tokens, err := consumer.Consume(t.Context(), rawToken)
	if err != nil {
		t.Fatalf("consume first-boot login: %v", err)
	}
	claims, err := verifier.VerifyAccess(tokens.AccessToken)
	if err != nil || claims.Subject == "" {
		t.Fatalf("verify bootstrap access token = (%+v, %v); want user subject", claims, err)
	}
	if _, err := consumer.Consume(t.Context(), rawToken); !errors.Is(err, auth.ErrBootstrapRejected) {
		t.Fatalf("replay bootstrap login error = %v; want %v", err, auth.ErrBootstrapRejected)
	}
	var consumedEvents int
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*)
		FROM events
		WHERE event_type = 'BootstrapLoginConsumed'`).Scan(&consumedEvents); err != nil {
		t.Fatalf("count bootstrap consume events: %v", err)
	}
	if consumedEvents != 1 {
		t.Fatalf("bootstrap consume events = %d; want one audit event", consumedEvents)
	}
}

func TestBootstrapAdmin_ExistingUserIsReused(t *testing.T) {
	_, _, _, clock, eventStore, pool := newTestRefreshService(t)
	minter, err := auth.NewBootstrapAdminMinter(
		eventStore,
		bytes.NewReader(bootstrapTestEntropy()),
		clock.Now,
	)
	if err != nil {
		t.Fatalf("create bootstrap admin minter: %v", err)
	}
	var loginURLs []string
	for range 2 {
		loginURL, err := minter.Mint(
			t.Context(),
			bootstrapTestEmail,
			"https://control.example.test/break-glass",
		)
		if err != nil {
			t.Fatalf("mint bootstrap login: %v", err)
		}
		loginURLs = append(loginURLs, loginURL)
	}
	if loginURLs[0] == loginURLs[1] {
		t.Fatal("repeated bootstrap mint returned the same secret URL")
	}
	var users, grants, logins int
	if err := pool.QueryRow(t.Context(), `
		SELECT
			count(*) FILTER (WHERE event_type = 'UserCreated'),
			count(*) FILTER (WHERE event_type = 'BootstrapAdminRoleGranted'),
			count(*) FILTER (WHERE event_type = 'BootstrapLoginMinted')
		FROM events`).Scan(&users, &grants, &logins); err != nil {
		t.Fatalf("count existing-user bootstrap events: %v", err)
	}
	if users != 1 || grants != 1 || logins != 2 {
		t.Fatalf(
			"existing-user events = (users %d, grants %d, logins %d); want (1, 1, 2)",
			users,
			grants,
			logins,
		)
	}
}

func TestBootstrapAdmin_ConcurrentConsumeHasOneWinner(t *testing.T) {
	refresh, _, _, clock, eventStore, pool := newTestRefreshService(t)
	minter, err := auth.NewBootstrapAdminMinter(
		eventStore,
		bytes.NewReader(bootstrapTestEntropy()),
		clock.Now,
	)
	if err != nil {
		t.Fatalf("create bootstrap admin minter: %v", err)
	}
	loginURL, err := minter.Mint(
		t.Context(),
		bootstrapTestEmail,
		"https://control.example.test/break-glass",
	)
	if err != nil {
		t.Fatalf("mint bootstrap login: %v", err)
	}
	consumer, err := auth.NewBootstrapAdminConsumer(eventStore, refresh, clock.Now)
	if err != nil {
		t.Fatalf("create bootstrap admin consumer: %v", err)
	}
	rawToken := bootstrapTokenFromURL(t, loginURL)

	barrierPool, err := pgxpool.New(t.Context(), pool.Config().ConnString())
	if err != nil {
		t.Fatalf("create bootstrap race barrier pool: %v", err)
	}
	defer barrierPool.Close()
	lockTx, err := barrierPool.Begin(t.Context())
	if err != nil {
		t.Fatalf("begin bootstrap race barrier: %v", err)
	}
	defer func() {
		_ = lockTx.Rollback(t.Context())
	}()
	if _, err := lockTx.Exec(t.Context(), "LOCK TABLE events IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatalf("lock event store for bootstrap race: %v", err)
	}

	start := make(chan struct{})
	ready := make(chan struct{}, 2)
	results := make(chan error, 2)
	for range 2 {
		go func() {
			ready <- struct{}{}
			<-start
			_, err := consumer.Consume(t.Context(), rawToken)
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-ready:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for bootstrap consumers")
		}
	}
	close(start)
	deadline := time.Now().Add(5 * time.Second)
	for pool.Stat().AcquiredConns() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if pool.Stat().AcquiredConns() < 2 {
		t.Fatalf(
			"bootstrap consumers did not reach the append barrier: %d acquired connections",
			pool.Stat().AcquiredConns(),
		)
	}
	if err := lockTx.Commit(t.Context()); err != nil {
		t.Fatalf("release bootstrap race barrier: %v", err)
	}

	successes, rejections := 0, 0
	for range 2 {
		select {
		case err := <-results:
			switch {
			case err == nil:
				successes++
			case errors.Is(err, auth.ErrBootstrapRejected):
				rejections++
			default:
				t.Fatalf("concurrent bootstrap consume error = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for bootstrap consume result")
		}
	}
	if successes != 1 || rejections != 1 {
		t.Fatalf("bootstrap race = (%d successes, %d rejections); want one each", successes, rejections)
	}
	var sessions int
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*)
		FROM events
		WHERE event_type = 'RefreshFamilyStarted'`).Scan(&sessions); err != nil {
		t.Fatalf("count bootstrap sessions: %v", err)
	}
	if sessions != 1 {
		t.Fatalf("bootstrap race created %d sessions; want exactly one", sessions)
	}
}

func TestBootstrapAdmin_ExpiryAndMalformedTokensShareStaticRejection(t *testing.T) {
	refresh, _, _, clock, eventStore, _ := newTestRefreshService(t)
	minter, err := auth.NewBootstrapAdminMinter(
		eventStore,
		bytes.NewReader(bootstrapTestEntropy()),
		clock.Now,
	)
	if err != nil {
		t.Fatalf("create bootstrap admin minter: %v", err)
	}
	loginURL, err := minter.Mint(
		t.Context(),
		bootstrapTestEmail,
		"https://control.example.test/break-glass",
	)
	if err != nil {
		t.Fatalf("mint bootstrap login: %v", err)
	}
	consumer, err := auth.NewBootstrapAdminConsumer(eventStore, refresh, clock.Now)
	if err != nil {
		t.Fatalf("create bootstrap admin consumer: %v", err)
	}
	clock.now = clock.now.Add(10 * time.Minute)
	for _, token := range []string{
		bootstrapTokenFromURL(t, loginURL),
		"",
		"not-a-bootstrap-token",
		strings.Repeat("x", 8193),
	} {
		if _, err := consumer.Consume(t.Context(), token); !errors.Is(err, auth.ErrBootstrapRejected) ||
			err.Error() != auth.ErrBootstrapRejected.Error() {
			t.Fatalf("bootstrap rejection for %q = %v; want exact static rejection", token, err)
		}
	}
}

func TestBootstrapAdminHTTPHandler_IsBoundedPostOnlyAndCookieFree(t *testing.T) {
	consumer := &bootstrapConsumerStub{
		tokens: auth.SessionTokens{AccessToken: "access", RefreshToken: "refresh"},
	}
	path, handler, err := NewBootstrapAdminHTTPHandler(consumer)
	if err != nil {
		t.Fatalf("create bootstrap HTTP handler: %v", err)
	}
	if path != "/bootstrap-admin/session" {
		t.Fatalf("bootstrap handler path = %q; want /bootstrap-admin/session", path)
	}

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		request := httptest.NewRequest(method, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status = %d; want 405", method, response.Code)
		}
		if response.Header().Get("Allow") != http.MethodPost {
			t.Fatalf("%s Allow = %q; want POST", method, response.Header().Get("Allow"))
		}
	}

	body, err := json.Marshal(map[string]string{"token": "fragment-secret"})
	if err != nil {
		t.Fatalf("encode bootstrap request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("bootstrap handler status = %d, body %q; want 200", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("bootstrap response headers = %v; want no-store and no cookie", response.Header())
	}
	var decoded map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode bootstrap response: %v", err)
	}
	if decoded["access_token"] != "access" || decoded["refresh_token"] != "refresh" {
		t.Fatalf("bootstrap response = %v; want ordinary token pair", decoded)
	}
	if consumer.token != "fragment-secret" {
		t.Fatalf("consumer token = %q; want JSON body token", consumer.token)
	}

	for _, test := range []struct {
		name       string
		err        error
		wantStatus int
		wantBody   string
	}{
		{
			name:       "rejected",
			err:        auth.ErrBootstrapRejected,
			wantStatus: http.StatusUnauthorized,
			wantBody:   `{"error":"bootstrap login rejected"}` + "\n",
		},
		{
			name:       "unavailable",
			err:        auth.ErrBootstrapUnavailable,
			wantStatus: http.StatusServiceUnavailable,
			wantBody:   `{"error":"bootstrap login unavailable"}` + "\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			consumer.err = test.err
			request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus || response.Body.String() != test.wantBody {
				t.Fatalf(
					"bootstrap %s response = (%d, %q); want (%d, %q)",
					test.name,
					response.Code,
					response.Body.String(),
					test.wantStatus,
					test.wantBody,
				)
			}
		})
	}
	consumer.err = nil

	oversized := httptest.NewRequest(
		http.MethodPost,
		path,
		strings.NewReader(`{"token":"`+strings.Repeat("x", 8193)+`"}`),
	)
	oversized.Header.Set("Content-Type", "application/json")
	oversizedResponse := httptest.NewRecorder()
	handler.ServeHTTP(oversizedResponse, oversized)
	if oversizedResponse.Code != http.StatusBadRequest {
		t.Fatalf("oversized bootstrap status = %d; want 400", oversizedResponse.Code)
	}
}

func bootstrapTestEntropy() []byte {
	entropy := make([]byte, 4096)
	for index := range entropy {
		entropy[index] = byte(index)
	}
	return entropy
}

func bootstrapTokenFromURL(t *testing.T, rawURL string) string {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse bootstrap login URL: %v", err)
	}
	if parsed.Scheme != "https" || parsed.RawQuery != "" || parsed.User != nil {
		t.Fatalf("bootstrap login URL = %q; want HTTPS without query or userinfo", rawURL)
	}
	const prefix = "bootstrap_token="
	if !strings.HasPrefix(parsed.Fragment, prefix) {
		t.Fatalf("bootstrap URL fragment = %q; want %q prefix", parsed.Fragment, prefix)
	}
	token := strings.TrimPrefix(parsed.Fragment, prefix)
	if token == "" {
		t.Fatal("bootstrap URL token is empty")
	}
	return token
}

type bootstrapConsumerStub struct {
	mu     sync.Mutex
	token  string
	tokens auth.SessionTokens
	err    error
}

func (s *bootstrapConsumerStub) Consume(_ context.Context, token string) (auth.SessionTokens, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.token = token
	return s.tokens, s.err
}
