package control

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	oidcTestClientID     = "power-manage-test"
	oidcTestClientSecret = "test-client-secret"
	oidcTestRedirect     = "https://console.example.test/callback"
	oidcTestLoopback     = "http://127.0.0.1:41731/callback"
)

func TestOIDCService_StartBuildsBoundPKCENonceAndAllowlistedRedirect(t *testing.T) {
	fixture := newOIDCTestFixture(t, false)

	if _, err := fixture.service.Start(t.Context(), "unknown", oidcTestRedirect); !errors.Is(err, auth.ErrOIDCRejected) {
		t.Fatalf("unknown-provider start error = %v; want %v", err, auth.ErrOIDCRejected)
	}
	if _, err := fixture.service.Start(
		t.Context(),
		fixture.provider.Slug,
		"https://attacker.example/callback",
	); !errors.Is(err, auth.ErrOIDCRejected) {
		t.Fatalf("unlisted-redirect start error = %v; want %v", err, auth.ErrOIDCRejected)
	}

	start := fixture.start(t, oidcTestRedirect, "start-subject", "start@example.test")
	query := start.authorization.Query()
	wantQuery := map[string]string{
		"response_type":         "code",
		"client_id":             oidcTestClientID,
		"redirect_uri":          oidcTestRedirect,
		"scope":                 "openid email",
		"state":                 start.state,
		"nonce":                 start.nonce,
		"code_challenge":        start.challenge,
		"code_challenge_method": "S256",
	}
	for key, want := range wantQuery {
		if got := query.Get(key); got != want {
			t.Fatalf("authorization query %s = %q; want %q", key, got, want)
		}
	}
	if start.authorization.Scheme != "https" ||
		start.authorization.Host != fixture.authorizationEndpoint.Host ||
		start.authorization.Path != fixture.authorizationEndpoint.Path {
		t.Fatalf("authorization endpoint = %s; want %s", start.authorization, fixture.authorizationEndpoint)
	}

	stateHash := sha256.Sum256([]byte(start.state))
	var verifier, nonce string
	var expiresAt time.Time
	if err := fixture.pool.QueryRow(t.Context(), `
		SELECT code_verifier, nonce, expires_at
		FROM oidc_login_states
		WHERE state_hash = $1`, stateHash[:]).Scan(&verifier, &nonce, &expiresAt); err != nil {
		t.Fatalf("inspect stored OIDC binding: %v", err)
	}
	challenge := sha256.Sum256([]byte(verifier))
	if got := base64.RawURLEncoding.EncodeToString(challenge[:]); got != start.challenge {
		t.Fatalf("stored-verifier challenge = %q; want %q", got, start.challenge)
	}
	if nonce != start.nonce || !expiresAt.Equal(fixture.clock.now.Add(10*time.Minute)) {
		t.Fatalf("stored binding = (nonce %q, expiry %s); want (%q, %s)",
			nonce, expiresAt, start.nonce, fixture.clock.now.Add(10*time.Minute))
	}

	if _, err := fixture.service.Start(t.Context(), fixture.provider.Slug, oidcTestLoopback); err != nil {
		t.Fatalf("explicitly allowlisted loopback redirect: %v", err)
	}
}

func TestOIDCService_UsesManagedPublicClientProviderAndHonorsDisable(t *testing.T) {
	fixture := newOIDCTestFixture(t, false)
	config := store.OIDCProviderMetadata{
		Slug:                  "managed",
		Issuer:                fixture.provider.Issuer,
		ClientID:              fixture.provider.ClientID,
		AuthorizationEndpoint: fixture.provider.AuthorizationEndpoint,
		TokenURL:              fixture.provider.TokenEndpoint,
		JWKSURI:               fixture.provider.JWKSURI,
		RedirectURIs:          []string{oidcTestRedirect},
		TrustEmailAssertions:  true,
	}
	created, err := store.OIDCProviderConfigCreatedEvent(config)
	if err != nil {
		t.Fatalf("create managed OIDC provider: %v", err)
	}
	if err := fixture.eventStore.AppendEventWithVersion(t.Context(), created, 0); err != nil {
		t.Fatalf("append managed OIDC provider: %v", err)
	}
	entropy := make([]byte, 4096)
	for index := range entropy {
		entropy[index] = byte((index*29 + 7) % 251)
	}
	service, err := auth.NewOIDCService(
		fixture.eventStore,
		fixture.refresh,
		nil,
		fixture.server.Client(),
		bytes.NewReader(entropy),
		fixture.clock.Now,
	)
	if err != nil {
		t.Fatalf("create management-only OIDC service: %v", err)
	}
	authorizationURL, err := service.Start(t.Context(), config.Slug, oidcTestRedirect)
	if err != nil {
		t.Fatalf("start managed OIDC provider: %v", err)
	}
	authorization := mustParseURL(t, authorizationURL)
	if authorization.Query().Get("client_id") != config.ClientID {
		t.Fatalf("managed client ID = %q; want %q", authorization.Query().Get("client_id"), config.ClientID)
	}

	config.Disabled = true
	disabled, err := store.OIDCProviderConfigUpdatedEvent(config)
	if err != nil {
		t.Fatalf("create managed OIDC provider disable: %v", err)
	}
	if err := fixture.eventStore.AppendEventWithVersion(t.Context(), disabled, 1); err != nil {
		t.Fatalf("append managed OIDC provider disable: %v", err)
	}
	if _, err := service.Start(
		t.Context(),
		config.Slug,
		oidcTestRedirect,
	); !errors.Is(err, auth.ErrOIDCRejected) {
		t.Fatalf("disabled managed-provider start error = %v; want %v", err, auth.ErrOIDCRejected)
	}
	before := fixture.tokenRequests()
	if _, err := service.Complete(
		t.Context(),
		authorization.Query().Get("state"),
		"good-code",
	); !errors.Is(err, auth.ErrOIDCRejected) {
		t.Fatalf("disabled managed-provider completion error = %v; want %v", err, auth.ErrOIDCRejected)
	}
	if got := fixture.tokenRequests(); got != before {
		t.Fatalf("disabled managed-provider completion made %d token requests; want %d", got, before)
	}
}

func TestOIDCService_CompleteRejectsReplayExpiryNonceIssuerAndAudience(t *testing.T) {
	fixture := newOIDCTestFixture(t, false)

	t.Run("replay", func(t *testing.T) {
		start := fixture.start(t, oidcTestRedirect, "replay-subject", "replay@example.test")
		if _, err := fixture.service.Complete(t.Context(), start.state, "good-code"); err != nil {
			t.Fatalf("first OIDC completion: %v", err)
		}
		if _, err := fixture.service.Complete(t.Context(), start.state, "good-code"); !errors.Is(err, auth.ErrOIDCRejected) {
			t.Fatalf("replayed completion error = %v; want %v", err, auth.ErrOIDCRejected)
		}
	})

	t.Run("expiry burns state before network", func(t *testing.T) {
		start := fixture.start(t, oidcTestRedirect, "expired-subject", "expired@example.test")
		before := fixture.tokenRequests()
		fixture.clock.now = fixture.clock.now.Add(10 * time.Minute)
		if _, err := fixture.service.Complete(t.Context(), start.state, "good-code"); !errors.Is(err, auth.ErrOIDCRejected) {
			t.Fatalf("expired completion error = %v; want %v", err, auth.ErrOIDCRejected)
		}
		if got := fixture.tokenRequests(); got != before {
			t.Fatalf("expired completion made %d token requests; want %d", got, before)
		}
		if _, err := fixture.service.Complete(t.Context(), start.state, "good-code"); !errors.Is(err, auth.ErrOIDCRejected) {
			t.Fatalf("expired-state replay error = %v; want %v", err, auth.ErrOIDCRejected)
		}
	})

	tests := []struct {
		name   string
		mutate func(*oidcTestClaims)
	}{
		{
			name: "nonce mismatch",
			mutate: func(claims *oidcTestClaims) {
				claims.Nonce = "wrong-nonce"
			},
		},
		{
			name: "issuer mismatch",
			mutate: func(claims *oidcTestClaims) {
				claims.Issuer = "https://unconfigured.example.test"
			},
		},
		{
			name: "audience mismatch",
			mutate: func(claims *oidcTestClaims) {
				claims.Audience = []string{"another-client"}
			},
		},
		{
			name: "expired ID token",
			mutate: func(claims *oidcTestClaims) {
				claims.ExpiresAt = fixture.clock.now.Unix()
			},
		},
		{
			name: "future issued ID token",
			mutate: func(claims *oidcTestClaims) {
				claims.IssuedAt = fixture.clock.now.Add(5*time.Minute + time.Second).Unix()
				claims.ExpiresAt = claims.IssuedAt + int64(5*time.Minute/time.Second)
			},
		},
		{
			name: "multiple audiences without authorized party",
			mutate: func(claims *oidcTestClaims) {
				claims.Audience = []string{oidcTestClientID, "another-client"}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			start := fixture.start(
				t,
				oidcTestRedirect,
				strings.ReplaceAll(test.name, " ", "-"),
				strings.ReplaceAll(test.name, " ", "-")+"@example.test",
			)
			fixture.mutateClaims(test.mutate)
			if _, err := fixture.service.Complete(t.Context(), start.state, "good-code"); !errors.Is(err, auth.ErrOIDCRejected) {
				t.Fatalf("completion error = %v; want %v", err, auth.ErrOIDCRejected)
			}
		})
	}
}

func TestOIDCService_AutoLinkRequiresVerifiedEmailAndProviderTrust(t *testing.T) {
	fixture := newOIDCTestFixture(t, false)
	const (
		userID        = "01K0QJ3E5E8R4M0D8EV3Y4N6K2"
		existingEmail = "linked@example.test"
	)
	created, err := store.UserCreatedEvent(userID, existingEmail)
	if err != nil {
		t.Fatalf("create existing user event: %v", err)
	}
	linked, err := store.OIDCIdentityLinkedEvent(
		userID,
		"existing",
		"https://existing-idp.example.test",
		"existing-subject",
		existingEmail,
	)
	if err != nil {
		t.Fatalf("create existing identity event: %v", err)
	}
	if err := fixture.eventStore.AppendEvents(t.Context(), []store.Event{created, linked}); err != nil {
		t.Fatalf("seed existing linked user: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*oidcTestClaims)
	}{
		{
			name: "false",
			mutate: func(claims *oidcTestClaims) {
				claims.EmailVerified = false
			},
		},
		{
			name: "absent",
			mutate: func(claims *oidcTestClaims) {
				claims.IncludeEmailVerified = false
			},
		},
	} {
		t.Run("email_verified "+test.name, func(t *testing.T) {
			unverified := fixture.start(t, oidcTestRedirect, "incoming-subject", existingEmail)
			fixture.mutateClaims(test.mutate)
			if _, err := fixture.service.Complete(t.Context(), unverified.state, "good-code"); !errors.Is(err, auth.ErrOIDCRejected) {
				t.Fatalf("unverified auto-link error = %v; want %v", err, auth.ErrOIDCRejected)
			}
		})
	}

	untrusted := fixture.start(t, oidcTestRedirect, "incoming-subject", existingEmail)
	if _, err := fixture.service.Complete(t.Context(), untrusted.state, "good-code"); !errors.Is(err, auth.ErrOIDCRejected) {
		t.Fatalf("untrusted cross-provider link error = %v; want %v", err, auth.ErrOIDCRejected)
	}
	if count, err := fixture.eventStore.UserOIDCIdentityCount(t.Context(), userID); err != nil || count != 1 {
		t.Fatalf("identity count after rejected links = (%d, %v); want (1, nil)", count, err)
	}

	trustedService := fixture.newService(t, true)
	trusted := fixture.startWithService(
		t,
		trustedService,
		oidcTestRedirect,
		"incoming-subject",
		existingEmail,
	)
	tokens, err := trustedService.Complete(t.Context(), trusted.state, "good-code")
	if err != nil {
		t.Fatalf("trusted cross-provider link: %v", err)
	}
	claims, err := fixture.verifier.VerifyAccess(tokens.AccessToken)
	if err != nil || claims.Subject != userID {
		t.Fatalf("trusted linked session = (%+v, %v); want subject %s", claims, err, userID)
	}
	if count, err := fixture.eventStore.UserOIDCIdentityCount(t.Context(), userID); err != nil || count != 2 {
		t.Fatalf("identity count after trusted link = (%d, %v); want (2, nil)", count, err)
	}
}

func TestOIDCService_CompleteCreatesOrdinaryRotatingSession(t *testing.T) {
	fixture := newOIDCTestFixture(t, false)
	start := fixture.start(t, oidcTestRedirect, "new-subject", "new-user@example.test")
	tokens, err := fixture.service.Complete(t.Context(), start.state, "authorization-code")
	if err != nil {
		t.Fatalf("complete OIDC session: %v", err)
	}
	user, err := fixture.eventStore.UserByEmail(t.Context(), "new-user@example.test")
	if err != nil {
		t.Fatalf("read OIDC-created user: %v", err)
	}
	access, err := fixture.verifier.VerifyAccess(tokens.AccessToken)
	if err != nil || access.Subject != user.UserID {
		t.Fatalf("OIDC access token = (%+v, %v); want subject %s", access, err, user.UserID)
	}
	rotated, err := fixture.refresh.Rotate(t.Context(), tokens.RefreshToken)
	if err != nil {
		t.Fatalf("rotate OIDC refresh token: %v", err)
	}
	rotatedAccess, err := fixture.verifier.VerifyAccess(rotated.AccessToken)
	if err != nil || rotatedAccess.Subject != user.UserID {
		t.Fatalf("rotated access token = (%+v, %v); want subject %s", rotatedAccess, err, user.UserID)
	}

	form, username, password := fixture.lastTokenRequest()
	if form.Get("grant_type") != "authorization_code" ||
		form.Get("code") != "authorization-code" ||
		form.Get("redirect_uri") != oidcTestRedirect ||
		form.Get("client_id") != oidcTestClientID ||
		len(form.Get("code_verifier")) < 43 ||
		username != oidcTestClientID ||
		password != oidcTestClientSecret {
		t.Fatalf("token request = (%v, %q, %q); want bound code-flow fields and client auth",
			form, username, password)
	}
	challenge := sha256.Sum256([]byte(form.Get("code_verifier")))
	if got := base64.RawURLEncoding.EncodeToString(challenge[:]); got != start.challenge {
		t.Fatalf("token verifier challenge = %q; want %q", got, start.challenge)
	}
}

func TestOIDCService_CompleteTreatsProviderOutageAsUnavailable(t *testing.T) {
	fixture := newOIDCTestFixture(t, false)
	start := fixture.start(t, oidcTestRedirect, "outage-subject", "outage@example.test")
	fixture.setTokenStatus(http.StatusServiceUnavailable)
	if _, err := fixture.service.Complete(
		t.Context(),
		start.state,
		"authorization-code",
	); !errors.Is(err, auth.ErrOIDCUnavailable) {
		t.Fatalf("OIDC provider outage error = %v; want %v", err, auth.ErrOIDCUnavailable)
	}
	if _, err := fixture.eventStore.UserByEmail(
		t.Context(),
		"outage@example.test",
	); !store.IsNotFound(err) {
		t.Fatalf("user after OIDC provider outage error = %v; want not found", err)
	}
}

func TestOIDCService_CompleteTreatsJWKSOutageAsUnavailable(t *testing.T) {
	for _, status := range []int{
		http.StatusRequestTimeout,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			fixture := newOIDCTestFixture(t, false)
			start := fixture.start(t, oidcTestRedirect, "jwks-outage", "jwks@example.test")
			fixture.setJWKSStatus(status)
			if _, err := fixture.service.Complete(
				t.Context(),
				start.state,
				"authorization-code",
			); !errors.Is(err, auth.ErrOIDCUnavailable) {
				t.Fatalf(
					"OIDC JWKS status %d error = %v; want %v",
					status,
					err,
					auth.ErrOIDCUnavailable,
				)
			}
		})
	}
}

func TestOIDCHandler_UsesStaticErrorsAndFailureOnlyLimits(t *testing.T) {
	fixture := newOIDCTestFixture(t, false)
	trustedProxies := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	session, err := NewSessionServiceWithOIDC(
		fixture.refresh,
		fixture.service,
		trustedProxies,
		fixture.clock.Now,
	)
	if err != nil {
		t.Fatalf("create OIDC session handler: %v", err)
	}
	client := newOIDCTestClient(t, session)

	for attempt := range 6 {
		response, err := client.StartOidcSession(
			t.Context(),
			connect.NewRequest(&powermanagev1.StartOidcSessionRequest{
				ProviderSlug: fixture.provider.Slug,
				RedirectUri:  oidcTestRedirect,
			}),
		)
		if err != nil || response.Msg.GetAuthorizationUrl() == "" {
			t.Fatalf("successful OIDC start %d = (%v, %v); want authorization URL",
				attempt+1, response, err)
		}
	}

	const wantRejectionMessage = "unauthenticated: oidc sign-in rejected"
	for attempt := range 6 {
		stateDigest := sha256.Sum256([]byte(fmt.Sprintf("missing-state-%d", attempt)))
		state := base64.RawURLEncoding.EncodeToString(stateDigest[:])
		_, err := client.CompleteOidcSession(
			t.Context(),
			connect.NewRequest(&powermanagev1.CompleteOidcSessionRequest{
				State: state,
				Code:  "authorization-code",
			}),
		)
		wantCode := connect.CodeUnauthenticated
		if attempt == 5 {
			wantCode = connect.CodeResourceExhausted
		}
		if connect.CodeOf(err) != wantCode {
			t.Fatalf("per-IP OIDC failure %d code = %v (%v); want %v",
				attempt+1, connect.CodeOf(err), err, wantCode)
		}
		if attempt < 5 {
			if err.Error() != wantRejectionMessage {
				t.Fatalf("OIDC rejection %d = %q; want static %q",
					attempt+1, err, wantRejectionMessage)
			}
		}
	}

	valid := fixture.start(t, oidcTestRedirect, "post-limit-subject", "post-limit@example.test")
	response, err := client.CompleteOidcSession(
		t.Context(),
		connect.NewRequest(&powermanagev1.CompleteOidcSessionRequest{
			State: valid.state,
			Code:  "authorization-code",
		}),
	)
	if err != nil || response.Msg.GetAccessToken() == "" || response.Msg.GetRefreshToken() == "" {
		t.Fatalf("valid callback after full failure bucket = (%v, %v); want ordinary session",
			response, err)
	}

	accountSession, err := NewSessionServiceWithOIDC(
		fixture.refresh,
		fixture.service,
		trustedProxies,
		fixture.clock.Now,
	)
	if err != nil {
		t.Fatalf("create per-account OIDC session handler: %v", err)
	}
	accountClient := newOIDCTestClient(t, accountSession)
	accountDigest := sha256.Sum256([]byte("same-missing-state"))
	accountState := base64.RawURLEncoding.EncodeToString(accountDigest[:])
	for attempt := range 6 {
		request := connect.NewRequest(&powermanagev1.CompleteOidcSessionRequest{
			State: accountState,
			Code:  "authorization-code",
		})
		request.Header().Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", attempt+1))
		_, err := accountClient.CompleteOidcSession(t.Context(), request)
		wantCode := connect.CodeUnauthenticated
		if attempt == 5 {
			wantCode = connect.CodeResourceExhausted
		}
		if connect.CodeOf(err) != wantCode {
			t.Fatalf("per-account OIDC failure %d code = %v (%v); want %v",
				attempt+1, connect.CodeOf(err), err, wantCode)
		}
	}
}

func newOIDCTestClient(
	t *testing.T,
	session *SessionService,
) powermanagev1connect.ControlServiceClient {
	t.Helper()
	passthrough := connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
			return next(ctx, request)
		}
	})
	chain, err := auth.NewInterceptorChain(
		passthrough,
		passthrough,
		passthrough,
		testAuthorizationGate(t),
	)
	if err != nil {
		t.Fatalf("create OIDC handler interceptor chain: %v", err)
	}
	path, handler, err := NewHTTPHandler(session, chain)
	if err != nil {
		t.Fatalf("create OIDC HTTP handler: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return powermanagev1connect.NewControlServiceClient(server.Client(), server.URL)
}

type oidcTestFixture struct {
	t                     *testing.T
	clock                 *refreshTestClock
	eventStore            *store.Store
	pool                  *pgxpool.Pool
	refresh               *auth.RefreshService
	verifier              *auth.Verifier
	provider              auth.OIDCProvider
	service               *auth.OIDCService
	server                *httptest.Server
	authorizationEndpoint *url.URL

	mu           sync.Mutex
	claims       oidcTestClaims
	requests     int
	lastForm     url.Values
	lastUsername string
	lastPassword string
	signingKey   *rsa.PrivateKey
	tokenStatus  int
	jwksStatus   int
}

type oidcStartFixture struct {
	authorization *url.URL
	state         string
	nonce         string
	challenge     string
}

type oidcTestClaims struct {
	Issuer               string
	Subject              string
	Audience             []string
	Authorized           string
	ExpiresAt            int64
	IssuedAt             int64
	Nonce                string
	Email                string
	EmailVerified        bool
	IncludeEmailVerified bool
}

func newOIDCTestFixture(t *testing.T, trustEmailAssertions bool) *oidcTestFixture {
	t.Helper()
	refresh, _, verifier, clock, eventStore, pool := newTestRefreshService(t)
	fixture := &oidcTestFixture{
		t:          t,
		clock:      clock,
		eventStore: eventStore,
		pool:       pool,
		refresh:    refresh,
		verifier:   verifier,
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate OIDC signing key: %v", err)
	}
	fixture.signingKey = key
	fixture.server = httptest.NewTLSServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(fixture.server.Close)
	fixture.authorizationEndpoint = mustParseURL(t, fixture.server.URL+"/authorize")
	fixture.provider = auth.OIDCProvider{
		Slug:                  "corporate",
		Issuer:                fixture.server.URL,
		ClientID:              oidcTestClientID,
		ClientSecret:          oidcTestClientSecret,
		AuthorizationEndpoint: fixture.authorizationEndpoint.String(),
		TokenEndpoint:         fixture.server.URL + "/token",
		JWKSURI:               fixture.server.URL + "/jwks",
		RedirectURIs:          []string{oidcTestRedirect, oidcTestLoopback},
		TrustEmailAssertions:  trustEmailAssertions,
	}
	fixture.service = fixture.newService(t, trustEmailAssertions)
	return fixture
}

func (f *oidcTestFixture) newService(t *testing.T, trustEmailAssertions bool) *auth.OIDCService {
	t.Helper()
	provider := f.provider
	provider.TrustEmailAssertions = trustEmailAssertions
	entropy := make([]byte, 4096)
	for index := range entropy {
		entropy[index] = byte((index*37 + 11) % 251)
	}
	service, err := auth.NewOIDCService(
		f.eventStore,
		f.refresh,
		[]auth.OIDCProvider{provider},
		f.server.Client(),
		bytes.NewReader(entropy),
		f.clock.Now,
	)
	if err != nil {
		t.Fatalf("create OIDC service: %v", err)
	}
	return service
}

func (f *oidcTestFixture) start(
	t *testing.T,
	redirectURI string,
	subject string,
	email string,
) oidcStartFixture {
	t.Helper()
	return f.startWithService(t, f.service, redirectURI, subject, email)
}

func (f *oidcTestFixture) startWithService(
	t *testing.T,
	service *auth.OIDCService,
	redirectURI string,
	subject string,
	email string,
) oidcStartFixture {
	t.Helper()
	authorizationURL, err := service.Start(t.Context(), f.provider.Slug, redirectURI)
	if err != nil {
		t.Fatalf("start OIDC session: %v", err)
	}
	authorization := mustParseURL(t, authorizationURL)
	start := oidcStartFixture{
		authorization: authorization,
		state:         authorization.Query().Get("state"),
		nonce:         authorization.Query().Get("nonce"),
		challenge:     authorization.Query().Get("code_challenge"),
	}
	f.mu.Lock()
	f.claims = oidcTestClaims{
		Issuer:               f.provider.Issuer,
		Subject:              subject,
		Audience:             []string{oidcTestClientID},
		ExpiresAt:            f.clock.now.Add(5 * time.Minute).Unix(),
		IssuedAt:             f.clock.now.Unix(),
		Nonce:                start.nonce,
		Email:                email,
		EmailVerified:        true,
		IncludeEmailVerified: true,
	}
	f.mu.Unlock()
	return start
}

func (f *oidcTestFixture) mutateClaims(mutate func(*oidcTestClaims)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mutate(&f.claims)
}

func (f *oidcTestFixture) tokenRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requests
}

func (f *oidcTestFixture) setTokenStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenStatus = status
}

func (f *oidcTestFixture) setJWKSStatus(status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jwksStatus = status
}

func (f *oidcTestFixture) lastTokenRequest() (url.Values, string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return cloneValues(f.lastForm), f.lastUsername, f.lastPassword
}

func (f *oidcTestFixture) serve(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/token":
		f.serveToken(response, request)
	case "/jwks":
		f.serveJWKS(response)
	default:
		http.NotFound(response, request)
	}
}

func (f *oidcTestFixture) serveToken(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(response, "method", http.StatusMethodNotAllowed)
		return
	}
	if err := request.ParseForm(); err != nil {
		http.Error(response, "form", http.StatusBadRequest)
		return
	}
	username, password, _ := request.BasicAuth()
	f.mu.Lock()
	f.requests++
	f.lastForm = cloneValues(request.PostForm)
	f.lastUsername = username
	f.lastPassword = password
	claims := f.claims
	status := f.tokenStatus
	f.mu.Unlock()

	token, err := f.signIDToken(claims)
	if err != nil {
		http.Error(response, "sign", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	if status != 0 {
		response.WriteHeader(status)
	}
	if err := writeOIDCTestJSON(response, map[string]any{
		"access_token": "provider-access-token",
		"token_type":   "Bearer",
		"id_token":     token,
	}); err != nil {
		f.t.Errorf("write OIDC token response: %v", err)
	}
}

func (f *oidcTestFixture) serveJWKS(response http.ResponseWriter) {
	f.mu.Lock()
	status := f.jwksStatus
	f.mu.Unlock()
	exponent := big.NewInt(int64(f.signingKey.PublicKey.E)).Bytes()
	response.Header().Set("Content-Type", "application/json")
	if status != 0 {
		response.WriteHeader(status)
	}
	if err := writeOIDCTestJSON(response, map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"kid": "test-rsa-key",
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(f.signingKey.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(exponent),
		}},
	}); err != nil {
		f.t.Errorf("write OIDC JWKS response: %v", err)
	}
}

func (f *oidcTestFixture) signIDToken(claims oidcTestClaims) (string, error) {
	header, err := marshalOIDCTestJSON(map[string]string{
		"alg": "RS256",
		"kid": "test-rsa-key",
		"typ": "JWT",
	})
	if err != nil {
		return "", err
	}
	payload := map[string]any{
		"iss":   claims.Issuer,
		"sub":   claims.Subject,
		"aud":   claims.Audience,
		"exp":   claims.ExpiresAt,
		"iat":   claims.IssuedAt,
		"nonce": claims.Nonce,
		"email": claims.Email,
	}
	if claims.IncludeEmailVerified {
		payload["email_verified"] = claims.EmailVerified
	}
	if claims.Authorized != "" {
		payload["azp"] = claims.Authorized
	}
	body, err := marshalOIDCTestJSON(payload)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(body)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, f.signingKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL %q: %v", raw, err)
	}
	return parsed
}

func cloneValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values))
	for key, entries := range values {
		cloned[key] = append([]string(nil), entries...)
	}
	return cloned
}
