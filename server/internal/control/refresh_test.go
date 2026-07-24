package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

const refreshTestSubject = "01K0QJ3E5E8R4M0D8EV3Y4N6J7"

func TestRefreshService_RotatesAndReplayRevokesFamily(t *testing.T) {
	service, _, verifier, _, eventStore, pool := newTestRefreshServiceWithUser(t)
	first, err := service.StartSession(t.Context(), refreshTestSubject)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	assertSessionTokens(t, verifier, first)

	second, err := service.Rotate(t.Context(), first.RefreshToken)
	if err != nil {
		t.Fatalf("rotate first refresh token: %v", err)
	}
	assertSessionTokens(t, verifier, second)
	if second.RefreshToken == first.RefreshToken {
		t.Fatal("refresh rotation returned the presented token")
	}

	if _, err := service.Rotate(t.Context(), first.RefreshToken); !errors.Is(err, auth.ErrRefreshRejected) {
		t.Fatalf("replay first refresh token error = %v; want %v", err, auth.ErrRefreshRejected)
	}
	if _, err := service.Rotate(t.Context(), second.RefreshToken); !errors.Is(err, auth.ErrRefreshRejected) {
		t.Fatalf("rotate successor after family replay error = %v; want %v", err, auth.ErrRefreshRejected)
	}

	firstHash := sha256.Sum256([]byte(first.RefreshToken))
	state, err := eventStore.RefreshFamilyToken(t.Context(), firstHash)
	if err != nil {
		t.Fatalf("read replayed refresh token: %v", err)
	}
	if !state.Superseded || !state.Revoked || state.ProjectionVersion != 3 {
		t.Fatalf("replayed refresh state = %+v; want superseded, family-revoked version three", state)
	}
	var revocations int
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*)
		FROM events
		WHERE stream_type = 'refresh-family'
		  AND event_type = 'RefreshFamilyRevoked'`).Scan(&revocations); err != nil {
		t.Fatalf("count refresh-family revocations: %v", err)
	}
	if revocations != 1 {
		t.Fatalf("refresh-family revocation events = %d; want one audit event", revocations)
	}
}

func TestRefreshService_ConcurrentRotationHasOneWinnerAndRevokesFamily(t *testing.T) {
	service, _, _, _, _, _ := newTestRefreshServiceWithUser(t)
	first, err := service.StartSession(t.Context(), refreshTestSubject)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}

	start := make(chan struct{})
	ready := make(chan struct{}, 2)
	results := make(chan refreshRotationResult, 2)
	for range 2 {
		go func() {
			ready <- struct{}{}
			<-start
			tokens, err := service.Rotate(context.Background(), first.RefreshToken)
			results <- refreshRotationResult{tokens: tokens, err: err}
		}()
	}
	for range 2 {
		select {
		case <-ready:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent rotations to become ready")
		}
	}
	close(start)

	var winner auth.SessionTokens
	successes := 0
	rejections := 0
	for range 2 {
		var result refreshRotationResult
		select {
		case result = <-results:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent rotation result")
		}
		switch {
		case result.err == nil:
			successes++
			winner = result.tokens
		case errors.Is(result.err, auth.ErrRefreshRejected):
			rejections++
		default:
			t.Fatalf("concurrent refresh error = %v; want success or generic replay rejection", result.err)
		}
	}
	if successes != 1 || rejections != 1 {
		t.Fatalf("concurrent refresh results = (%d successes, %d rejections); want one each", successes, rejections)
	}
	if _, err := service.Rotate(t.Context(), winner.RefreshToken); !errors.Is(err, auth.ErrRefreshRejected) {
		t.Fatalf("winning successor remained live after replay race: %v", err)
	}
}

func TestRefreshService_FailureCausesHaveParity(t *testing.T) {
	fixtures := map[auth.EnumerationFailureCause]func(
		*testing.T,
		*auth.RefreshService,
		*auth.Signer,
		*refreshTestClock,
	) string{
		auth.EnumerationMalformed: func(
			*testing.T,
			*auth.RefreshService,
			*auth.Signer,
			*refreshTestClock,
		) string {
			return "not-a-refresh-token"
		},
		auth.EnumerationNonexistent: func(
			t *testing.T,
			_ *auth.RefreshService,
			signer *auth.Signer,
			_ *refreshTestClock,
		) string {
			t.Helper()
			token, err := signer.MintRefresh(refreshTestSubject, 1)
			if err != nil {
				t.Fatalf("mint nonexistent refresh fixture: %v", err)
			}
			return token
		},
		auth.EnumerationExpired: func(
			t *testing.T,
			service *auth.RefreshService,
			_ *auth.Signer,
			clock *refreshTestClock,
		) string {
			t.Helper()
			tokens, err := service.StartSession(t.Context(), refreshTestSubject)
			if err != nil {
				t.Fatalf("start expired refresh fixture: %v", err)
			}
			clock.now = clock.now.Add(7 * 24 * time.Hour)
			return tokens.RefreshToken
		},
		auth.EnumerationSuperseded: func(
			t *testing.T,
			service *auth.RefreshService,
			_ *auth.Signer,
			_ *refreshTestClock,
		) string {
			t.Helper()
			first, err := service.StartSession(t.Context(), refreshTestSubject)
			if err != nil {
				t.Fatalf("start superseded refresh fixture: %v", err)
			}
			if _, err := service.Rotate(t.Context(), first.RefreshToken); err != nil {
				t.Fatalf("rotate superseded refresh fixture: %v", err)
			}
			return first.RefreshToken
		},
		auth.EnumerationRevoked: func(
			t *testing.T,
			service *auth.RefreshService,
			_ *auth.Signer,
			_ *refreshTestClock,
		) string {
			t.Helper()
			first, err := service.StartSession(t.Context(), refreshTestSubject)
			if err != nil {
				t.Fatalf("start revoked refresh fixture: %v", err)
			}
			second, err := service.Rotate(t.Context(), first.RefreshToken)
			if err != nil {
				t.Fatalf("rotate revoked refresh fixture: %v", err)
			}
			if _, err := service.Rotate(t.Context(), first.RefreshToken); !errors.Is(err, auth.ErrRefreshRejected) {
				t.Fatalf("replay revoked refresh fixture: %v", err)
			}
			return second.RefreshToken
		},
	}
	profile, exists := auth.EnumerationParityProfiles()[auth.SecretVerifierRefresh]
	if !exists {
		t.Fatal("refresh enumeration parity profile is absent")
	}
	if len(fixtures) != len(profile.FailureCauses) {
		t.Fatalf("refresh parity fixtures = %d; registered causes = %d", len(fixtures), len(profile.FailureCauses))
	}

	const samplesPerCause = 3
	medians := make(map[auth.EnumerationFailureCause]time.Duration, len(profile.FailureCauses))
	var wantErrorBytes string
	for _, cause := range profile.FailureCauses {
		fixture, exists := fixtures[cause]
		if !exists {
			t.Fatalf("registered refresh parity cause %q has no fixture", cause)
		}
		t.Run(string(cause), func(t *testing.T) {
			service, signer, _, clock, _, _ := newTestRefreshServiceWithUser(t)
			samples := make([]time.Duration, 0, samplesPerCause)
			for range samplesPerCause {
				token := fixture(t, service, signer, clock)
				started := time.Now()
				tokens, err := service.Rotate(t.Context(), token)
				samples = append(samples, time.Since(started))
				if !errors.Is(err, auth.ErrRefreshRejected) || tokens != (auth.SessionTokens{}) {
					t.Fatalf("%s refresh result = (%+v, %v); want empty tokens and generic rejection",
						cause, tokens, err)
				}
				if err.Error() != auth.ErrRefreshRejected.Error() {
					t.Fatalf("%s refresh error bytes = %q; want %q", cause, err, auth.ErrRefreshRejected)
				}
				if wantErrorBytes == "" {
					wantErrorBytes = err.Error()
				} else if err.Error() != wantErrorBytes {
					t.Fatalf("%s refresh error bytes = %q; baseline %q", cause, err, wantErrorBytes)
				}
			}
			slices.Sort(samples)
			median := samples[len(samples)/2]
			if median < profile.MinimumRejectionLatency {
				t.Fatalf("%s median rejection took %s; want at least %s",
					cause, median, profile.MinimumRejectionLatency)
			}
			medians[cause] = median
		})
	}
	var fastest, slowest time.Duration
	for _, median := range medians {
		if fastest == 0 || median < fastest {
			fastest = median
		}
		if median > slowest {
			slowest = median
		}
	}
	if spread := slowest - fastest; spread > 100*time.Millisecond {
		t.Fatalf("refresh rejection median spread = %s; want no more than 100ms (%v)", spread, medians)
	}
}

func TestRefreshService_StartPersistsOnlyHash(t *testing.T) {
	service, _, _, _, _, pool := newTestRefreshServiceWithUser(t)
	tokens, err := service.StartSession(t.Context(), refreshTestSubject)
	if err != nil {
		t.Fatalf("start session: %v", err)
	}
	rows, err := pool.Query(t.Context(), `
		SELECT payload
		FROM events
		WHERE stream_type = 'refresh-family'`)
	if err != nil {
		t.Fatalf("read refresh-family events: %v", err)
	}
	defer rows.Close()
	discovered := 0
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			t.Fatalf("scan refresh-family event: %v", err)
		}
		discovered++
		for name, token := range map[string]string{
			"access":  tokens.AccessToken,
			"refresh": tokens.RefreshToken,
		} {
			if bytes.Contains(payload, []byte(token)) {
				t.Fatalf("refresh-family event persisted raw %s token", name)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate refresh-family events: %v", err)
	}
	if discovered != 1 {
		t.Fatalf("refresh-family events after session start = %d; want one", discovered)
	}

	wantHash := sha256.Sum256([]byte(tokens.RefreshToken))
	var gotHash []byte
	if err := pool.QueryRow(t.Context(), `SELECT active_token_hash FROM refresh_families`).Scan(&gotHash); err != nil {
		t.Fatalf("read active refresh-token hash: %v", err)
	}
	if !bytes.Equal(gotHash, wantHash[:]) {
		t.Fatalf("persisted refresh-token hash = %x; want SHA-256 %x", gotHash, wantHash)
	}
}

type refreshRotationResult struct {
	tokens auth.SessionTokens
	err    error
}

type refreshTestClock struct {
	now time.Time
}

func (c *refreshTestClock) Now() time.Time {
	return c.now
}

func newTestRefreshService(
	t *testing.T,
) (
	*auth.RefreshService,
	*auth.Signer,
	*auth.Verifier,
	*refreshTestClock,
	*store.Store,
	*pgxpool.Pool,
) {
	t.Helper()
	pool := crlRotationPostgres.Database(t, store.Migrate)
	eventStore, err := store.NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	clock := &refreshTestClock{now: time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)}
	key, err := auth.GenerateSigningKey()
	if err != nil {
		t.Fatalf("generate auth signing key: %v", err)
	}
	signer, err := auth.NewSigner(key, clock.Now)
	if err != nil {
		t.Fatalf("create auth signer: %v", err)
	}
	verifier, err := auth.NewVerifier(&key.PublicKey, clock.Now)
	if err != nil {
		t.Fatalf("create auth verifier: %v", err)
	}
	entropy := make([]byte, 256)
	for index := range entropy {
		entropy[index] = byte(index)
	}
	service, err := auth.NewRefreshService(
		eventStore,
		signer,
		verifier,
		bytes.NewReader(entropy),
		clock.Now,
	)
	if err != nil {
		t.Fatalf("create refresh service: %v", err)
	}
	return service, signer, verifier, clock, eventStore, pool
}

func newTestRefreshServiceWithUser(
	t *testing.T,
) (
	*auth.RefreshService,
	*auth.Signer,
	*auth.Verifier,
	*refreshTestClock,
	*store.Store,
	*pgxpool.Pool,
) {
	t.Helper()
	service, signer, verifier, clock, eventStore, pool := newTestRefreshService(t)
	if err := eventStore.AppendEventWithVersion(t.Context(), sessionUserCreated(t), 0); err != nil {
		t.Fatalf("append refresh test user: %v", err)
	}
	return service, signer, verifier, clock, eventStore, pool
}

func assertSessionTokens(t *testing.T, verifier *auth.Verifier, tokens auth.SessionTokens) {
	t.Helper()
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("session tokens = %+v; want non-empty access and refresh values", tokens)
	}
	access, err := verifier.VerifyAccess(tokens.AccessToken)
	if err != nil || access.Subject != refreshTestSubject || access.SessionVersion != 1 {
		t.Fatalf(
			"verify access token = (%+v, %v); want subject %s at session version one",
			access,
			err,
			refreshTestSubject,
		)
	}
	refresh, err := verifier.VerifyRefresh(tokens.RefreshToken)
	if err != nil || refresh.Subject != refreshTestSubject || refresh.SessionVersion != 1 {
		t.Fatalf(
			"verify refresh token = (%+v, %v); want subject %s at session version one",
			refresh,
			err,
			refreshTestSubject,
		)
	}
}
