package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/store"
)

func TestPATService_MintStoresOnlyHashAndCanonicalScopes(t *testing.T) {
	service, _, pool, _ := newTestPATService(t)
	expiresAt := patTestTime.Add(30 * 24 * time.Hour)
	credential, err := service.Mint(
		t.Context(),
		refreshTestSubject,
		[]string{" devices.write ", "actions.read", "actions.read"},
		expiresAt,
	)
	if err != nil {
		t.Fatalf("mint PAT: %v", err)
	}
	if credential.TokenID == "" ||
		credential.Secret == "" ||
		credential.ExpiresAt != expiresAt ||
		!slices.Equal(credential.Scopes, []string{"actions.read", "devices.write"}) {
		t.Fatalf("minted PAT = %+v; want ID, one-time secret, expiry, and canonical scopes", credential)
	}
	if len(credential.Secret) != len("pm_pat_")+base64.RawURLEncoding.EncodedLen(32) ||
		credential.Secret[:len("pm_pat_")] != "pm_pat_" {
		t.Fatalf("minted PAT secret has invalid public format: %q", credential.Secret)
	}

	rows, err := pool.Query(t.Context(), `
		SELECT payload
		FROM events
		WHERE stream_type = 'personal-access-token'`)
	if err != nil {
		t.Fatalf("read PAT events: %v", err)
	}
	defer rows.Close()
	discovered := 0
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			t.Fatalf("scan PAT event: %v", err)
		}
		discovered++
		if bytes.Contains(payload, []byte(credential.Secret)) {
			t.Fatal("PAT event persisted the raw one-time secret")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate PAT events: %v", err)
	}
	if discovered != 1 {
		t.Fatalf("PAT events after mint = %d; want one", discovered)
	}

	wantHash := sha256.Sum256([]byte(credential.Secret))
	var gotHash []byte
	if err := pool.QueryRow(t.Context(), `
		SELECT token_hash
		FROM personal_access_tokens
		WHERE token_id = $1`, credential.TokenID).Scan(&gotHash); err != nil {
		t.Fatalf("read PAT digest: %v", err)
	}
	if !bytes.Equal(gotHash, wantHash[:]) {
		t.Fatalf("stored PAT digest = %x; want SHA-256 %x", gotHash, wantHash)
	}
}

func TestPATService_MintRejectsInvalidInputAndEntropyWithoutWriting(t *testing.T) {
	service, clock, pool, eventStore := newTestPATService(t)
	testCases := []struct {
		name      string
		subject   string
		scopes    []string
		expiresAt time.Time
	}{
		{name: "empty subject", scopes: []string{"actions.read"}, expiresAt: clock.now.Add(time.Hour)},
		{name: "empty scopes", subject: refreshTestSubject, expiresAt: clock.now.Add(time.Hour)},
		{
			name:      "invalid scope",
			subject:   refreshTestSubject,
			scopes:    []string{"Actions.Read"},
			expiresAt: clock.now.Add(time.Hour),
		},
		{
			name:      "expired",
			subject:   refreshTestSubject,
			scopes:    []string{"actions.read"},
			expiresAt: clock.now,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			credential, err := service.Mint(
				t.Context(),
				testCase.subject,
				testCase.scopes,
				testCase.expiresAt,
			)
			if !errors.Is(err, auth.ErrPATInvalid) || !emptyPATCredential(credential) {
				t.Fatalf("invalid PAT mint result = (%+v, %v); want empty credential and %v",
					credential, err, auth.ErrPATInvalid)
			}
		})
	}

	shortEntropy, err := auth.NewPATService(
		eventStore,
		bytes.NewReader(make([]byte, 10)),
		clock.Now,
	)
	if err != nil {
		t.Fatalf("create short-entropy PAT service: %v", err)
	}
	credential, err := shortEntropy.Mint(
		t.Context(),
		refreshTestSubject,
		[]string{"actions.read"},
		clock.now.Add(time.Hour),
	)
	if !errors.Is(err, auth.ErrPATUnavailable) || !emptyPATCredential(credential) {
		t.Fatalf("short-entropy PAT mint result = (%+v, %v); want empty credential and %v",
			credential, err, auth.ErrPATUnavailable)
	}

	var events int
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*)
		FROM events
		WHERE stream_type = 'personal-access-token'`).Scan(&events); err != nil {
		t.Fatalf("count PAT events after rejected mints: %v", err)
	}
	if events != 0 {
		t.Fatalf("PAT events after rejected mints = %d; want zero", events)
	}
}

func TestPATService_AuthenticationCarriesPerTokenAuditIdentityUntilRevoked(t *testing.T) {
	service, _, _, _ := newTestPATService(t)
	expiresAt := patTestTime.Add(24 * time.Hour)
	first, err := service.Mint(
		t.Context(),
		refreshTestSubject,
		[]string{"actions.read"},
		expiresAt,
	)
	if err != nil {
		t.Fatalf("mint first PAT: %v", err)
	}
	second, err := service.Mint(
		t.Context(),
		refreshTestSubject,
		[]string{"actions.read"},
		expiresAt,
	)
	if err != nil {
		t.Fatalf("mint second PAT: %v", err)
	}

	firstPrincipal, err := service.Authenticate(t.Context(), first.Secret)
	if err != nil {
		t.Fatalf("authenticate first PAT: %v", err)
	}
	secondPrincipal, err := service.Authenticate(t.Context(), second.Secret)
	if err != nil {
		t.Fatalf("authenticate second PAT: %v", err)
	}
	if firstPrincipal.Subject != refreshTestSubject ||
		firstPrincipal.TokenID != first.TokenID ||
		firstPrincipal.AuditIdentity != "pat:"+first.TokenID ||
		!slices.Equal(firstPrincipal.Scopes, []string{"actions.read"}) {
		t.Fatalf("first PAT principal = %+v; want subject, scope, and stable per-token audit identity", firstPrincipal)
	}
	if secondPrincipal.AuditIdentity != "pat:"+second.TokenID ||
		secondPrincipal.AuditIdentity == firstPrincipal.AuditIdentity {
		t.Fatalf("PAT audit identities = (%q, %q); want stable distinct token identities",
			firstPrincipal.AuditIdentity, secondPrincipal.AuditIdentity)
	}

	if err := service.Revoke(t.Context(), first.TokenID); err != nil {
		t.Fatalf("revoke first PAT: %v", err)
	}
	if _, err := service.Authenticate(t.Context(), first.Secret); !errors.Is(err, auth.ErrPATRejected) {
		t.Fatalf("authenticate revoked PAT error = %v; want %v", err, auth.ErrPATRejected)
	}
	stillActive, err := service.Authenticate(t.Context(), second.Secret)
	if err != nil {
		t.Fatalf("authenticate unrelated PAT after revocation: %v", err)
	}
	if stillActive.AuditIdentity != secondPrincipal.AuditIdentity {
		t.Fatalf("unrelated PAT audit identity changed from %q to %q",
			secondPrincipal.AuditIdentity, stillActive.AuditIdentity)
	}
}

func TestPATService_ConcurrentRevocationIsIdempotent(t *testing.T) {
	service, _, pool, _ := newTestPATService(t)
	credential, err := service.Mint(
		t.Context(),
		refreshTestSubject,
		[]string{"actions.read"},
		patTestTime.Add(24*time.Hour),
	)
	if err != nil {
		t.Fatalf("mint PAT: %v", err)
	}

	start := make(chan struct{})
	ready := make(chan struct{}, 2)
	results := make(chan error, 2)
	for range 2 {
		go func() {
			ready <- struct{}{}
			<-start
			results <- service.Revoke(context.Background(), credential.TokenID)
		}()
	}
	for range 2 {
		select {
		case <-ready:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for PAT revocations to become ready")
		}
	}
	close(start)
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("concurrent PAT revocation: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for concurrent PAT revocation")
		}
	}
	if err := service.Revoke(t.Context(), credential.TokenID); err != nil {
		t.Fatalf("repeat PAT revocation: %v", err)
	}
	var revocations int
	if err := pool.QueryRow(t.Context(), `
		SELECT count(*)
		FROM events
		WHERE stream_type = 'personal-access-token'
		  AND event_type = 'PersonalAccessTokenRevoked'`).Scan(&revocations); err != nil {
		t.Fatalf("count PAT revocations: %v", err)
	}
	if revocations != 1 {
		t.Fatalf("PAT revocation events = %d; want one", revocations)
	}
	if err := service.Revoke(t.Context(), "not-a-token-id"); !errors.Is(err, auth.ErrPATInvalid) {
		t.Fatalf("malformed PAT revocation error = %v; want %v", err, auth.ErrPATInvalid)
	}
}

func TestPATService_FailureCausesHaveParity(t *testing.T) {
	fixtures := map[auth.EnumerationFailureCause]func(
		*testing.T,
		*auth.PATService,
		*refreshTestClock,
	) string{
		auth.EnumerationMalformed: func(
			*testing.T,
			*auth.PATService,
			*refreshTestClock,
		) string {
			return "not-a-pat"
		},
		auth.EnumerationNonexistent: func(
			*testing.T,
			*auth.PATService,
			*refreshTestClock,
		) string {
			return "pm_pat_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 32))
		},
		auth.EnumerationExpired: func(
			t *testing.T,
			service *auth.PATService,
			clock *refreshTestClock,
		) string {
			t.Helper()
			credential, err := service.Mint(
				t.Context(),
				refreshTestSubject,
				[]string{"actions.read"},
				clock.now.Add(time.Hour),
			)
			if err != nil {
				t.Fatalf("mint expired PAT fixture: %v", err)
			}
			clock.now = clock.now.Add(time.Hour)
			return credential.Secret
		},
		auth.EnumerationRevoked: func(
			t *testing.T,
			service *auth.PATService,
			clock *refreshTestClock,
		) string {
			t.Helper()
			credential, err := service.Mint(
				t.Context(),
				refreshTestSubject,
				[]string{"actions.read"},
				clock.now.Add(time.Hour),
			)
			if err != nil {
				t.Fatalf("mint revoked PAT fixture: %v", err)
			}
			if err := service.Revoke(t.Context(), credential.TokenID); err != nil {
				t.Fatalf("revoke PAT fixture: %v", err)
			}
			return credential.Secret
		},
	}
	profile, exists := auth.EnumerationParityProfiles()[auth.SecretVerifierPAT]
	if !exists {
		t.Fatal("PAT enumeration parity profile is absent")
	}
	if len(fixtures) != len(profile.FailureCauses) {
		t.Fatalf("PAT parity fixtures = %d; registered causes = %d", len(fixtures), len(profile.FailureCauses))
	}

	const samplesPerCause = 3
	medians := make(map[auth.EnumerationFailureCause]time.Duration, len(profile.FailureCauses))
	var wantErrorBytes string
	for _, cause := range profile.FailureCauses {
		fixture, exists := fixtures[cause]
		if !exists {
			t.Fatalf("registered PAT parity cause %q has no fixture", cause)
		}
		t.Run(string(cause), func(t *testing.T) {
			service, clock, _, _ := newTestPATService(t)
			samples := make([]time.Duration, 0, samplesPerCause)
			for range samplesPerCause {
				token := fixture(t, service, clock)
				started := time.Now()
				principal, err := service.Authenticate(t.Context(), token)
				samples = append(samples, time.Since(started))
				if !errors.Is(err, auth.ErrPATRejected) ||
					principal.Subject != "" ||
					principal.TokenID != "" ||
					principal.AuditIdentity != "" ||
					len(principal.Scopes) != 0 {
					t.Fatalf("%s PAT result = (%+v, %v); want empty principal and generic rejection",
						cause, principal, err)
				}
				if err.Error() != auth.ErrPATRejected.Error() {
					t.Fatalf("%s PAT error bytes = %q; want %q", cause, err, auth.ErrPATRejected)
				}
				if wantErrorBytes == "" {
					wantErrorBytes = err.Error()
				} else if err.Error() != wantErrorBytes {
					t.Fatalf("%s PAT error bytes = %q; baseline %q", cause, err, wantErrorBytes)
				}
			}
			slices.Sort(samples)
			median := samples[len(samples)/2]
			if median < profile.MinimumRejectionLatency {
				t.Fatalf("%s median PAT rejection took %s; want at least %s",
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
		t.Fatalf("PAT rejection median spread = %s; want no more than 100ms (%v)", spread, medians)
	}
}

func newTestPATService(
	t *testing.T,
) (*auth.PATService, *refreshTestClock, *pgxpool.Pool, *store.Store) {
	t.Helper()
	pool := crlRotationPostgres.Database(t, store.Migrate)
	eventStore, err := store.NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	clock := &refreshTestClock{now: patTestTime}
	entropy := make([]byte, 256)
	for index := range entropy {
		entropy[index] = byte(index)
	}
	service, err := auth.NewPATService(eventStore, bytes.NewReader(entropy), clock.Now)
	if err != nil {
		t.Fatalf("create PAT service: %v", err)
	}
	return service, clock, pool, eventStore
}

var patTestTime = time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)

func emptyPATCredential(credential auth.PATCredential) bool {
	return credential.TokenID == "" &&
		credential.Secret == "" &&
		len(credential.Scopes) == 0 &&
		credential.ExpiresAt.IsZero()
}
