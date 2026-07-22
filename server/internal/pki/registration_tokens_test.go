package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testpostgres"
)

var registrationPostgres testpostgres.Harness

func TestMain(m *testing.M) {
	os.Exit(registrationPostgres.Run(m))
}

// TestRegistrationTokens_MintStoresOnlyHash proves the returned secret is 256
// random bits while every durable representation contains only its digest.
func TestRegistrationTokens_MintStoresOnlyHash(t *testing.T) {
	clock := newMutableClock(time.Date(2026, time.July, 22, 9, 0, 0, 0, time.UTC))
	service, pool := newTestRegistrationTokens(t, deterministicRandom(1), clock, noWait)
	minted, err := service.Mint(context.Background(), RegistrationTokenOptions{
		Purpose:   RegistrationTokenPurposeAgent,
		MaxUses:   3,
		ExpiresAt: clock.Now().Add(time.Hour),
		Owner:     "owner@example.com",
	})
	if err != nil {
		t.Fatalf("mint registration token: %v", err)
	}
	if !identity.IsCanonicalULID(minted.TokenID) {
		t.Fatalf("minted token ID = %q; want canonical ULID", minted.TokenID)
	}
	id, secret := decodeMintedToken(t, minted.Token)
	if id != minted.TokenID || len(secret) != 32 {
		t.Fatalf("minted token shape = (%q, %d secret bytes); want (%q, 32)", id, len(secret), minted.TokenID)
	}
	wantHash := sha256.Sum256(secret)
	persisted, err := service.eventStore.RegistrationToken(context.Background(), minted.TokenID)
	if err != nil {
		t.Fatalf("read registration token: %v", err)
	}
	if persisted.Hash != wantHash {
		t.Fatalf("persisted hash = %x; want SHA-256(secret) %x", persisted.Hash, wantHash)
	}
	if persisted.Purpose != store.RegistrationTokenPurposeAgent || len(persisted.DNSNames) != 0 ||
		persisted.MaxUses != 3 || persisted.Uses != 0 || persisted.Owner != "owner@example.com" || persisted.Disabled {
		t.Fatalf("persisted token metadata = %+v; want unused enabled owner-bound token", persisted)
	}
	rows, err := pool.Query(context.Background(), `SELECT payload FROM events WHERE stream_id = $1`, minted.TokenID)
	if err != nil {
		t.Fatalf("read token events: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			t.Fatalf("scan token event payload: %v", err)
		}
		if bytes.Contains(payload, []byte(minted.Token)) || bytes.Contains(payload, secret) {
			t.Fatalf("event payload contains raw registration token material: %q", payload)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate token events: %v", err)
	}
}

// TestGatewayRegistrationToken_CrossPurposeUseRejectsWithoutConsumption
// proves token purpose is an authorization boundary, not enrollment metadata.
func TestGatewayRegistrationToken_CrossPurposeUseRejectsWithoutConsumption(t *testing.T) {
	clock := newMutableClock(time.Date(2026, time.July, 22, 9, 0, 0, 0, time.UTC))
	service, pool := newTestRegistrationTokens(t, deterministicRandom(2), clock, noWait)
	agent, err := service.Mint(context.Background(), RegistrationTokenOptions{
		Purpose:   RegistrationTokenPurposeAgent,
		MaxUses:   1,
		ExpiresAt: clock.Now().Add(time.Hour),
		Owner:     "agent-owner@example.com",
	})
	if err != nil {
		t.Fatalf("mint agent registration token: %v", err)
	}
	gatewayDNSNames := []string{"gateway-1.internal.example"}
	gateway, err := service.Mint(context.Background(), RegistrationTokenOptions{
		Purpose:   RegistrationTokenPurposeGateway,
		MaxUses:   1,
		ExpiresAt: clock.Now().Add(time.Hour),
		DNSNames:  gatewayDNSNames,
	})
	if err != nil {
		t.Fatalf("mint gateway registration token: %v", err)
	}

	tests := []struct {
		name            string
		token           MintedRegistrationToken
		expectedPurpose RegistrationTokenPurpose
	}{
		{name: "agent token on gateway enrollment", token: agent, expectedPurpose: RegistrationTokenPurposeGateway},
		{name: "gateway token on agent enrollment", token: gateway, expectedPurpose: RegistrationTokenPurposeAgent},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			grant, err := service.Consume(
				context.Background(),
				fmt.Sprintf("cross-purpose-%d", index),
				test.token.Token,
				test.expectedPurpose,
			)
			assertEmptyRegistrationTokenGrant(t, grant)
			if !errors.Is(err, ErrInvalidRegistrationToken) || err.Error() != ErrInvalidRegistrationToken.Error() {
				t.Fatalf("cross-purpose rejection = %v; want uniform invalid-token sentinel", err)
			}
			state, err := service.eventStore.RegistrationToken(context.Background(), test.token.TokenID)
			if err != nil {
				t.Fatalf("read token after cross-purpose rejection: %v", err)
			}
			if state.Uses != 0 || state.ProjectionVersion != 1 || tokenEventCount(t, pool, test.token.TokenID) != 1 {
				t.Fatalf("token state after cross-purpose rejection = %+v; want unconsumed version one", state)
			}
		})
	}

	agentGrant, err := service.Consume(context.Background(), "agent-purpose", agent.Token, RegistrationTokenPurposeAgent)
	if err != nil {
		t.Fatalf("consume matching agent token: %v", err)
	}
	if agentGrant.Purpose != RegistrationTokenPurposeAgent || len(agentGrant.DNSNames) != 0 {
		t.Fatalf("agent grant = %+v; want agent purpose without DNS names", agentGrant)
	}
	gatewayGrant, err := service.Consume(context.Background(), "gateway-purpose", gateway.Token, RegistrationTokenPurposeGateway)
	if err != nil {
		t.Fatalf("consume matching gateway token: %v", err)
	}
	if gatewayGrant.Purpose != RegistrationTokenPurposeGateway || !slices.Equal(gatewayGrant.DNSNames, gatewayDNSNames) {
		t.Fatalf("gateway grant = %+v; want gateway purpose and DNS names %v", gatewayGrant, gatewayDNSNames)
	}
}

// TestRegistrationTokens_ConcurrentConsumeHonorsMaxUses is AC-2's real
// Postgres N+k race: explicit fresh CAS attempts grant exactly N callers.
func TestRegistrationTokens_ConcurrentConsumeHonorsMaxUses(t *testing.T) {
	clock := newMutableClock(time.Date(2026, time.July, 22, 9, 0, 0, 0, time.UTC))
	service, pool := newTestRegistrationTokens(t, deterministicRandom(1), clock, noWait)
	const (
		maxUses = 3
		callers = 8
	)
	minted, err := service.Mint(context.Background(), RegistrationTokenOptions{
		Purpose: RegistrationTokenPurposeAgent, MaxUses: maxUses, ExpiresAt: clock.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("mint registration token: %v", err)
	}
	start := make(chan struct{})
	results := make(chan error, callers)
	for caller := range callers {
		go func() {
			<-start
			_, err := service.Consume(
				context.Background(), fmt.Sprintf("source-%d", caller), minted.Token, RegistrationTokenPurposeAgent,
			)
			results <- err
		}()
	}
	close(start)

	var successes, rejected int
	for range callers {
		err := <-results
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrInvalidRegistrationToken):
			rejected++
		default:
			t.Fatalf("concurrent consume returned unexpected error: %v", err)
		}
	}
	if successes != maxUses || rejected != callers-maxUses {
		t.Fatalf("concurrent consumes: successes=%d rejected=%d; want %d and %d", successes, rejected, maxUses, callers-maxUses)
	}
	persisted, err := service.eventStore.RegistrationToken(context.Background(), minted.TokenID)
	if err != nil {
		t.Fatalf("read consumed token: %v", err)
	}
	if persisted.Uses != maxUses || persisted.ProjectionVersion != 1+maxUses {
		t.Fatalf("consumed token state = %+v; want %d uses and version %d", persisted, maxUses, 1+maxUses)
	}
	if got := tokenEventCount(t, pool, minted.TokenID); got != 1+maxUses {
		t.Fatalf("token event count = %d; want mint plus %d consumes", got, maxUses)
	}
}

func TestRegistrationTokens_CASRetriesAreBoundedAndBackedOff(t *testing.T) {
	clock := newMutableClock(time.Date(2026, time.July, 22, 9, 0, 0, 0, time.UTC))
	waits := &recordingWaiter{}
	service, pool := newTestRegistrationTokens(t, deterministicRandom(1), clock, waits.WaitUntil)
	service.casAttempts = 3
	minted, err := service.Mint(context.Background(), RegistrationTokenOptions{
		Purpose: RegistrationTokenPurposeAgent, MaxUses: 4, ExpiresAt: clock.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("mint CAS-retry fixture: %v", err)
	}
	if _, err := service.Consume(context.Background(), "primer", minted.Token, RegistrationTokenPurposeAgent); err != nil {
		t.Fatalf("consume CAS-retry fixture: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `
		UPDATE registration_tokens
		SET projection_version = 1, uses = 0
		WHERE token_id = $1`, minted.TokenID); err != nil {
		t.Fatalf("stale registration-token projection: %v", err)
	}

	grant, err := service.Consume(context.Background(), "bounded-retry", minted.Token, RegistrationTokenPurposeAgent)
	assertEmptyRegistrationTokenGrant(t, grant)
	if err == nil || !strings.Contains(err.Error(), "consume exceeded CAS retry limit") {
		t.Fatalf("CAS retry exhaustion error = %v; want consume retry-limit category", err)
	}
	deadlines := waits.Deadlines()
	if len(deadlines) != service.casAttempts-1 {
		t.Fatalf("CAS retry waits = %d; want %d", len(deadlines), service.casAttempts-1)
	}
	for index, deadline := range deadlines {
		delay := deadline.Sub(clock.Now())
		if delay <= 0 || delay > maximumRegistrationCASBackoff {
			t.Fatalf("CAS retry delay %d = %s; want positive and at most %s", index, delay, maximumRegistrationCASBackoff)
		}
	}
	if got := tokenEventCount(t, pool, minted.TokenID); got != 2 {
		t.Fatalf("token event count after bounded conflicts = %d; want mint plus primer consume", got)
	}
}

// TestRegistrationTokens_RejectionsAreUniform covers every token-state cause,
// opposite-end secret mismatches, and disabled precedence with one deadline.
func TestRegistrationTokens_RejectionsAreUniform(t *testing.T) {
	clock := newMutableClock(time.Date(2026, time.July, 22, 9, 0, 0, 0, time.UTC))
	waits := &recordingWaiter{}
	service, pool := newTestRegistrationTokens(t, deterministicRandom(3), clock, waits.WaitUntil)
	expired, err := service.Mint(context.Background(), RegistrationTokenOptions{
		Purpose: RegistrationTokenPurposeAgent, MaxUses: 2, ExpiresAt: clock.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("mint expiry fixture: %v", err)
	}
	disabled, err := service.Mint(context.Background(), RegistrationTokenOptions{
		Purpose: RegistrationTokenPurposeAgent, MaxUses: 2, ExpiresAt: clock.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("mint disabled fixture: %v", err)
	}
	if err := service.Disable(context.Background(), disabled.TokenID); err != nil {
		t.Fatalf("disable registration token: %v", err)
	}
	if err := service.Disable(context.Background(), disabled.TokenID); err != nil {
		t.Fatalf("repeat idempotent disable: %v", err)
	}
	if got := tokenEventCount(t, pool, disabled.TokenID); got != 2 {
		t.Fatalf("disabled token event count = %d; want one mint and one disable", got)
	}
	exhausted, err := service.Mint(context.Background(), RegistrationTokenOptions{
		Purpose: RegistrationTokenPurposeAgent, MaxUses: 1, ExpiresAt: clock.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("mint exhausted fixture: %v", err)
	}
	if _, err := service.Consume(context.Background(), "exhaust-primer", exhausted.Token, RegistrationTokenPurposeAgent); err != nil {
		t.Fatalf("consume exhaustion fixture: %v", err)
	}

	id, secret := decodeMintedToken(t, expired.Token)
	wrongFirst := append([]byte(nil), secret...)
	wrongFirst[0] ^= 0xff
	wrongLast := append([]byte(nil), secret...)
	wrongLast[len(wrongLast)-1] ^= 0xff
	clock.Advance(2 * time.Hour)
	cases := []struct {
		name  string
		token string
	}{
		{name: "malformed", token: "malformed"},
		{name: "unknown", token: "7ZZZZZZZZZZZZZZZZZZZZZZZZZ." + base64.RawURLEncoding.EncodeToString(secret)},
		{name: "wrong first secret byte", token: id + "." + base64.RawURLEncoding.EncodeToString(wrongFirst)},
		{name: "wrong last secret byte", token: id + "." + base64.RawURLEncoding.EncodeToString(wrongLast)},
		{name: "expired", token: expired.Token},
		{name: "disabled and expired", token: disabled.Token},
		{name: "exhausted and expired", token: exhausted.Token},
	}
	for index, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			grant, err := service.Consume(context.Background(), fmt.Sprintf("reject-%d", index), test.token, RegistrationTokenPurposeAgent)
			assertEmptyRegistrationTokenGrant(t, grant)
			if !errors.Is(err, ErrInvalidRegistrationToken) || err.Error() != ErrInvalidRegistrationToken.Error() {
				t.Fatalf("rejection = %v; want byte-identical invalid-token sentinel", err)
			}
		})
	}
	deadlines := waits.Deadlines()
	if len(deadlines) != len(cases) {
		t.Fatalf("rejection waits = %d; want %d", len(deadlines), len(cases))
	}
	for index, deadline := range deadlines[1:] {
		if !deadline.Equal(deadlines[0]) {
			t.Fatalf("rejection deadline %d = %s; want %s", index+1, deadline, deadlines[0])
		}
	}
	disabledState, err := service.eventStore.RegistrationToken(context.Background(), disabled.TokenID)
	if err != nil {
		t.Fatalf("read disabled token: %v", err)
	}
	if disabledState.Uses != 0 || !disabledState.Disabled {
		t.Fatalf("disabled token state = %+v; want kill switch with zero consumes", disabledState)
	}
}

func TestRegistrationTokens_RateLimitsFiveAttemptsPerSlidingMinute(t *testing.T) {
	clock := newMutableClock(time.Date(2026, time.July, 22, 9, 0, 0, 0, time.UTC))
	service, _ := newTestRegistrationTokens(t, deterministicRandom(1), clock, noWait)
	minted, err := service.Mint(context.Background(), RegistrationTokenOptions{
		Purpose: RegistrationTokenPurposeAgent, MaxUses: 10, ExpiresAt: clock.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("mint rate-limit fixture: %v", err)
	}
	for attempt := range 5 {
		if _, err := service.Consume(context.Background(), "same-source", minted.Token, RegistrationTokenPurposeAgent); err != nil {
			t.Fatalf("allowed attempt %d: %v", attempt+1, err)
		}
	}
	if _, err := service.Consume(context.Background(), "same-source", minted.Token, RegistrationTokenPurposeAgent); !errors.Is(err, ErrRegistrationRateLimited) {
		t.Fatalf("sixth attempt error = %v; want rate-limit sentinel", err)
	}
	if _, err := service.Consume(context.Background(), "different-source", minted.Token, RegistrationTokenPurposeAgent); err != nil {
		t.Fatalf("independent source rejected: %v", err)
	}
	clock.Advance(time.Minute + time.Nanosecond)
	if _, err := service.Consume(context.Background(), "same-source", minted.Token, RegistrationTokenPurposeAgent); err != nil {
		t.Fatalf("source rejected after sliding window elapsed: %v", err)
	}
}

func TestRegistrationTokens_MintFailureWritesNothing(t *testing.T) {
	clock := newMutableClock(time.Date(2026, time.July, 22, 9, 0, 0, 0, time.UTC))
	wantRNG := errors.New("rng unavailable")
	service, pool := newTestRegistrationTokens(t, errorReader{err: wantRNG}, clock, noWait)
	tests := []struct {
		name    string
		ctx     context.Context
		options RegistrationTokenOptions
		want    string
	}{
		{name: "nil context", options: RegistrationTokenOptions{Purpose: RegistrationTokenPurposeAgent, MaxUses: 1, ExpiresAt: clock.Now().Add(time.Hour)}, want: "nil context"},
		{name: "invalid purpose", ctx: context.Background(), options: RegistrationTokenOptions{MaxUses: 1, ExpiresAt: clock.Now().Add(time.Hour)}, want: "purpose"},
		{name: "zero max uses", ctx: context.Background(), options: RegistrationTokenOptions{Purpose: RegistrationTokenPurposeAgent, ExpiresAt: clock.Now().Add(time.Hour)}, want: "max uses"},
		{name: "past expiry", ctx: context.Background(), options: RegistrationTokenOptions{Purpose: RegistrationTokenPurposeAgent, MaxUses: 1, ExpiresAt: clock.Now()}, want: "future"},
		{name: "invalid owner", ctx: context.Background(), options: RegistrationTokenOptions{Purpose: RegistrationTokenPurposeAgent, MaxUses: 1, ExpiresAt: clock.Now().Add(time.Hour), Owner: "bad\x00owner"}, want: "owner"},
		{name: "agent token with DNS names", ctx: context.Background(), options: RegistrationTokenOptions{Purpose: RegistrationTokenPurposeAgent, MaxUses: 1, ExpiresAt: clock.Now().Add(time.Hour), DNSNames: []string{"gateway.internal.example"}}, want: "DNS"},
		{name: "gateway token without DNS names", ctx: context.Background(), options: RegistrationTokenOptions{Purpose: RegistrationTokenPurposeGateway, MaxUses: 1, ExpiresAt: clock.Now().Add(time.Hour)}, want: "DNS"},
		{name: "randomness failure", ctx: context.Background(), options: RegistrationTokenOptions{Purpose: RegistrationTokenPurposeAgent, MaxUses: 1, ExpiresAt: clock.Now().Add(time.Hour)}, want: wantRNG.Error()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := service.Mint(test.ctx, test.options)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Mint error = %v; want %q", err, test.want)
			}
		})
	}
	if got := allEventCount(t, pool); got != 0 {
		t.Fatalf("events after rejected mints = %d; want 0", got)
	}
}

func TestRegistrationTokens_MintGatewayWithoutDNSRejectsAtPKIBoundary(t *testing.T) {
	clock := newMutableClock(time.Date(2026, time.July, 22, 9, 0, 0, 0, time.UTC))
	random := &countingRandomReader{}
	service, pool := newTestRegistrationTokens(t, random, clock, noWait)
	minted, err := service.Mint(context.Background(), RegistrationTokenOptions{
		Purpose:   RegistrationTokenPurposeGateway,
		MaxUses:   1,
		ExpiresAt: clock.Now().Add(time.Hour),
		DNSNames:  []string{},
	})
	if err == nil {
		t.Fatal("Mint accepted a gateway registration token without DNS names")
	}
	message := strings.ToLower(err.Error())
	if !strings.Contains(message, "pki:") ||
		!strings.Contains(message, "gateway registration token") ||
		!strings.Contains(message, "dns name") {
		t.Errorf("Mint error = %q; want friendly PKI gateway-DNS validation category", err)
	}
	for _, leakedLayer := range []string{"store:", "sqlstate", "constraint", "registration_tokens_dns_names_check"} {
		if strings.Contains(message, leakedLayer) {
			t.Errorf("Mint error = %q; must not expose lower-layer category %q", err, leakedLayer)
		}
	}
	if minted.TokenID != "" || minted.Token != "" || random.readCalls != 0 {
		t.Fatalf("rejected Mint returned/consumed token material = (%q, %q, %d random reads); want none", minted.TokenID, minted.Token, random.readCalls)
	}
	if events := allEventCount(t, pool); events != 0 {
		t.Fatalf("events after rejected gateway Mint = %d; want zero", events)
	}
	var projections int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM registration_tokens`).Scan(&projections); err != nil {
		t.Fatalf("count registration-token projections: %v", err)
	}
	if projections != 0 {
		t.Fatalf("registration-token projections after rejected gateway Mint = %d; want zero", projections)
	}
}

func TestNewRegistrationTokens_RejectsNilStore(t *testing.T) {
	service, err := NewRegistrationTokens(nil)
	if err == nil || service != nil || !strings.Contains(err.Error(), "nil registration-token event store") {
		t.Fatalf("NewRegistrationTokens(nil) = (%v, %v); want nil and nil-store error", service, err)
	}
}

func TestRegistrationTokens_ConstantTimeHashGate(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "registration_tokens.go", nil, 0)
	if err != nil {
		t.Fatalf("parse registration-token implementation: %v", err)
	}
	constantTimeCalls := 0
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "ConstantTimeCompare" {
			return true
		}
		identifier, ok := selector.X.(*ast.Ident)
		if ok && identifier.Name == "subtle" {
			constantTimeCalls++
		}
		return true
	})
	if constantTimeCalls != 1 {
		t.Fatalf("subtle.ConstantTimeCompare call sites = %d; want sole hash-authentication chokepoint", constantTimeCalls)
	}
}

func TestRegistrationRateLimiter_BoundsTrackedSources(t *testing.T) {
	limiter := newRegistrationRateLimiter()
	now := time.Date(2026, time.July, 22, 9, 0, 0, 0, time.UTC)
	for source := range maxTrackedRegistrationSources {
		if !limiter.Allow(fmt.Sprintf("source-%d", source), now) {
			t.Fatalf("source %d rejected below tracker bound", source)
		}
	}
	if limiter.Allow("overflow-source", now) {
		t.Fatal("source tracker accepted an unbounded new entry")
	}
	if len(limiter.attempts) != maxTrackedRegistrationSources {
		t.Fatalf("tracked sources = %d; want bound %d", len(limiter.attempts), maxTrackedRegistrationSources)
	}
	if !limiter.Allow("overflow-source", now.Add(time.Minute+time.Nanosecond)) {
		t.Fatal("expired sources were not pruned for a new admission")
	}
}

func newTestRegistrationTokens(
	t *testing.T,
	random io.Reader,
	clock *mutableClock,
	waitUntil func(context.Context, time.Time) error,
) (*RegistrationTokens, *pgxpool.Pool) {
	t.Helper()
	pool := registrationPostgres.Database(t, store.Migrate)
	eventStore, err := store.NewProduction(pool)
	if err != nil {
		t.Fatalf("create production event store: %v", err)
	}
	service, err := newRegistrationTokens(eventStore, random, clock.Now, waitUntil)
	if err != nil {
		t.Fatalf("create registration-token service: %v", err)
	}
	return service, pool
}

func deterministicRandom(mints int) io.Reader {
	material := make([]byte, mints*42)
	for index := range material {
		material[index] = byte(index + 1)
	}
	return bytes.NewReader(material)
}

func decodeMintedToken(t *testing.T, token string) (string, []byte) {
	t.Helper()
	id, encoded, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatalf("minted token %q has no locator separator", token)
	}
	secret, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode minted token secret: %v", err)
	}
	return id, secret
}

func assertEmptyRegistrationTokenGrant(t *testing.T, grant RegistrationTokenGrant) {
	t.Helper()
	if grant.TokenID != "" || grant.Owner != "" || grant.Purpose != "" || len(grant.DNSNames) != 0 {
		t.Fatalf("rejected consume returned grant %+v; want empty grant", grant)
	}
}

func tokenEventCount(t *testing.T, pool *pgxpool.Pool, tokenID string) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM events WHERE stream_type = 'registration-token' AND stream_id = $1`,
		tokenID,
	).Scan(&count); err != nil {
		t.Fatalf("count registration-token events: %v", err)
	}
	return count
}

func allEventCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM events`).Scan(&count); err != nil {
		t.Fatalf("count all events: %v", err)
	}
	return count
}

type mutableClock struct {
	mu  sync.Mutex
	now time.Time
}

func newMutableClock(now time.Time) *mutableClock { return &mutableClock{now: now} }

func (c *mutableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *mutableClock) Advance(delta time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(delta)
}

type recordingWaiter struct {
	mu        sync.Mutex
	deadlines []time.Time
}

func (w *recordingWaiter) WaitUntil(_ context.Context, deadline time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func (w *recordingWaiter) Deadlines() []time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]time.Time(nil), w.deadlines...)
}

func noWait(context.Context, time.Time) error { return nil }

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type countingRandomReader struct{ readCalls int }

func (r *countingRandomReader) Read(buffer []byte) (int, error) {
	r.readCalls++
	for index := range buffer {
		buffer[index] = byte(index + 1)
	}
	return len(buffer), nil
}
