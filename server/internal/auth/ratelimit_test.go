package auth

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

const testRateLimitProcedure = "/test.AuthService/Authenticate"

func TestFailureLadder_ThrottlesFailedAccountsWithoutLockout(t *testing.T) {
	ladder := mustFailureLadder(t, map[string]RateLimitPolicy{
		testRateLimitProcedure: {
			PerIP:      FailureLimit{Attempts: 10, Window: time.Minute},
			PerAccount: FailureLimit{Attempts: 2, Window: time.Minute},
		},
	})
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	attempt := AuthenticationAttempt{
		Procedure:  testRateLimitProcedure,
		ClientIP:   netip.MustParseAddr("192.0.2.10"),
		AccountKey: "user:alice",
	}

	for number := 1; number <= 2; number++ {
		if !ladder.Allow(attempt, now.Add(time.Duration(number)*time.Second)) {
			t.Fatalf("failed authentication %d denied before the configured account limit", number)
		}
	}
	if ladder.Allow(attempt, now.Add(3*time.Second)) {
		t.Fatal("failed authentication after the account limit was allowed")
	}

	attempt.Succeeded = true
	if !ladder.Allow(attempt, now.Add(4*time.Second)) {
		t.Fatal("correct authentication was locked out by accumulated failures")
	}
	attempt.Succeeded = false
	if ladder.Allow(attempt, now.Add(5*time.Second)) {
		t.Fatal("successful authentication unexpectedly cleared the failure throttle")
	}
}

func TestFailureLadder_EnforcesIPAndAccountIndependently(t *testing.T) {
	policy := map[string]RateLimitPolicy{
		testRateLimitProcedure: {
			PerIP:      FailureLimit{Attempts: 1, Window: time.Minute},
			PerAccount: FailureLimit{Attempts: 1, Window: time.Minute},
		},
	}
	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

	t.Run("IP bucket crosses accounts", func(t *testing.T) {
		ladder := mustFailureLadder(t, policy)
		if !ladder.Allow(AuthenticationAttempt{
			Procedure:  testRateLimitProcedure,
			ClientIP:   netip.MustParseAddr("192.0.2.10"),
			AccountKey: "user:alice",
		}, now) {
			t.Fatal("first failed authentication was denied")
		}
		if ladder.Allow(AuthenticationAttempt{
			Procedure:  testRateLimitProcedure,
			ClientIP:   netip.MustParseAddr("192.0.2.10"),
			AccountKey: "user:bob",
		}, now.Add(time.Second)) {
			t.Fatal("a different account bypassed the exhausted IP bucket")
		}
	})

	t.Run("account bucket crosses IPs", func(t *testing.T) {
		ladder := mustFailureLadder(t, policy)
		if !ladder.Allow(AuthenticationAttempt{
			Procedure:  testRateLimitProcedure,
			ClientIP:   netip.MustParseAddr("192.0.2.10"),
			AccountKey: "user:alice",
		}, now) {
			t.Fatal("first failed authentication was denied")
		}
		if ladder.Allow(AuthenticationAttempt{
			Procedure:  testRateLimitProcedure,
			ClientIP:   netip.MustParseAddr("198.51.100.10"),
			AccountKey: "user:alice",
		}, now.Add(time.Second)) {
			t.Fatal("a different IP bypassed the exhausted account bucket")
		}
	})
}

func TestFailureLadder_ExpiresSlidingWindows(t *testing.T) {
	const window = time.Minute
	policies := map[string]RateLimitPolicy{
		testRateLimitProcedure: {
			PerIP:      FailureLimit{Attempts: 1, Window: window},
			PerAccount: FailureLimit{Attempts: 1, Window: window},
		},
	}
	start := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	attempt := AuthenticationAttempt{
		Procedure:  testRateLimitProcedure,
		ClientIP:   netip.MustParseAddr("192.0.2.10"),
		AccountKey: "user:alice",
	}
	early := mustFailureLadder(t, policies)
	if !early.Allow(attempt, start) {
		t.Fatal("first failed authentication was denied")
	}
	if early.Allow(attempt, start.Add(window-time.Nanosecond)) {
		t.Fatal("failure bucket expired before its sliding window elapsed")
	}

	expired := mustFailureLadder(t, policies)
	if !expired.Allow(attempt, start) {
		t.Fatal("first failed authentication in expiry fixture was denied")
	}
	if !expired.Allow(attempt, start.Add(window)) {
		t.Fatal("failure bucket did not expire at the sliding-window boundary")
	}
}

func TestFailureLadder_RejectedFailuresExtendSlidingWindowWithoutLockout(t *testing.T) {
	const window = time.Minute
	ladder := mustFailureLadder(t, map[string]RateLimitPolicy{
		testRateLimitProcedure: {
			PerIP:      FailureLimit{Attempts: 2, Window: window},
			PerAccount: FailureLimit{Attempts: 2, Window: window},
		},
	})
	start := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	attempt := AuthenticationAttempt{
		Procedure:  testRateLimitProcedure,
		ClientIP:   netip.MustParseAddr("192.0.2.10"),
		AccountKey: "user:alice",
	}
	for _, offset := range []time.Duration{0, time.Second} {
		if !ladder.Allow(attempt, start.Add(offset)) {
			t.Fatalf("failed authentication at %s denied before the configured limit", offset)
		}
	}
	if ladder.Allow(attempt, start.Add(59*time.Second)) {
		t.Fatal("sustained failure inside the full bucket was allowed")
	}
	if ladder.Allow(attempt, start.Add(window)) {
		t.Fatal("recent rejected failure did not extend the sliding window")
	}

	attempt.Succeeded = true
	if !ladder.Allow(attempt, start.Add(window)) {
		t.Fatal("correct authentication was locked out by sustained rejected failures")
	}
}

func TestFailureLadder_FailsClosedForInvalidInputAndCapacity(t *testing.T) {
	validPolicy := RateLimitPolicy{
		PerIP:      FailureLimit{Attempts: 2, Window: time.Minute},
		PerAccount: FailureLimit{Attempts: 2, Window: time.Minute},
	}
	for _, test := range []struct {
		name     string
		policies map[string]RateLimitPolicy
		wantErr  string
	}{
		{name: "nil policies", policies: nil, wantErr: "rate-limit policy registry is empty"},
		{name: "empty policies", policies: map[string]RateLimitPolicy{}, wantErr: "rate-limit policy registry is empty"},
		{name: "empty procedure", policies: map[string]RateLimitPolicy{"": validPolicy}, wantErr: "rate-limit policy procedure is empty"},
		{name: "missing IP limit", policies: map[string]RateLimitPolicy{
			testRateLimitProcedure: {PerAccount: validPolicy.PerAccount},
		}, wantErr: "rate-limit policy is invalid"},
		{name: "missing account limit", policies: map[string]RateLimitPolicy{
			testRateLimitProcedure: {PerIP: validPolicy.PerIP},
		}, wantErr: "rate-limit policy is invalid"},
		{name: "zero attempts", policies: map[string]RateLimitPolicy{
			testRateLimitProcedure: {
				PerIP:      FailureLimit{Window: time.Minute},
				PerAccount: validPolicy.PerAccount,
			},
		}, wantErr: "rate-limit policy is invalid"},
		{name: "zero window", policies: map[string]RateLimitPolicy{
			testRateLimitProcedure: {
				PerIP:      validPolicy.PerIP,
				PerAccount: FailureLimit{Attempts: 1},
			},
		}, wantErr: "rate-limit policy is invalid"},
		{name: "negative attempts", policies: map[string]RateLimitPolicy{
			testRateLimitProcedure: {
				PerIP:      FailureLimit{Attempts: -1, Window: time.Minute},
				PerAccount: validPolicy.PerAccount,
			},
		}, wantErr: "rate-limit policy is invalid"},
		{name: "negative window", policies: map[string]RateLimitPolicy{
			testRateLimitProcedure: {
				PerIP:      validPolicy.PerIP,
				PerAccount: FailureLimit{Attempts: 1, Window: -time.Second},
			},
		}, wantErr: "rate-limit policy is invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ladder, err := NewFailureLadder(test.policies)
			if err == nil || ladder != nil {
				t.Fatalf("NewFailureLadder = (%v, %v); want nil ladder and %q", ladder, err, test.wantErr)
			}
			if err.Error() != test.wantErr {
				t.Fatalf("NewFailureLadder error = %q; want %q", err, test.wantErr)
			}
		})
	}

	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	ladder := mustFailureLadder(t, map[string]RateLimitPolicy{
		testRateLimitProcedure: validPolicy,
	})
	validAttempt := AuthenticationAttempt{
		Procedure:  testRateLimitProcedure,
		ClientIP:   netip.MustParseAddr("192.0.2.10"),
		AccountKey: "user:alice",
	}
	var nilLadder *FailureLadder
	for _, test := range []struct {
		name    string
		ladder  *FailureLadder
		attempt AuthenticationAttempt
	}{
		{name: "nil ladder", ladder: nilLadder, attempt: validAttempt},
		{name: "unknown procedure", ladder: ladder, attempt: AuthenticationAttempt{
			Procedure:  "/unknown.Service/Method",
			ClientIP:   validAttempt.ClientIP,
			AccountKey: validAttempt.AccountKey,
		}},
		{name: "missing procedure", ladder: ladder, attempt: AuthenticationAttempt{
			ClientIP:   validAttempt.ClientIP,
			AccountKey: validAttempt.AccountKey,
		}},
		{name: "invalid client IP", ladder: ladder, attempt: AuthenticationAttempt{
			Procedure:  validAttempt.Procedure,
			AccountKey: validAttempt.AccountKey,
		}},
		{name: "missing account key", ladder: ladder, attempt: AuthenticationAttempt{
			Procedure: validAttempt.Procedure,
			ClientIP:  validAttempt.ClientIP,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.attempt.Succeeded = true
			if test.ladder.Allow(test.attempt, now) {
				t.Fatal("structurally invalid authentication attempt was allowed")
			}
		})
	}

	if failureBucketCapacity < 2 {
		t.Fatalf("failureBucketCapacity = %d; want room for both required dimensions", failureBucketCapacity)
	}
	capacityLadder := mustFailureLadder(t, map[string]RateLimitPolicy{
		testRateLimitProcedure: {
			PerIP:      FailureLimit{Attempts: failureBucketCapacity + 1, Window: time.Hour},
			PerAccount: FailureLimit{Attempts: failureBucketCapacity + 1, Window: time.Hour},
		},
	})
	for index := 0; index < failureBucketCapacity-1; index++ {
		attempt := AuthenticationAttempt{
			Procedure: testRateLimitProcedure,
			ClientIP: netip.AddrFrom4([4]byte{
				10,
				byte(uint32(index) >> 16),
				byte(uint32(index) >> 8),
				byte(index),
			}),
			AccountKey: "user:shared",
		}
		if !capacityLadder.Allow(attempt, now) {
			t.Fatalf("failure bucket %d denied before fixed capacity was reached", index)
		}
	}
	index := failureBucketCapacity - 1
	if capacityLadder.Allow(AuthenticationAttempt{
		Procedure: testRateLimitProcedure,
		ClientIP: netip.AddrFrom4([4]byte{
			10,
			byte(uint32(index) >> 16),
			byte(uint32(index) >> 8),
			byte(index),
		}),
		AccountKey: "user:shared",
	}, now) {
		t.Fatal("new failure bucket was allowed after fixed capacity was exhausted")
	}
}

func TestFailureLadder_DefensivelyCopiesPolicies(t *testing.T) {
	policies := map[string]RateLimitPolicy{
		testRateLimitProcedure: {
			PerIP:      FailureLimit{Attempts: 1, Window: time.Minute},
			PerAccount: FailureLimit{Attempts: 1, Window: time.Minute},
		},
	}
	ladder := mustFailureLadder(t, policies)
	policies[testRateLimitProcedure] = RateLimitPolicy{
		PerIP:      FailureLimit{Attempts: 100, Window: time.Hour},
		PerAccount: FailureLimit{Attempts: 100, Window: time.Hour},
	}
	policies["/injected.Service/Method"] = policies[testRateLimitProcedure]
	delete(policies, testRateLimitProcedure)

	now := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	attempt := AuthenticationAttempt{
		Procedure:  testRateLimitProcedure,
		ClientIP:   netip.MustParseAddr("192.0.2.10"),
		AccountKey: "user:alice",
	}
	if !ladder.Allow(attempt, now) {
		t.Fatal("first failed authentication was denied after caller mutated its policy map")
	}
	if ladder.Allow(attempt, now.Add(time.Second)) {
		t.Fatal("caller mutation changed the ladder's copied failure limit")
	}
	attempt.Procedure = "/injected.Service/Method"
	if ladder.Allow(attempt, now) {
		t.Fatal("caller mutation injected a procedure into the ladder")
	}
}

func TestClientIPResolver_IgnoresForwardedForFromUntrustedPeer(t *testing.T) {
	resolver, err := NewClientIPResolver([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
	})
	if err != nil {
		t.Fatalf("NewClientIPResolver: %v", err)
	}
	peer := netip.MustParseAddr("198.51.100.10")
	for _, forwardedFor := range []string{
		"203.0.113.20, 10.0.0.2",
		"malformed, 10.0.0.2",
	} {
		resolved, err := resolver.Resolve(peer, forwardedFor)
		if err != nil {
			t.Fatalf("Resolve untrusted peer with %q: %v", forwardedFor, err)
		}
		if resolved != peer {
			t.Fatalf("Resolve untrusted peer with %q = %s; want socket peer %s", forwardedFor, resolved, peer)
		}
	}
}

func TestClientIPResolver_WalksTrustedChainRightToLeft(t *testing.T) {
	resolver, err := NewClientIPResolver([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
	})
	if err != nil {
		t.Fatalf("NewClientIPResolver: %v", err)
	}
	resolved, err := resolver.Resolve(
		netip.MustParseAddr("10.0.0.3"),
		"203.0.113.20, 198.51.100.10, 10.0.0.2",
	)
	if err != nil {
		t.Fatalf("Resolve trusted chain: %v", err)
	}
	want := netip.MustParseAddr("198.51.100.10")
	if resolved != want {
		t.Fatalf("Resolve trusted chain = %s; want first untrusted hop %s", resolved, want)
	}

	resolved, err = resolver.Resolve(
		netip.MustParseAddr("10.0.0.3"),
		"malformed-attacker-entry, 198.51.100.10, 10.0.0.2",
	)
	if err != nil {
		t.Fatalf("Resolve trusted chain with malformed entry before trust boundary: %v", err)
	}
	if resolved != want {
		t.Fatalf("Resolve trusted chain with malformed entry before trust boundary = %s; want first untrusted hop %s",
			resolved, want)
	}

	peer := netip.MustParseAddr("10.0.0.4")
	resolved, err = resolver.Resolve(peer, "")
	if err != nil {
		t.Fatalf("Resolve trusted peer without X-Forwarded-For: %v", err)
	}
	if resolved != peer {
		t.Fatalf("Resolve trusted peer without X-Forwarded-For = %s; want socket peer %s", resolved, peer)
	}
}

func TestClientIPResolver_BoundsTrustedForwardedChain(t *testing.T) {
	const expectedMaximumForwardedHops = 32
	resolver, err := NewClientIPResolver([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
	})
	if err != nil {
		t.Fatalf("NewClientIPResolver: %v", err)
	}

	hops := make([]string, 0, expectedMaximumForwardedHops)
	want := netip.MustParseAddr("198.51.100.10")
	hops = append(hops, want.String())
	for range expectedMaximumForwardedHops - 1 {
		hops = append(hops, "10.0.0.2")
	}
	peer := netip.MustParseAddr("10.0.0.3")

	t.Run("accepts maximum", func(t *testing.T) {
		resolved, err := resolver.Resolve(peer, strings.Join(hops, ", "))
		if err != nil {
			t.Fatalf("Resolve %d-hop trusted chain: %v", len(hops), err)
		}
		if resolved != want {
			t.Fatalf("Resolve %d-hop trusted chain = %s; want first untrusted hop %s", len(hops), resolved, want)
		}
	})

	t.Run("rejects oversized", func(t *testing.T) {
		oversized := append(append([]string(nil), hops...), "10.0.0.4")
		if resolved, err := resolver.Resolve(peer, strings.Join(oversized, ", ")); err == nil || resolved.IsValid() {
			t.Fatalf("Resolve %d-hop trusted chain = (%s, %v); want invalid address and error before traversal",
				len(oversized), resolved, err)
		}
	})

	t.Run("untrusted peer ignores hostile chain", func(t *testing.T) {
		hostile := append(append([]string(nil), hops...), "malformed")
		untrustedPeer := netip.MustParseAddr("203.0.113.20")
		resolved, err := resolver.Resolve(untrustedPeer, strings.Join(hostile, ", "))
		if err != nil {
			t.Fatalf("Resolve untrusted peer with oversized malformed chain: %v", err)
		}
		if resolved != untrustedPeer {
			t.Fatalf("Resolve untrusted peer with oversized malformed chain = %s; want socket peer %s",
				resolved, untrustedPeer)
		}
	})
}

func TestClientIPResolver_RejectsMalformedTrustedChain(t *testing.T) {
	resolver, err := NewClientIPResolver([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
	})
	if err != nil {
		t.Fatalf("NewClientIPResolver: %v", err)
	}
	peer := netip.MustParseAddr("10.0.0.3")
	for _, forwardedFor := range []string{
		"203.0.113.20, malformed, 10.0.0.2",
		"203.0.113.20,,10.0.0.2",
	} {
		t.Run(forwardedFor, func(t *testing.T) {
			if resolved, err := resolver.Resolve(peer, forwardedFor); err == nil || resolved.IsValid() {
				t.Fatalf("Resolve malformed trusted chain = (%s, %v); want invalid address and error", resolved, err)
			}
		})
	}
	if resolved, err := resolver.Resolve(netip.Addr{}, "203.0.113.20"); err == nil || resolved.IsValid() {
		t.Fatalf("Resolve invalid socket peer = (%s, %v); want invalid address and error", resolved, err)
	}
}

func TestClientIPResolver_RejectsInvalidConfiguration(t *testing.T) {
	for _, test := range []struct {
		name     string
		prefixes []netip.Prefix
	}{
		{name: "invalid prefix", prefixes: []netip.Prefix{{}}},
		{name: "non-canonical prefix", prefixes: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.1/8"),
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if resolver, err := NewClientIPResolver(test.prefixes); err == nil || resolver != nil {
				t.Fatalf("NewClientIPResolver = (%v, %v); want nil resolver and validation error", resolver, err)
			}
		})
	}

	resolver, err := NewClientIPResolver(nil)
	if err != nil {
		t.Fatalf("NewClientIPResolver without trusted proxies: %v", err)
	}
	peer := netip.MustParseAddr("198.51.100.10")
	resolved, err := resolver.Resolve(peer, "203.0.113.20")
	if err != nil {
		t.Fatalf("Resolve without trusted proxies: %v", err)
	}
	if resolved != peer {
		t.Fatalf("Resolve without trusted proxies = %s; want socket peer %s", resolved, peer)
	}
}

func mustFailureLadder(t *testing.T, policies map[string]RateLimitPolicy) *FailureLadder {
	t.Helper()
	ladder, err := NewFailureLadder(policies)
	if err != nil {
		t.Fatalf("NewFailureLadder: %v", err)
	}
	return ladder
}
