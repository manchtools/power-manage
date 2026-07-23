package auth

import (
	"errors"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	failureBucketCapacity = 4096
	maxAccountKeyBytes    = 512
	maxForwardedForHops   = 32
)

// FailureLimit bounds failed authentication attempts in one sliding window.
type FailureLimit struct {
	Attempts int
	Window   time.Duration
}

// RateLimitPolicy defines the independent IP and account failure dimensions.
type RateLimitPolicy struct {
	PerIP      FailureLimit
	PerAccount FailureLimit
}

// AuthenticationAttempt is one structurally validated authentication result.
type AuthenticationAttempt struct {
	Procedure  string
	ClientIP   netip.Addr
	AccountKey string
	Succeeded  bool
}

// FailureLadder tracks per-process authentication failures.
type FailureLadder struct {
	mu        sync.Mutex
	policies  map[string]RateLimitPolicy
	buckets   map[failureBucketKey]failureBucket
	nextSweep time.Time
}

type failureDimension uint8

const (
	failureDimensionIP failureDimension = iota + 1
	failureDimensionAccount
)

type failureBucketKey struct {
	procedure string
	value     string
	dimension failureDimension
}

type failureBucket struct {
	attempts []time.Time
	window   time.Duration
}

// NewFailureLadder validates and defensively copies the public policy registry.
func NewFailureLadder(policies map[string]RateLimitPolicy) (*FailureLadder, error) {
	if len(policies) == 0 {
		return nil, errors.New("rate-limit policy registry is empty")
	}
	for procedure, policy := range policies {
		if procedure == "" {
			return nil, errors.New("rate-limit policy procedure is empty")
		}
		if !validFailureLimit(policy.PerIP) || !validFailureLimit(policy.PerAccount) {
			return nil, errors.New("rate-limit policy is invalid")
		}
	}
	return &FailureLadder{
		policies: maps.Clone(policies),
		buckets:  make(map[failureBucketKey]failureBucket),
	}, nil
}

func validFailureLimit(limit FailureLimit) bool {
	return limit.Attempts > 0 && limit.Window > 0
}

// Allow records a failed attempt and reports whether it remains below both
// limits. A valid successful attempt always bypasses existing failure buckets.
func (l *FailureLadder) Allow(attempt AuthenticationAttempt, now time.Time) bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	policy, ok := l.policies[attempt.Procedure]
	if !ok || !validAuthenticationAttempt(attempt) {
		return false
	}
	if attempt.Succeeded {
		return true
	}
	if l.nextSweep.IsZero() || !now.Before(l.nextSweep) {
		l.prune(now)
		l.nextSweep = now.Add(time.Minute)
	}

	keys := [2]failureBucketKey{
		{
			procedure: attempt.Procedure,
			value:     attempt.ClientIP.Unmap().String(),
			dimension: failureDimensionIP,
		},
		{
			procedure: attempt.Procedure,
			value:     attempt.AccountKey,
			dimension: failureDimensionAccount,
		},
	}
	limits := [2]FailureLimit{policy.PerIP, policy.PerAccount}
	l.pruneKeys(keys, limits, now)
	if l.newBucketCount(keys)+len(l.buckets) > failureBucketCapacity {
		l.prune(now)
		if l.newBucketCount(keys)+len(l.buckets) > failureBucketCapacity {
			return false
		}
	}

	allowed := true
	for index, key := range keys {
		bucket := l.buckets[key]
		limit := limits[index]
		if len(bucket.attempts) >= limit.Attempts {
			allowed = false
			copy(bucket.attempts, bucket.attempts[1:])
			bucket.attempts[len(bucket.attempts)-1] = now
		} else {
			bucket.attempts = append(bucket.attempts, now)
		}
		bucket.window = limit.Window
		l.buckets[key] = bucket
	}
	return allowed
}

func validAuthenticationAttempt(attempt AuthenticationAttempt) bool {
	return attempt.Procedure != "" &&
		attempt.ClientIP.IsValid() &&
		attempt.AccountKey != "" &&
		len(attempt.AccountKey) <= maxAccountKeyBytes &&
		utf8.ValidString(attempt.AccountKey) &&
		!strings.ContainsRune(attempt.AccountKey, '\x00')
}

func (l *FailureLadder) newBucketCount(keys [2]failureBucketKey) int {
	count := 0
	for _, key := range keys {
		if _, exists := l.buckets[key]; !exists {
			count++
		}
	}
	return count
}

func (l *FailureLadder) pruneKeys(keys [2]failureBucketKey, limits [2]FailureLimit, now time.Time) {
	for index, key := range keys {
		bucket, exists := l.buckets[key]
		if !exists {
			continue
		}
		bucket.attempts = currentFailures(bucket.attempts, now.Add(-limits[index].Window))
		if len(bucket.attempts) == 0 {
			delete(l.buckets, key)
			continue
		}
		bucket.window = limits[index].Window
		l.buckets[key] = bucket
	}
}

func (l *FailureLadder) prune(now time.Time) {
	for key, bucket := range l.buckets {
		bucket.attempts = currentFailures(bucket.attempts, now.Add(-bucket.window))
		if len(bucket.attempts) == 0 {
			delete(l.buckets, key)
			continue
		}
		l.buckets[key] = bucket
	}
}

func currentFailures(attempts []time.Time, cutoff time.Time) []time.Time {
	firstCurrent := 0
	for firstCurrent < len(attempts) && !attempts[firstCurrent].After(cutoff) {
		firstCurrent++
	}
	return append(attempts[:0], attempts[firstCurrent:]...)
}

// ClientIPResolver applies trusted-proxy X-Forwarded-For semantics.
type ClientIPResolver struct {
	trusted []netip.Prefix
}

// NewClientIPResolver validates and copies the trusted proxy prefixes.
func NewClientIPResolver(trusted []netip.Prefix) (*ClientIPResolver, error) {
	for _, prefix := range trusted {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
			return nil, errors.New("trusted proxy prefix is invalid")
		}
	}
	return &ClientIPResolver{trusted: slices.Clone(trusted)}, nil
}

// Resolve ignores X-Forwarded-For for untrusted peers and otherwise walks
// right-to-left until it reaches the first untrusted hop.
func (r *ClientIPResolver) Resolve(peer netip.Addr, forwardedFor string) (netip.Addr, error) {
	if r == nil || !peer.IsValid() {
		return netip.Addr{}, errors.New("client IP peer is invalid")
	}
	current := peer.Unmap()
	if forwardedFor == "" || !r.isTrusted(current) {
		return current, nil
	}
	if strings.Count(forwardedFor, ",") >= maxForwardedForHops {
		return netip.Addr{}, errors.New("trusted proxy chain is invalid")
	}
	hops := strings.Split(forwardedFor, ",")
	for index := len(hops) - 1; index >= 0 && r.isTrusted(current); index-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[index]))
		if err != nil {
			return netip.Addr{}, errors.New("trusted proxy chain is invalid")
		}
		current = hop.Unmap()
	}
	return current, nil
}

func (r *ClientIPResolver) isTrusted(address netip.Addr) bool {
	for _, prefix := range r.trusted {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
