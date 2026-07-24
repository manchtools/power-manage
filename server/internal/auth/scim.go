package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	scimBearerPrefix              = "pm_scim_"
	scimBearerBytes               = 32
	scimFailureBucketCapacity     = 4096
	minimumSCIMRejectionDuration  = 100 * time.Microsecond
	maxSCIMAuthorizationHeaderLen = 256
)

var (
	// ErrSCIMInvalid identifies invalid provider-management input.
	ErrSCIMInvalid = errors.New("auth: SCIM provider input is invalid")
	// ErrSCIMRejected is the static response for every rejected bearer.
	ErrSCIMRejected = errors.New("auth: SCIM bearer rejected")
	// ErrSCIMRateLimited identifies a request rejected before bcrypt.
	ErrSCIMRateLimited = errors.New("auth: SCIM request rate limited")
	// ErrSCIMUnavailable identifies a request without a durable conclusion.
	ErrSCIMUnavailable = errors.New("auth: SCIM service unavailable")
	// ErrSCIMAuthenticatorNotWired classifies missing authenticator dependencies.
	ErrSCIMAuthenticatorNotWired = errors.New("auth: SCIM authenticator is not wired")
)

// SCIMFailureLimits defines independent provider and provider-IP windows.
type SCIMFailureLimits struct {
	PerProvider   FailureLimit
	PerProviderIP FailureLimit
}

// SCIMFailureLimiter tracks failed bearer checks without making bcrypt
// attacker-reachable after either window is exhausted.
type SCIMFailureLimiter struct {
	mu      sync.Mutex
	limits  SCIMFailureLimits
	buckets map[scimFailureBucketKey][]time.Time
}

type scimFailureBucketKey struct {
	provider string
	address  netip.Addr
}

// NewSCIMFailureLimiter validates the two required failure windows.
func NewSCIMFailureLimiter(limits SCIMFailureLimits) (*SCIMFailureLimiter, error) {
	if !validFailureLimit(limits.PerProvider) || !validFailureLimit(limits.PerProviderIP) {
		return nil, errors.New("auth: SCIM failure limits are invalid")
	}
	return &SCIMFailureLimiter{
		limits:  limits,
		buckets: make(map[scimFailureBucketKey][]time.Time),
	}, nil
}

// Check reports whether both SCIM failure dimensions permit bcrypt work.
func (l *SCIMFailureLimiter) Check(providerSlug string, address netip.Addr, now time.Time) bool {
	if l == nil || !validSCIMProviderSlug(providerSlug) || !address.IsValid() || now.IsZero() {
		return false
	}
	address = address.Unmap()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(now)
	keys := [2]scimFailureBucketKey{
		{provider: providerSlug},
		{provider: providerSlug, address: address},
	}
	if l.newBucketCount(keys)+len(l.buckets) > scimFailureBucketCapacity {
		return false
	}
	return len(l.buckets[keys[0]]) <
		l.limits.PerProvider.Attempts &&
		len(l.buckets[keys[1]]) <
			l.limits.PerProviderIP.Attempts
}

// RecordFailure adds one failed bearer check to both independent windows.
func (l *SCIMFailureLimiter) RecordFailure(
	providerSlug string,
	address netip.Addr,
	now time.Time,
) {
	if l == nil || !validSCIMProviderSlug(providerSlug) || !address.IsValid() || now.IsZero() {
		return
	}
	address = address.Unmap()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(now)
	keys := [2]scimFailureBucketKey{
		{provider: providerSlug},
		{provider: providerSlug, address: address},
	}
	for _, key := range keys {
		if _, exists := l.buckets[key]; !exists &&
			len(l.buckets) >= scimFailureBucketCapacity {
			continue
		}
		l.buckets[key] = append(l.buckets[key], now)
	}
}

func (l *SCIMFailureLimiter) newBucketCount(keys [2]scimFailureBucketKey) int {
	count := 0
	for _, key := range keys {
		if _, exists := l.buckets[key]; !exists {
			count++
		}
	}
	return count
}

func (l *SCIMFailureLimiter) prune(now time.Time) {
	for key, failures := range l.buckets {
		window := l.limits.PerProvider
		if key.address.IsValid() {
			window = l.limits.PerProviderIP
		}
		failures = currentFailures(failures, now.Add(-window.Window))
		if len(failures) == 0 {
			delete(l.buckets, key)
			continue
		}
		l.buckets[key] = failures
	}
}

// SCIMProviderManager mints one-time provider bearers and persists only bcrypt
// verifiers.
type SCIMProviderManager struct {
	eventStore *store.Store
	random     io.Reader
	randomMu   sync.Mutex
	now        func() time.Time
	hash       func([]byte) ([]byte, error)
}

// NewSCIMProviderManager validates the provider-management dependencies.
func NewSCIMProviderManager(
	eventStore *store.Store,
	random io.Reader,
	now func() time.Time,
	hash func([]byte) ([]byte, error),
) (*SCIMProviderManager, error) {
	if eventStore == nil || random == nil || now == nil || hash == nil {
		return nil, errors.New("auth: SCIM provider manager is not wired")
	}
	return &SCIMProviderManager{
		eventStore: eventStore,
		random:     random,
		now:        now,
		hash:       hash,
	}, nil
}

// Create returns a fresh provider bearer once.
func (m *SCIMProviderManager) Create(ctx context.Context, providerSlug string) (string, error) {
	if !m.wired() || ctx == nil || !validSCIMProviderSlug(providerSlug) || m.now().IsZero() {
		return "", ErrSCIMInvalid
	}
	bearer, hash, err := m.newBearer()
	if err != nil {
		return "", fmt.Errorf("%w: mint provider bearer", ErrSCIMUnavailable)
	}
	event, err := store.SCIMProviderCreatedEvent(providerSlug, hash)
	if err != nil {
		return "", fmt.Errorf("%w: create provider event", ErrSCIMUnavailable)
	}
	if err := m.eventStore.AppendEventWithVersion(ctx, event, 0); err != nil {
		return "", fmt.Errorf("%w: persist provider", ErrSCIMUnavailable)
	}
	return bearer, nil
}

// Rotate replaces one enabled provider bearer and returns the new value once.
func (m *SCIMProviderManager) Rotate(ctx context.Context, providerSlug string) (string, error) {
	if !m.wired() || ctx == nil || !validSCIMProviderSlug(providerSlug) || m.now().IsZero() {
		return "", ErrSCIMInvalid
	}
	provider, err := m.eventStore.SCIMProvider(ctx, providerSlug)
	if err != nil {
		if store.IsNotFound(err) {
			return "", ErrSCIMInvalid
		}
		return "", fmt.Errorf("%w: read provider", ErrSCIMUnavailable)
	}
	if provider.Disabled {
		return "", ErrSCIMInvalid
	}
	bearer, hash, err := m.newBearer()
	if err != nil {
		return "", fmt.Errorf("%w: mint provider bearer", ErrSCIMUnavailable)
	}
	event, err := store.SCIMProviderTokenRotatedEvent(providerSlug, hash)
	if err != nil {
		return "", fmt.Errorf("%w: create rotation event", ErrSCIMUnavailable)
	}
	if err := m.eventStore.AppendEventWithVersion(
		ctx,
		event,
		provider.ProjectionVersion,
	); err != nil {
		return "", fmt.Errorf("%w: persist provider rotation", ErrSCIMUnavailable)
	}
	return bearer, nil
}

// Disable idempotently disables one provider.
func (m *SCIMProviderManager) Disable(ctx context.Context, providerSlug string) error {
	if !m.wired() || ctx == nil || !validSCIMProviderSlug(providerSlug) || m.now().IsZero() {
		return ErrSCIMInvalid
	}
	provider, err := m.eventStore.SCIMProvider(ctx, providerSlug)
	if err != nil {
		if store.IsNotFound(err) {
			return ErrSCIMInvalid
		}
		return fmt.Errorf("%w: read provider", ErrSCIMUnavailable)
	}
	if provider.Disabled {
		return nil
	}
	event, err := store.SCIMProviderDisabledEvent(providerSlug)
	if err != nil {
		return fmt.Errorf("%w: create provider disable event", ErrSCIMUnavailable)
	}
	if err := m.eventStore.AppendEventWithVersion(
		ctx,
		event,
		provider.ProjectionVersion,
	); err != nil {
		return fmt.Errorf("%w: persist provider disable", ErrSCIMUnavailable)
	}
	return nil
}

func (m *SCIMProviderManager) newBearer() (string, []byte, error) {
	m.randomMu.Lock()
	defer m.randomMu.Unlock()
	raw := make([]byte, scimBearerBytes)
	if _, err := io.ReadFull(m.random, raw); err != nil {
		return "", nil, fmt.Errorf("read SCIM bearer entropy: %w", err)
	}
	bearer := scimBearerPrefix + base64.RawURLEncoding.EncodeToString(raw)
	hash, err := m.hash([]byte(bearer))
	if err != nil {
		return "", nil, fmt.Errorf("hash SCIM bearer: %w", err)
	}
	return bearer, hash, nil
}

func (m *SCIMProviderManager) wired() bool {
	return m != nil &&
		m.eventStore != nil &&
		m.random != nil &&
		m.now != nil &&
		m.hash != nil
}

// SCIMAuthenticator applies pre-bcrypt limits and identical bearer rejection.
type SCIMAuthenticator struct {
	eventStore *store.Store
	limiter    *SCIMFailureLimiter
	resolver   *ClientIPResolver
	compare    func([]byte, []byte) error
	dummyHash  []byte
	now        func() time.Time
}

// NewSCIMAuthenticator validates every dependency at the SCIM trust boundary.
func NewSCIMAuthenticator(
	eventStore *store.Store,
	limiter *SCIMFailureLimiter,
	resolver *ClientIPResolver,
	compare func([]byte, []byte) error,
	dummyHash []byte,
	now func() time.Time,
) (*SCIMAuthenticator, error) {
	_, hashErr := bcrypt.Cost(dummyHash)
	if eventStore == nil || limiter == nil || resolver == nil ||
		compare == nil || hashErr != nil || now == nil {
		return nil, ErrSCIMAuthenticatorNotWired
	}
	return &SCIMAuthenticator{
		eventStore: eventStore,
		limiter:    limiter,
		resolver:   resolver,
		compare:    compare,
		dummyHash:  append([]byte(nil), dummyHash...),
		now:        now,
	}, nil
}

// Authenticate verifies one provider bearer after both rate-limit checks.
func (a *SCIMAuthenticator) Authenticate(
	ctx context.Context,
	providerSlug string,
	authorization string,
	remoteAddress string,
	forwardedFor string,
) error {
	if !a.wired() || ctx == nil {
		return ErrSCIMUnavailable
	}
	providerSlug = strings.TrimSpace(providerSlug)
	peer, err := peerAddress(remoteAddress)
	if err != nil || !validSCIMProviderSlug(providerSlug) {
		return ErrSCIMRejected
	}
	clientIP, err := a.resolver.Resolve(peer, forwardedFor)
	if err != nil {
		return ErrSCIMRejected
	}
	now := a.now()
	if now.IsZero() || !a.limiter.Check(providerSlug, clientIP, now) {
		return ErrSCIMRateLimited
	}

	bearer, structurallyValid := parseSCIMAuthorization(authorization)
	provider, providerErr := a.eventStore.SCIMProvider(ctx, providerSlug)
	if providerErr != nil && !store.IsNotFound(providerErr) {
		return ErrSCIMUnavailable
	}
	hash := a.dummyHash
	if providerErr == nil {
		hash = []byte(provider.TokenHash)
	}
	matches := a.compare(hash, []byte(bearer)) == nil
	if providerErr != nil || provider.Disabled || !structurallyValid || !matches {
		a.limiter.RecordFailure(providerSlug, clientIP, now)
		return ErrSCIMRejected
	}
	return nil
}

func (a *SCIMAuthenticator) wired() bool {
	return a != nil &&
		a.eventStore != nil &&
		a.limiter != nil &&
		a.resolver != nil &&
		a.compare != nil &&
		len(a.dummyHash) > 0 &&
		a.now != nil
}

func peerAddress(remoteAddress string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddress))
	if err != nil {
		host = strings.TrimSpace(remoteAddress)
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, errors.New("auth: SCIM peer address is invalid")
	}
	return address.Unmap(), nil
}

func parseSCIMAuthorization(authorization string) (string, bool) {
	authorization = strings.TrimSpace(authorization)
	if len(authorization) > maxSCIMAuthorizationHeaderLen {
		return "", false
	}
	scheme, bearer, found := strings.Cut(authorization, " ")
	bearer = strings.TrimSpace(bearer)
	return bearer, found &&
		scheme == "Bearer" &&
		strings.HasPrefix(bearer, scimBearerPrefix) &&
		len(bearer) == len(scimBearerPrefix)+base64.RawURLEncoding.EncodedLen(scimBearerBytes)
}

func validSCIMProviderSlug(value string) bool {
	if len(value) == 0 || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range []byte(value[1:]) {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '-' {
			continue
		}
		return false
	}
	return true
}
