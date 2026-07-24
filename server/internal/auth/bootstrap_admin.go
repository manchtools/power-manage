package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/manchtools/power-manage/sdk/ulidx"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	bootstrapLoginLifetime = 10 * time.Minute
	bootstrapSecretBytes   = 32
	maxBootstrapTokenBytes = 256
)

var (
	// ErrBootstrapRejected is the static result for every invalid, expired,
	// spent, or unknown break-glass login.
	ErrBootstrapRejected = errors.New("bootstrap login rejected")
	// ErrBootstrapUnavailable identifies a break-glass operation that could
	// not reach a durable conclusion.
	ErrBootstrapUnavailable = errors.New("bootstrap login unavailable")
)

// BootstrapAdminMinter creates first-boot identity facts and hash-only login
// URLs from the control host.
type BootstrapAdminMinter struct {
	eventStore *store.Store
	random     io.Reader
	randomMu   sync.Mutex
	now        func() time.Time
}

// BootstrapAdminConsumer redeems one-time URLs into ordinary sessions.
type BootstrapAdminConsumer struct {
	eventStore *store.Store
	refresh    *RefreshService
	now        func() time.Time
}

// NewBootstrapAdminMinter validates host-side bootstrap dependencies.
func NewBootstrapAdminMinter(
	eventStore *store.Store,
	random io.Reader,
	now func() time.Time,
) (*BootstrapAdminMinter, error) {
	switch {
	case eventStore == nil:
		return nil, errors.New("auth: bootstrap event store is not wired")
	case random == nil:
		return nil, errors.New("auth: bootstrap entropy source is not wired")
	case now == nil:
		return nil, errors.New("auth: bootstrap clock is not wired")
	default:
		return &BootstrapAdminMinter{eventStore: eventStore, random: random, now: now}, nil
	}
}

// NewBootstrapAdminConsumer validates one-time consume and session wiring.
func NewBootstrapAdminConsumer(
	eventStore *store.Store,
	refresh *RefreshService,
	now func() time.Time,
) (*BootstrapAdminConsumer, error) {
	switch {
	case eventStore == nil:
		return nil, errors.New("auth: bootstrap event store is not wired")
	case refresh == nil || refresh.ValidateWiring() != nil:
		return nil, errors.New("auth: bootstrap refresh service is not wired")
	case now == nil:
		return nil, errors.New("auth: bootstrap clock is not wired")
	default:
		return &BootstrapAdminConsumer{
			eventStore: eventStore,
			refresh:    refresh,
			now:        now,
		}, nil
	}
}

// Mint ensures the first-boot user/grant facts exist, then returns one
// fragment-carried login secret after its digest is durable.
func (m *BootstrapAdminMinter) Mint(
	ctx context.Context,
	email string,
	loginBaseURL string,
) (string, error) {
	if !m.wired() || ctx == nil {
		return "", ErrBootstrapUnavailable
	}
	email, err := store.CanonicalUserEmail(email)
	if err != nil {
		return "", ErrBootstrapRejected
	}
	baseURL, err := canonicalBootstrapLoginURL(loginBaseURL)
	if err != nil {
		return "", ErrBootstrapRejected
	}
	now := m.now()
	if !validTime(now) {
		return "", ErrBootstrapUnavailable
	}
	user, err := m.eventStore.UserByEmail(ctx, email)
	if err != nil {
		if !store.IsNotFound(err) {
			return "", fmt.Errorf("%w: read bootstrap user", ErrBootstrapUnavailable)
		}
		user, err = m.createFirstBootUser(ctx, email, now)
		if err != nil {
			return "", err
		}
	}
	loginID, rawToken, err := m.newLoginMaterial(now)
	if err != nil {
		return "", fmt.Errorf("%w: mint login material", ErrBootstrapUnavailable)
	}
	tokenHash := sha256.Sum256([]byte(rawToken))
	expiresAt := time.Unix(now.Add(bootstrapLoginLifetime).Unix(), 0).UTC()
	minted, err := store.BootstrapLoginMintedEvent(
		loginID,
		user.UserID,
		tokenHash,
		expiresAt,
	)
	if err != nil {
		return "", fmt.Errorf("%w: create login event", ErrBootstrapUnavailable)
	}
	if err := m.eventStore.AppendEventWithVersion(ctx, minted, 0); err != nil {
		return "", fmt.Errorf("%w: persist login event", ErrBootstrapUnavailable)
	}
	baseURL.Fragment = "bootstrap_token=" + rawToken
	return baseURL.String(), nil
}

// Consume atomically spends one login and starts a normal refresh family.
func (c *BootstrapAdminConsumer) Consume(
	ctx context.Context,
	presented string,
) (SessionTokens, error) {
	if !c.wired() || ctx == nil {
		return SessionTokens{}, ErrBootstrapUnavailable
	}
	rawToken, ok := canonicalBootstrapToken(presented)
	if !ok {
		return SessionTokens{}, ErrBootstrapRejected
	}
	tokenHash := sha256.Sum256([]byte(rawToken))
	state, err := c.eventStore.BootstrapLoginByHash(ctx, tokenHash)
	if err != nil {
		if store.IsNotFound(err) {
			return SessionTokens{}, ErrBootstrapRejected
		}
		return SessionTokens{}, fmt.Errorf("%w: read login state", ErrBootstrapUnavailable)
	}
	now := c.now()
	if !validTime(now) {
		return SessionTokens{}, ErrBootstrapUnavailable
	}
	if state.Consumed || !now.Before(state.ExpiresAt) {
		return SessionTokens{}, ErrBootstrapRejected
	}
	consumed, err := store.BootstrapLoginConsumedEvent(state.LoginID)
	if err != nil {
		return SessionTokens{}, fmt.Errorf("%w: create consume event", ErrBootstrapUnavailable)
	}
	// Spend before session creation. Reversing this order lets the losing side
	// of a consume race persist an unreachable refresh family before CAS fails.
	err = c.eventStore.AppendEventWithVersion(
		ctx,
		consumed,
		state.ProjectionVersion,
	)
	if err != nil {
		if store.IsVersionConflict(err) {
			return SessionTokens{}, ErrBootstrapRejected
		}
		return SessionTokens{}, fmt.Errorf("%w: persist consume event", ErrBootstrapUnavailable)
	}
	tokens, err := c.refresh.StartSession(ctx, state.UserID)
	if err != nil {
		return SessionTokens{}, fmt.Errorf("%w: start session", ErrBootstrapUnavailable)
	}
	return tokens, nil
}

func (m *BootstrapAdminMinter) createFirstBootUser(
	ctx context.Context,
	email string,
	now time.Time,
) (store.User, error) {
	userID, err := m.newULID(now)
	if err != nil {
		return store.User{}, fmt.Errorf("%w: mint user ID", ErrBootstrapUnavailable)
	}
	created, err := store.UserCreatedEvent(userID, email)
	if err != nil {
		return store.User{}, fmt.Errorf("%w: create user event", ErrBootstrapUnavailable)
	}
	granted, err := store.BootstrapAdminRoleGrantedEvent(userID)
	if err != nil {
		return store.User{}, fmt.Errorf("%w: create admin grant event", ErrBootstrapUnavailable)
	}
	if err := m.eventStore.AppendEvents(ctx, []store.Event{created, granted}); err != nil {
		return store.User{}, fmt.Errorf("%w: persist user and admin grant", ErrBootstrapUnavailable)
	}
	return store.User{
		UserID:            userID,
		Email:             email,
		SessionVersion:    1,
		ProjectionVersion: 2,
	}, nil
}

func (m *BootstrapAdminMinter) newLoginMaterial(now time.Time) (string, string, error) {
	m.randomMu.Lock()
	defer m.randomMu.Unlock()
	loginID, err := ulidx.NewWithReader(now, m.random)
	if err != nil {
		return "", "", err
	}
	secret := make([]byte, bootstrapSecretBytes)
	if _, err := io.ReadFull(m.random, secret); err != nil {
		return "", "", err
	}
	return loginID, base64.RawURLEncoding.EncodeToString(secret), nil
}

func (m *BootstrapAdminMinter) newULID(now time.Time) (string, error) {
	m.randomMu.Lock()
	defer m.randomMu.Unlock()
	return ulidx.NewWithReader(now, m.random)
}

func canonicalBootstrapLoginURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil ||
		parsed.Host == "" ||
		parsed.User != nil ||
		parsed.RawQuery != "" ||
		parsed.Fragment != "" {
		return nil, ErrBootstrapRejected
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		host := parsed.Hostname()
		ip := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
			return nil, ErrBootstrapRejected
		}
	default:
		return nil, ErrBootstrapRejected
	}
	copy := *parsed
	return &copy, nil
}

func canonicalBootstrapToken(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > maxBootstrapTokenBytes {
		return "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil ||
		len(decoded) != bootstrapSecretBytes ||
		base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return "", false
	}
	return raw, true
}

func (m *BootstrapAdminMinter) wired() bool {
	return m != nil && m.eventStore != nil && m.random != nil && m.now != nil
}

func (c *BootstrapAdminConsumer) wired() bool {
	return c != nil &&
		c.eventStore != nil &&
		c.refresh != nil &&
		c.refresh.ValidateWiring() == nil &&
		c.now != nil
}
