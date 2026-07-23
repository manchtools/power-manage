package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/manchtools/power-manage/sdk/ulidx"
	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	patPrefix                   = "pm_pat_"
	patSecretBytes              = 32
	maxPATScopes                = 64
	maxPATScopeBytes            = 128
	minimumPATRejectionDuration = 25 * time.Millisecond
)

var (
	// ErrPATInvalid identifies invalid PAT mint or revocation input.
	ErrPATInvalid = errors.New("personal access token input is invalid")
	// ErrPATRejected is the static failure for every invalid presented PAT.
	ErrPATRejected = errors.New("personal access token rejected")
	// ErrPATUnavailable identifies a PAT operation that could not reach a
	// durable conclusion.
	ErrPATUnavailable = errors.New("personal access token service unavailable")
)

// PATCredential is returned once when a personal access token is minted.
type PATCredential struct {
	TokenID   string
	Secret    string
	Scopes    []string
	ExpiresAt time.Time
}

// PATPrincipal is the authenticated identity and scope set carried by one PAT.
type PATPrincipal struct {
	Subject       string
	TokenID       string
	Scopes        []string
	AuditIdentity string
}

// PATService owns personal access token minting, verification, and revocation.
type PATService struct {
	eventStore *store.Store
	random     io.Reader
	randomMu   sync.Mutex
	now        func() time.Time
}

// NewPATService validates the dependencies required for durable PAT handling.
func NewPATService(
	eventStore *store.Store,
	random io.Reader,
	now func() time.Time,
) (*PATService, error) {
	switch {
	case eventStore == nil:
		return nil, errors.New("auth: PAT event store is not wired")
	case random == nil:
		return nil, errors.New("auth: PAT entropy source is not wired")
	case now == nil:
		return nil, errors.New("auth: PAT clock is not wired")
	default:
		return &PATService{eventStore: eventStore, random: random, now: now}, nil
	}
}

// Mint returns a new PAT secret once and persists only its SHA-256 digest.
func (s *PATService) Mint(
	ctx context.Context,
	subject string,
	scopes []string,
	expiresAt time.Time,
) (PATCredential, error) {
	if !s.wired() || ctx == nil {
		return PATCredential{}, ErrPATUnavailable
	}
	subject = strings.TrimSpace(subject)
	canonicalScopes, err := canonicalPATScopes(scopes)
	if err != nil || !validPATSubject(subject) {
		return PATCredential{}, ErrPATInvalid
	}
	now := s.now()
	if !validTime(now) || !validTime(expiresAt) || !expiresAt.After(now) {
		return PATCredential{}, ErrPATInvalid
	}
	expiresAt = expiresAt.UTC()

	tokenID, secret, err := s.newCredential(now)
	if err != nil {
		return PATCredential{}, fmt.Errorf("%w: mint credential", ErrPATUnavailable)
	}
	tokenHash := sha256.Sum256([]byte(secret))
	event, err := store.PersonalAccessTokenMintedEvent(
		tokenID,
		subject,
		canonicalScopes,
		tokenHash,
		expiresAt,
	)
	if err != nil {
		return PATCredential{}, fmt.Errorf("%w: create mint event", ErrPATUnavailable)
	}
	if err := s.eventStore.AppendEventWithVersion(ctx, event, 0); err != nil {
		return PATCredential{}, fmt.Errorf("%w: persist mint", ErrPATUnavailable)
	}
	return PATCredential{
		TokenID:   tokenID,
		Secret:    secret,
		Scopes:    slices.Clone(canonicalScopes),
		ExpiresAt: expiresAt,
	}, nil
}

// Authenticate verifies one presented PAT without exposing why it was rejected.
func (s *PATService) Authenticate(
	ctx context.Context,
	presented string,
) (PATPrincipal, error) {
	startedAt := time.Now()
	if !s.wired() || ctx == nil {
		return PATPrincipal{}, ErrPATUnavailable
	}
	presented = strings.TrimSpace(presented)
	if !validPATSecret(presented) {
		return PATPrincipal{}, rejectPAT(ctx, startedAt)
	}
	tokenHash := sha256.Sum256([]byte(presented))
	state, stateErr := s.eventStore.PersonalAccessTokenByHash(ctx, tokenHash)
	if stateErr != nil && !store.IsNotFound(stateErr) {
		return PATPrincipal{}, fmt.Errorf("%w: read token", ErrPATUnavailable)
	}
	now := s.now()
	if stateErr != nil ||
		state.Revoked ||
		!validTime(now) ||
		!now.Before(state.ExpiresAt) {
		return PATPrincipal{}, rejectPAT(ctx, startedAt)
	}
	return PATPrincipal{
		Subject:       state.Subject,
		TokenID:       state.TokenID,
		Scopes:        slices.Clone(state.Scopes),
		AuditIdentity: "pat:" + state.TokenID,
	}, nil
}

// Revoke durably invalidates one PAT. Repeated and concurrent revocations are
// idempotent and append at most one revocation event.
func (s *PATService) Revoke(ctx context.Context, tokenID string) error {
	if !s.wired() || ctx == nil {
		return ErrPATUnavailable
	}
	tokenID = strings.TrimSpace(tokenID)
	if err := validate.ULIDPathID(tokenID); err != nil {
		return ErrPATInvalid
	}
	state, err := s.eventStore.PersonalAccessTokenByID(ctx, tokenID)
	if err != nil {
		if store.IsNotFound(err) {
			return ErrPATInvalid
		}
		return fmt.Errorf("%w: read token", ErrPATUnavailable)
	}
	if state.Revoked {
		return nil
	}
	event, err := store.PersonalAccessTokenRevokedEvent(state.TokenID)
	if err != nil {
		return fmt.Errorf("%w: create revocation", ErrPATUnavailable)
	}
	err = s.eventStore.AppendEventWithVersion(ctx, event, state.ProjectionVersion)
	if err == nil {
		return nil
	}
	if !store.IsVersionConflict(err) {
		return fmt.Errorf("%w: persist revocation", ErrPATUnavailable)
	}
	// Revocation is the only transition after mint. An exact version
	// conflict therefore proves another revocation committed first; confirm
	// that durable state instead of adding a retry loop with no other valid
	// transition to pursue.
	state, err = s.eventStore.PersonalAccessTokenByID(ctx, state.TokenID)
	if err != nil {
		return fmt.Errorf("%w: confirm revocation", ErrPATUnavailable)
	}
	if state.Revoked {
		return nil
	}
	return fmt.Errorf("%w: PAT revocation contention", ErrPATUnavailable)
}

func (s *PATService) newCredential(now time.Time) (string, string, error) {
	s.randomMu.Lock()
	defer s.randomMu.Unlock()
	tokenID, err := ulidx.NewWithReader(now, s.random)
	if err != nil {
		return "", "", err
	}
	raw := make([]byte, patSecretBytes)
	if _, err := io.ReadFull(s.random, raw); err != nil {
		return "", "", fmt.Errorf("read PAT entropy: %w", err)
	}
	return tokenID, patPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func (s *PATService) wired() bool {
	return s != nil && s.eventStore != nil && s.random != nil && s.now != nil
}

func validPATSubject(subject string) bool {
	return validSubject(subject) && !strings.ContainsRune(subject, '\x00')
}

func canonicalPATScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 || len(scopes) > maxPATScopes {
		return nil, ErrPATInvalid
	}
	canonical := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if !validPATScope(scope) {
			return nil, ErrPATInvalid
		}
		canonical = append(canonical, scope)
	}
	slices.Sort(canonical)
	canonical = slices.Compact(canonical)
	if len(canonical) == 0 {
		return nil, ErrPATInvalid
	}
	return canonical, nil
}

func validPATScope(scope string) bool {
	if len(scope) == 0 || len(scope) > maxPATScopeBytes ||
		scope[0] < 'a' || scope[0] > 'z' {
		return false
	}
	for _, character := range []byte(scope[1:]) {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validPATSecret(secret string) bool {
	if len(secret) != len(patPrefix)+base64.RawURLEncoding.EncodedLen(patSecretBytes) ||
		!strings.HasPrefix(secret, patPrefix) {
		return false
	}
	encoded := strings.TrimPrefix(secret, patPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil &&
		len(raw) == patSecretBytes &&
		base64.RawURLEncoding.EncodeToString(raw) == encoded
}

func rejectPAT(ctx context.Context, startedAt time.Time) error {
	deadline := startedAt.Add(minimumPATRejectionDuration)
	if delay := time.Until(deadline); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: rejection wait interrupted", ErrPATUnavailable)
		case <-timer.C:
		}
	}
	return ErrPATRejected
}
