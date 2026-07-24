package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/manchtools/power-manage/sdk/ulidx"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	minimumRefreshRejectionDuration = 25 * time.Millisecond
	refreshRevocationAttempts       = 8
	refreshRevocationBaseBackoff    = 5 * time.Millisecond
)

var (
	// ErrRefreshRejected is the static failure for every invalid refresh token.
	ErrRefreshRejected = errors.New("refresh token rejected")
	// ErrRefreshUnavailable identifies a refresh operation that could not reach
	// a durable conclusion.
	ErrRefreshUnavailable = errors.New("refresh service unavailable")
)

// SessionTokens contains the short-lived access token and rotating refresh
// token returned at a session boundary.
type SessionTokens struct {
	AccessToken  string
	RefreshToken string
}

// RefreshService owns durable refresh-token family creation and rotation.
type RefreshService struct {
	eventStore *store.Store
	signer     *Signer
	verifier   *Verifier
	random     io.Reader
	randomMu   sync.Mutex
	now        func() time.Time
}

// ValidateWiring rejects nil and partially initialized refresh services.
func (s *RefreshService) ValidateWiring() error {
	if !s.wired() {
		return ErrRefreshUnavailable
	}
	return nil
}

// NewRefreshService validates the dependencies required for durable rotation.
func NewRefreshService(
	eventStore *store.Store,
	signer *Signer,
	verifier *Verifier,
	random io.Reader,
	now func() time.Time,
) (*RefreshService, error) {
	switch {
	case eventStore == nil:
		return nil, errors.New("auth: refresh event store is not wired")
	case signer == nil || signer.key == nil || signer.now == nil:
		return nil, errors.New("auth: refresh signer is not wired")
	case verifier == nil || verifier.key == nil || verifier.now == nil:
		return nil, errors.New("auth: refresh verifier is not wired")
	case random == nil:
		return nil, errors.New("auth: refresh entropy source is not wired")
	case now == nil:
		return nil, errors.New("auth: refresh clock is not wired")
	default:
		return &RefreshService{
			eventStore: eventStore,
			signer:     signer,
			verifier:   verifier,
			random:     random,
			now:        now,
		}, nil
	}
}

// StartSession mints a new token pair and persists only the refresh digest.
func (s *RefreshService) StartSession(ctx context.Context, subject string) (SessionTokens, error) {
	if !s.wired() || ctx == nil || !validSubject(subject) {
		return SessionTokens{}, ErrRefreshUnavailable
	}
	now := s.now()
	if !validTime(now) {
		return SessionTokens{}, ErrRefreshUnavailable
	}
	user, err := s.eventStore.UserByID(ctx, subject)
	if err != nil {
		if store.IsNotFound(err) {
			return SessionTokens{}, ErrRefreshRejected
		}
		return SessionTokens{}, fmt.Errorf("%w: read session user", ErrRefreshUnavailable)
	}
	if user.Disabled {
		return SessionTokens{}, ErrRefreshRejected
	}
	familyID, err := s.newFamilyID(now)
	if err != nil {
		return SessionTokens{}, fmt.Errorf("%w: mint family ID", ErrRefreshUnavailable)
	}
	tokens, err := s.mintTokens(subject, user.SessionVersion)
	if err != nil {
		return SessionTokens{}, fmt.Errorf("%w: mint session tokens", ErrRefreshUnavailable)
	}
	refreshHash := sha256.Sum256([]byte(tokens.RefreshToken))
	expiresAt := time.Unix(now.Add(refreshTokenLifetime).Unix(), 0).UTC()
	event, err := store.RefreshFamilyStartedEvent(familyID, subject, refreshHash, expiresAt)
	if err != nil {
		return SessionTokens{}, fmt.Errorf("%w: create family start", ErrRefreshUnavailable)
	}
	if err := s.eventStore.AppendEventWithVersion(ctx, event, 0); err != nil {
		return SessionTokens{}, fmt.Errorf("%w: persist family start", ErrRefreshUnavailable)
	}
	return tokens, nil
}

// Rotate consumes one active refresh token. Reuse of a superseded token
// revokes its complete family before returning the static rejection.
func (s *RefreshService) Rotate(ctx context.Context, presented string) (SessionTokens, error) {
	startedAt := time.Now()
	if !s.wired() || ctx == nil {
		return SessionTokens{}, ErrRefreshUnavailable
	}

	presented = strings.TrimSpace(presented)
	presentedHash := sha256.Sum256([]byte(presented))
	claims, verifyErr := s.verifier.VerifyRefresh(presented)
	state, stateErr := s.eventStore.RefreshFamilyToken(ctx, presentedHash)
	if stateErr != nil && !store.IsNotFound(stateErr) {
		return SessionTokens{}, fmt.Errorf("%w: read refresh family", ErrRefreshUnavailable)
	}
	var (
		user    store.User
		userErr error
	)
	if verifyErr == nil && stateErr == nil && claims.Subject == state.Subject {
		user, userErr = s.eventStore.UserByID(ctx, state.Subject)
		if userErr != nil && !store.IsNotFound(userErr) {
			return SessionTokens{}, fmt.Errorf("%w: read refresh session user", ErrRefreshUnavailable)
		}
	}
	if verifyErr != nil || stateErr != nil || userErr != nil ||
		claims.Subject != state.Subject ||
		claims.SessionVersion != user.SessionVersion ||
		user.Disabled ||
		state.Revoked ||
		!s.activeAt(state, presentedHash) {
		if stateErr == nil && state.Superseded && !state.Revoked {
			if err := s.revokeReplayed(ctx, presentedHash); err != nil {
				return SessionTokens{}, err
			}
		}
		return SessionTokens{}, rejectRefresh(ctx, startedAt)
	}

	tokens, err := s.mintTokens(state.Subject, user.SessionVersion)
	if err != nil {
		return SessionTokens{}, fmt.Errorf("%w: mint rotated session tokens", ErrRefreshUnavailable)
	}
	nextHash := sha256.Sum256([]byte(tokens.RefreshToken))
	expiresAt := time.Unix(s.now().Add(refreshTokenLifetime).Unix(), 0).UTC()
	event, err := store.RefreshTokenRotatedEvent(
		state.FamilyID,
		presentedHash,
		nextHash,
		expiresAt,
	)
	if err != nil {
		return SessionTokens{}, fmt.Errorf("%w: create refresh rotation", ErrRefreshUnavailable)
	}
	err = s.eventStore.AppendEventWithVersion(ctx, event, state.ProjectionVersion)
	if err == nil {
		return tokens, nil
	}
	if !store.IsVersionConflict(err) {
		return SessionTokens{}, fmt.Errorf("%w: persist refresh rotation", ErrRefreshUnavailable)
	}
	if err := s.revokeReplayed(ctx, presentedHash); err != nil {
		return SessionTokens{}, err
	}
	return SessionTokens{}, rejectRefresh(ctx, startedAt)
}

func (s *RefreshService) newFamilyID(now time.Time) (string, error) {
	s.randomMu.Lock()
	defer s.randomMu.Unlock()
	return ulidx.NewWithReader(now, s.random)
}

func (s *RefreshService) mintTokens(subject string, sessionVersion int64) (SessionTokens, error) {
	accessToken, err := s.signer.MintAccess(subject, sessionVersion)
	if err != nil {
		return SessionTokens{}, err
	}
	refreshToken, err := s.signer.MintRefresh(subject, sessionVersion)
	if err != nil {
		return SessionTokens{}, err
	}
	return SessionTokens{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (s *RefreshService) activeAt(
	state store.RefreshFamilyToken,
	presentedHash [sha256.Size]byte,
) bool {
	now := s.now()
	return !state.Superseded &&
		validTime(now) &&
		now.Before(state.ExpiresAt) &&
		subtle.ConstantTimeCompare(presentedHash[:], state.ActiveHash[:]) == 1
}

func (s *RefreshService) revokeReplayed(
	ctx context.Context,
	replayedHash [sha256.Size]byte,
) error {
	backoff := refreshRevocationBaseBackoff
	for attempt := range refreshRevocationAttempts {
		state, err := s.eventStore.RefreshFamilyToken(ctx, replayedHash)
		if err != nil {
			if store.IsNotFound(err) {
				return nil
			}
			return fmt.Errorf("%w: reread replayed refresh token", ErrRefreshUnavailable)
		}
		if state.Revoked || !state.Superseded {
			return nil
		}
		event, err := store.RefreshFamilyRevokedEvent(state.FamilyID, replayedHash)
		if err != nil {
			return fmt.Errorf("%w: create refresh-family revocation", ErrRefreshUnavailable)
		}
		err = s.eventStore.AppendEventWithVersion(ctx, event, state.ProjectionVersion)
		switch {
		case err == nil:
			return nil
		case store.IsVersionConflict(err):
			if attempt < refreshRevocationAttempts-1 {
				if err := waitRefreshRevocationBackoff(ctx, backoff); err != nil {
					return err
				}
				backoff *= 2
			}
			continue
		default:
			return fmt.Errorf("%w: persist refresh-family revocation", ErrRefreshUnavailable)
		}
	}
	return fmt.Errorf("%w: refresh-family revocation contention", ErrRefreshUnavailable)
}

func waitRefreshRevocationBackoff(ctx context.Context, delay time.Duration) error {
	if ctx == nil || delay <= 0 {
		return fmt.Errorf("%w: invalid revocation backoff", ErrRefreshUnavailable)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("%w: revocation backoff interrupted", ErrRefreshUnavailable)
	case <-timer.C:
		return nil
	}
}

func (s *RefreshService) wired() bool {
	return s != nil &&
		s.eventStore != nil &&
		s.signer != nil &&
		s.verifier != nil &&
		s.random != nil &&
		s.now != nil
}

func rejectRefresh(ctx context.Context, startedAt time.Time) error {
	deadline := startedAt.Add(minimumRefreshRejectionDuration)
	if delay := time.Until(deadline); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: rejection wait interrupted", ErrRefreshUnavailable)
		case <-timer.C:
		}
	}
	return ErrRefreshRejected
}
