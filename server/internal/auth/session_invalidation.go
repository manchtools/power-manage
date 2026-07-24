package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/manchtools/power-manage/server/internal/store"
)

var (
	// ErrSessionAuthenticatorNotWired classifies missing access-auth dependencies.
	ErrSessionAuthenticatorNotWired = errors.New("auth: session authenticator is not wired")
	// ErrSessionUnavailable identifies access authentication without a durable conclusion.
	ErrSessionUnavailable = errors.New("auth: session authentication unavailable")
)

// SessionAuthenticator binds a valid access JWT to current durable user state.
type SessionAuthenticator struct {
	eventStore *store.Store
	verifier   *Verifier
}

// NewSessionAuthenticator validates the store-backed access-token boundary.
func NewSessionAuthenticator(
	eventStore *store.Store,
	verifier *Verifier,
) (*SessionAuthenticator, error) {
	if eventStore == nil || verifier == nil || verifier.key == nil || verifier.now == nil {
		return nil, ErrSessionAuthenticatorNotWired
	}
	return &SessionAuthenticator{eventStore: eventStore, verifier: verifier}, nil
}

// AuthenticateAccess rejects a token whose user is absent, disabled, or has
// advanced past the token's session version.
func (a *SessionAuthenticator) AuthenticateAccess(
	ctx context.Context,
	token string,
) (Claims, error) {
	if a == nil || a.eventStore == nil || a.verifier == nil || ctx == nil {
		return Claims{}, ErrSessionUnavailable
	}
	claims, err := a.verifier.VerifyAccess(token)
	if err != nil {
		return Claims{}, err
	}
	user, err := a.eventStore.UserByID(ctx, claims.Subject)
	if err != nil {
		if store.IsNotFound(err) {
			return Claims{}, ErrInvalid
		}
		return Claims{}, fmt.Errorf("%w: read user session", ErrSessionUnavailable)
	}
	if user.Disabled || user.SessionVersion != claims.SessionVersion {
		return Claims{}, ErrInvalid
	}
	return claims, nil
}
