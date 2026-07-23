package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/manchtools/power-manage/server/internal/store/generated"
)

// ErrOIDCLoginStateExpired identifies an atomically consumed state that is no
// longer within its login window.
var ErrOIDCLoginStateExpired = errors.New("store: OIDC login state expired")

// OIDCLoginState is the server-held half of one OIDC authorization flow.
type OIDCLoginState struct {
	ProviderSlug string
	RedirectURI  string
	Nonce        string
	CodeVerifier string
	ExpiresAt    time.Time
}

// StoreOIDCLoginState persists one digest-keyed authorization flow.
func (s *Store) StoreOIDCLoginState(
	ctx context.Context,
	stateHash [sha256.Size]byte,
	state OIDCLoginState,
) error {
	if s == nil || s.pool == nil {
		return errors.New("store: nil store")
	}
	if ctx == nil {
		return errors.New("store: nil OIDC login-state context")
	}
	if err := validateOIDCLoginState(state); err != nil {
		return err
	}
	affected, err := generated.New(s.pool).InsertOIDCLoginState(
		ctx,
		generated.InsertOIDCLoginStateParams{
			StateHash:    stateHash[:],
			ProviderSlug: state.ProviderSlug,
			RedirectUri:  state.RedirectURI,
			Nonce:        state.Nonce,
			CodeVerifier: state.CodeVerifier,
			ExpiresAt:    state.ExpiresAt.UTC(),
		},
	)
	if err != nil {
		return fmt.Errorf("store: OIDC login-state insert: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: OIDC login-state insert affected %d rows; want one", affected)
	}
	return nil
}

// ConsumeOIDCLoginState atomically deletes and returns one authorization flow.
func (s *Store) ConsumeOIDCLoginState(
	ctx context.Context,
	stateHash [sha256.Size]byte,
	now time.Time,
) (OIDCLoginState, error) {
	if s == nil || s.pool == nil {
		return OIDCLoginState{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return OIDCLoginState{}, errors.New("store: nil OIDC login-state context")
	}
	if now.IsZero() || now.Unix() <= 0 {
		return OIDCLoginState{}, errors.New("store: OIDC login-state clock is invalid")
	}
	row, err := generated.New(s.pool).ConsumeOIDCLoginState(ctx, stateHash[:])
	if err != nil {
		return OIDCLoginState{}, fmt.Errorf("store: OIDC login-state consume: %w", err)
	}
	state := OIDCLoginState{
		ProviderSlug: row.ProviderSlug,
		RedirectURI:  row.RedirectUri,
		Nonce:        row.Nonce,
		CodeVerifier: row.CodeVerifier,
		ExpiresAt:    row.ExpiresAt.UTC(),
	}
	if err := validateOIDCLoginState(state); err != nil {
		return OIDCLoginState{}, fmt.Errorf("store: OIDC login-state consumed value is invalid: %w", err)
	}
	if !now.Before(state.ExpiresAt) {
		return OIDCLoginState{}, ErrOIDCLoginStateExpired
	}
	return state, nil
}

// DeleteExpiredOIDCLoginStates bounds abandoned authorization-flow storage.
func (s *Store) DeleteExpiredOIDCLoginStates(ctx context.Context, now time.Time) error {
	if s == nil || s.pool == nil {
		return errors.New("store: nil store")
	}
	if ctx == nil || now.IsZero() || now.Unix() <= 0 {
		return errors.New("store: OIDC login-state cleanup request is invalid")
	}
	if _, err := generated.New(s.pool).DeleteExpiredOIDCLoginStates(ctx, now.UTC()); err != nil {
		return fmt.Errorf("store: OIDC login-state delete expired rows: %w", err)
	}
	return nil
}

func validateOIDCLoginState(state OIDCLoginState) error {
	if !validProviderSlug(state.ProviderSlug) {
		return errors.New("store: OIDC provider slug is invalid")
	}
	if !validBoundedText(state.RedirectURI, 2048) {
		return errors.New("store: OIDC redirect URI is invalid")
	}
	if !validBoundedText(state.Nonce, 256) {
		return errors.New("store: OIDC nonce is invalid")
	}
	if !validCodeVerifier(state.CodeVerifier) {
		return errors.New("store: OIDC code verifier is invalid")
	}
	if state.ExpiresAt.IsZero() || state.ExpiresAt.Unix() <= 0 {
		return errors.New("store: OIDC login-state expiry is invalid")
	}
	return nil
}

func validProviderSlug(value string) bool {
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

func validBoundedText(value string, maximum int) bool {
	return len(value) > 0 &&
		len(value) <= maximum &&
		utf8.ValidString(value) &&
		!strings.ContainsRune(value, '\x00')
}

func validCodeVerifier(value string) bool {
	if len(value) < 43 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '.' ||
			character == '_' || character == '~' {
			continue
		}
		return false
	}
	return true
}
