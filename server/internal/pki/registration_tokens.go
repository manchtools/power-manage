package pki

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"slices"
	"time"

	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	registrationTokenSecretBytes      = 32
	registrationTokenEntropyBytes     = 10
	registrationTokenMaterialBytes    = registrationTokenEntropyBytes + registrationTokenSecretBytes
	registrationTokenEncodedSecretLen = 43
	registrationTokenWireLen          = 26 + 1 + registrationTokenEncodedSecretLen
	registrationAttemptsPerMinute     = 5
	maxRegistrationCASAttempts        = 1024
	initialRegistrationCASBackoff     = time.Millisecond
	maximumRegistrationCASBackoff     = 10 * time.Millisecond
	minimumTokenRejectionDuration     = 25 * time.Millisecond
	maxULIDTimestamp                  = 1<<48 - 1
	dummyRegistrationTokenID          = "00000000000000000000000000"
	ulidAlphabet                      = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

var (
	// ErrInvalidRegistrationToken is the sole caller-visible token-state error.
	ErrInvalidRegistrationToken = errors.New("registration token rejected")
	dummyRegistrationTokenHash  = sha256.Sum256([]byte("power-manage:registration-token:dummy:v1"))
)

// RegistrationTokenPurpose is the enrollment class authorized by a token.
type RegistrationTokenPurpose = store.RegistrationTokenPurpose

const (
	RegistrationTokenPurposeAgent   = store.RegistrationTokenPurposeAgent
	RegistrationTokenPurposeGateway = store.RegistrationTokenPurposeGateway
)

// RegistrationTokenOptions are the durable bounds stamped at mint time.
type RegistrationTokenOptions struct {
	Purpose   RegistrationTokenPurpose
	MaxUses   int32
	ExpiresAt time.Time
	Owner     string
	DNSNames  []string
}

// MintedRegistrationToken is returned once; Token is never persisted.
type MintedRegistrationToken struct {
	TokenID string
	Token   string
}

// RegistrationTokenGrant carries admission metadata for the future enroll handler.
type RegistrationTokenGrant struct {
	TokenID  string
	Owner    string
	Purpose  RegistrationTokenPurpose
	DNSNames []string
}

// RegistrationTokens owns hash-only token minting and bounded-use admission.
type RegistrationTokens struct {
	eventStore  *store.Store
	random      io.Reader
	now         func() time.Time
	waitUntil   func(context.Context, time.Time) error
	casAttempts int
}

// NewRegistrationTokens returns the production registration-token service.
func NewRegistrationTokens(eventStore *store.Store) (*RegistrationTokens, error) {
	return newRegistrationTokens(eventStore, cryptorand.Reader, time.Now, waitUntilContext)
}

func newRegistrationTokens(
	eventStore *store.Store,
	random io.Reader,
	now func() time.Time,
	waitUntil func(context.Context, time.Time) error,
) (*RegistrationTokens, error) {
	if eventStore == nil {
		return nil, errors.New("pki: nil registration-token event store")
	}
	if random == nil {
		return nil, errors.New("pki: nil registration-token random source")
	}
	if now == nil {
		return nil, errors.New("pki: nil registration-token clock")
	}
	if waitUntil == nil {
		return nil, errors.New("pki: nil registration-token waiter")
	}
	return &RegistrationTokens{
		eventStore:  eventStore,
		random:      random,
		now:         now,
		waitUntil:   waitUntil,
		casAttempts: maxRegistrationCASAttempts,
	}, nil
}

// Mint creates a 256-bit registration secret and persists only its hash.
func (r *RegistrationTokens) Mint(
	ctx context.Context,
	options RegistrationTokenOptions,
) (MintedRegistrationToken, error) {
	if err := r.validateCall(ctx); err != nil {
		return MintedRegistrationToken{}, err
	}
	now := r.now()
	if !options.ExpiresAt.After(now) {
		return MintedRegistrationToken{}, errors.New("pki: registration-token expiry must be in the future")
	}
	var zeroHash [sha256.Size]byte
	if _, err := registrationTokenMintedEvent(
		dummyRegistrationTokenID,
		zeroHash,
		options,
	); err != nil {
		return MintedRegistrationToken{}, fmt.Errorf("pki: validate registration-token options: %w", err)
	}

	var material [registrationTokenMaterialBytes]byte
	if _, err := io.ReadFull(r.random, material[:]); err != nil {
		return MintedRegistrationToken{}, fmt.Errorf("pki: generate registration token: %w", err)
	}
	tokenID, err := newRegistrationTokenID(now, material[:registrationTokenEntropyBytes])
	if err != nil {
		return MintedRegistrationToken{}, err
	}
	secret := material[registrationTokenEntropyBytes:]
	hash := sha256.Sum256(secret)
	event, err := registrationTokenMintedEvent(
		tokenID,
		hash,
		options,
	)
	if err != nil {
		return MintedRegistrationToken{}, fmt.Errorf("pki: create registration-token mint event: %w", err)
	}
	if err := r.eventStore.AppendEventWithVersion(ctx, event, 0); err != nil {
		return MintedRegistrationToken{}, fmt.Errorf("pki: persist registration-token mint: %w", err)
	}
	return MintedRegistrationToken{
		TokenID: tokenID,
		Token:   tokenID + "." + base64.RawURLEncoding.EncodeToString(secret),
	}, nil
}

// Consume authenticates and claims one use through an explicit fresh CAS.
func (r *RegistrationTokens) Consume(
	ctx context.Context,
	rawToken string,
	expectedPurpose RegistrationTokenPurpose,
) (RegistrationTokenGrant, error) {
	if err := r.validateCall(ctx); err != nil {
		return RegistrationTokenGrant{}, err
	}
	if expectedPurpose != RegistrationTokenPurposeAgent && expectedPurpose != RegistrationTokenPurposeGateway {
		return RegistrationTokenGrant{}, errors.New("pki: invalid expected registration-token purpose")
	}
	startedAt := r.now()

	tokenID, secret, wellFormed := parseRegistrationToken(rawToken)
	candidateHash := sha256.Sum256(secret[:])
	for attempt := range r.casAttempts {
		state, found, err := r.registrationTokenState(ctx, tokenID)
		if err != nil {
			return RegistrationTokenGrant{}, err
		}
		hashMatches := subtle.ConstantTimeCompare(candidateHash[:], state.Hash[:])
		if wellFormed&found&hashMatches != 1 {
			return RegistrationTokenGrant{}, r.reject(ctx, startedAt)
		}
		// Disabled is deliberately first among state checks: the kill switch
		// never depends on expiry or remaining capacity.
		if state.Disabled {
			return RegistrationTokenGrant{}, r.reject(ctx, startedAt)
		}
		if !r.now().Before(state.ExpiresAt) {
			return RegistrationTokenGrant{}, r.reject(ctx, startedAt)
		}
		if state.Uses >= state.MaxUses {
			return RegistrationTokenGrant{}, r.reject(ctx, startedAt)
		}
		if state.Purpose != expectedPurpose {
			return RegistrationTokenGrant{}, r.reject(ctx, startedAt)
		}

		event, err := store.RegistrationTokenConsumedEvent(state.TokenID)
		if err != nil {
			return RegistrationTokenGrant{}, fmt.Errorf("pki: create registration-token consume event: %w", err)
		}
		err = r.eventStore.AppendEventWithVersion(ctx, event, state.ProjectionVersion)
		switch {
		case err == nil:
			return RegistrationTokenGrant{
				TokenID:  state.TokenID,
				Owner:    state.Owner,
				Purpose:  state.Purpose,
				DNSNames: slices.Clone(state.DNSNames),
			}, nil
		case store.IsVersionConflict(err):
			// Another caller progressed. Re-read and re-authorize the new state
			// before submitting another explicit CAS; the stale append is never
			// retried by the store.
			if err := r.waitForCASRetry(ctx, attempt, "consume"); err != nil {
				return RegistrationTokenGrant{}, err
			}
		default:
			return RegistrationTokenGrant{}, fmt.Errorf("pki: persist registration-token consume: %w", err)
		}
	}
	return RegistrationTokenGrant{}, errors.New("pki: registration-token consume exceeded CAS retry limit")
}

func registrationTokenMintedEvent(
	tokenID string,
	hash [sha256.Size]byte,
	options RegistrationTokenOptions,
) (store.Event, error) {
	switch options.Purpose {
	case RegistrationTokenPurposeAgent:
		if len(options.DNSNames) != 0 {
			return store.Event{}, errors.New("pki: agent registration token must not contain DNS names")
		}
		return store.RegistrationTokenMintedEvent(
			tokenID,
			hash,
			options.MaxUses,
			options.ExpiresAt,
			options.Owner,
		)
	case RegistrationTokenPurposeGateway:
		if len(options.DNSNames) == 0 {
			return store.Event{}, errors.New("pki: gateway registration token must contain at least one DNS name")
		}
		return store.GatewayRegistrationTokenMintedEvent(
			tokenID,
			hash,
			options.MaxUses,
			options.ExpiresAt,
			options.Owner,
			options.DNSNames,
		)
	default:
		return store.Event{}, errors.New("pki: registration-token purpose is invalid")
	}
}

// Disable durably and idempotently activates one token's kill switch.
func (r *RegistrationTokens) Disable(ctx context.Context, tokenID string) error {
	if err := r.validateCall(ctx); err != nil {
		return err
	}
	for attempt := range r.casAttempts {
		state, err := r.eventStore.RegistrationToken(ctx, tokenID)
		if err != nil {
			return fmt.Errorf("pki: read registration token for disable: %w", err)
		}
		if state.Disabled {
			return nil
		}
		event, err := store.RegistrationTokenDisabledEvent(state.TokenID)
		if err != nil {
			return fmt.Errorf("pki: create registration-token disable event: %w", err)
		}
		err = r.eventStore.AppendEventWithVersion(ctx, event, state.ProjectionVersion)
		switch {
		case err == nil:
			return nil
		case store.IsVersionConflict(err):
			if err := r.waitForCASRetry(ctx, attempt, "disable"); err != nil {
				return err
			}
		default:
			return fmt.Errorf("pki: persist registration-token disable: %w", err)
		}
	}
	return errors.New("pki: registration-token disable exceeded CAS retry limit")
}

func (r *RegistrationTokens) validateCall(ctx context.Context) error {
	if r == nil || r.eventStore == nil || r.random == nil || r.now == nil || r.waitUntil == nil || r.casAttempts <= 0 {
		return errors.New("pki: registration-token service is not wired")
	}
	if ctx == nil {
		return errors.New("pki: nil context for registration-token operation")
	}
	return nil
}

func (r *RegistrationTokens) waitForCASRetry(ctx context.Context, attempt int, operation string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if attempt+1 >= r.casAttempts {
		return fmt.Errorf("pki: registration-token %s exceeded CAS retry limit", operation)
	}
	deadline := r.now().Add(registrationCASBackoff(attempt))
	if err := r.waitUntil(ctx, deadline); err != nil {
		return err
	}
	return nil
}

func registrationCASBackoff(attempt int) time.Duration {
	ceiling := initialRegistrationCASBackoff
	for range min(attempt, 4) {
		ceiling *= 2
	}
	ceiling = min(ceiling, maximumRegistrationCASBackoff)
	floor := ceiling / 2
	return floor + time.Duration(mathrand.Int64N(int64(ceiling-floor)+1))
}

func (r *RegistrationTokens) registrationTokenState(
	ctx context.Context,
	tokenID string,
) (store.RegistrationToken, int, error) {
	state, err := r.eventStore.RegistrationToken(ctx, tokenID)
	if err == nil {
		return state, 1, nil
	}
	if !store.IsNotFound(err) {
		return store.RegistrationToken{}, 0, fmt.Errorf("pki: read registration token: %w", err)
	}
	return store.RegistrationToken{Hash: dummyRegistrationTokenHash}, 0, nil
}

func (r *RegistrationTokens) reject(ctx context.Context, startedAt time.Time) error {
	if err := r.waitUntil(ctx, startedAt.Add(minimumTokenRejectionDuration)); err != nil {
		return err
	}
	return ErrInvalidRegistrationToken
}

func parseRegistrationToken(rawToken string) (string, [registrationTokenSecretBytes]byte, int) {
	var secret [registrationTokenSecretBytes]byte
	if len(rawToken) != registrationTokenWireLen || rawToken[26] != '.' {
		return dummyRegistrationTokenID, secret, 0
	}
	tokenID := rawToken[:26]
	if !identity.IsCanonicalULID(tokenID) {
		return dummyRegistrationTokenID, secret, 0
	}
	encoded := rawToken[27:]
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != registrationTokenSecretBytes {
		return dummyRegistrationTokenID, secret, 0
	}
	copy(secret[:], decoded)
	return tokenID, secret, 1
}

func newRegistrationTokenID(now time.Time, entropy []byte) (string, error) {
	if len(entropy) != registrationTokenEntropyBytes {
		return "", errors.New("pki: registration-token ULID entropy has the wrong length")
	}
	milliseconds := now.UnixMilli()
	if milliseconds < 0 || milliseconds > maxULIDTimestamp {
		return "", errors.New("pki: registration-token time is outside the ULID range")
	}
	var raw [16]byte
	raw[0] = byte(milliseconds >> 40)
	raw[1] = byte(milliseconds >> 32)
	raw[2] = byte(milliseconds >> 24)
	raw[3] = byte(milliseconds >> 16)
	raw[4] = byte(milliseconds >> 8)
	raw[5] = byte(milliseconds)
	copy(raw[6:], entropy)
	return encodeULID(raw), nil
}

func encodeULID(raw [16]byte) string {
	encoded := make([]byte, 26)
	var (
		buffer uint32
		bits   = 2 // A ULID is 128 bits encoded in a zero-prefixed 130-bit field.
		output int
	)
	for _, value := range raw {
		buffer = buffer<<8 | uint32(value)
		bits += 8
		for bits >= 5 {
			shift := bits - 5
			encoded[output] = ulidAlphabet[(buffer>>shift)&31]
			output++
			bits -= 5
			if bits == 0 {
				buffer = 0
			} else {
				buffer &= 1<<bits - 1
			}
		}
	}
	return string(encoded)
}

func waitUntilContext(ctx context.Context, deadline time.Time) error {
	delay := time.Until(deadline)
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
