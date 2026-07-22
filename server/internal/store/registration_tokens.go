package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	registrationTokenStreamType        = "registration-token"
	registrationTokenMintedEventType   = "RegistrationTokenMinted"
	registrationTokenConsumedEventType = "RegistrationTokenConsumed"
	registrationTokenDisabledEventType = "RegistrationTokenDisabled"
	registrationTokenPayloadVersion    = 1
	maxRegistrationTokenOwnerBytes     = 256
)

// RegistrationTokenRebuildTarget is the CLI-only token recovery target.
const RegistrationTokenRebuildTarget = "registration-tokens"

// RegistrationToken is the hash-only token state used during admission.
type RegistrationToken struct {
	TokenID           string
	Hash              [sha256.Size]byte
	MaxUses           int32
	Uses              int32
	ExpiresAt         time.Time
	Owner             string
	Disabled          bool
	ProjectionVersion int64
}

type registrationTokenMintedPayload struct {
	TokenHash []byte    `json:"token_hash"`
	MaxUses   int32     `json:"max_uses"`
	ExpiresAt time.Time `json:"expires_at"`
	Owner     string    `json:"owner"`
}

type registrationTokenConsumedPayload struct{}
type registrationTokenDisabledPayload struct{}

// RegistrationTokenMintedEvent returns the hash-only token creation event.
func RegistrationTokenMintedEvent(
	tokenID string,
	hash [sha256.Size]byte,
	maxUses int32,
	expiresAt time.Time,
	owner string,
) (Event, error) {
	tokenID, err := canonicalRegistrationTokenID(tokenID)
	if err != nil {
		return Event{}, err
	}
	if err := validateRegistrationTokenMetadata(maxUses, expiresAt, owner); err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(registrationTokenMintedPayload{
		TokenHash: append([]byte(nil), hash[:]...),
		MaxUses:   maxUses,
		ExpiresAt: expiresAt.UTC(),
		Owner:     owner,
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode registration-token mint: %w", err)
	}
	return registrationTokenEvent(tokenID, registrationTokenMintedEventType, payload), nil
}

// RegistrationTokenConsumedEvent returns one bounded-use consume event.
func RegistrationTokenConsumedEvent(tokenID string) (Event, error) {
	tokenID, err := canonicalRegistrationTokenID(tokenID)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(registrationTokenConsumedPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode registration-token consume: %w", err)
	}
	return registrationTokenEvent(tokenID, registrationTokenConsumedEventType, payload), nil
}

// RegistrationTokenDisabledEvent returns the durable kill-switch event.
func RegistrationTokenDisabledEvent(tokenID string) (Event, error) {
	tokenID, err := canonicalRegistrationTokenID(tokenID)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(registrationTokenDisabledPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode registration-token disable: %w", err)
	}
	return registrationTokenEvent(tokenID, registrationTokenDisabledEventType, payload), nil
}

// RegistrationToken reads and validates one hash-only token projection row.
func (s *Store) RegistrationToken(ctx context.Context, tokenID string) (RegistrationToken, error) {
	if s == nil || s.pool == nil {
		return RegistrationToken{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return RegistrationToken{}, errors.New("store: nil registration-token context")
	}
	tokenID, err := canonicalRegistrationTokenID(tokenID)
	if err != nil {
		return RegistrationToken{}, err
	}
	row, err := generated.New(s.pool).GetRegistrationToken(ctx, tokenID)
	if err != nil {
		return RegistrationToken{}, fmt.Errorf("store: read registration token: %w", err)
	}
	if row.TokenID != tokenID {
		return RegistrationToken{}, errors.New("store: registration-token projection returned a mismatched ID")
	}
	if row.ProjectionVersion <= 0 {
		return RegistrationToken{}, errors.New("store: registration-token projection has an invalid version")
	}
	if len(row.TokenHash) != sha256.Size {
		return RegistrationToken{}, errors.New("store: registration-token projection has an invalid hash")
	}
	if err := validateRegistrationTokenMetadata(row.MaxUses, row.ExpiresAt, row.Owner); err != nil {
		return RegistrationToken{}, fmt.Errorf("store: invalid registration-token projection: %w", err)
	}
	if row.Uses < 0 || row.Uses > row.MaxUses {
		return RegistrationToken{}, errors.New("store: registration-token projection has an invalid use count")
	}
	state := RegistrationToken{
		TokenID:           row.TokenID,
		MaxUses:           row.MaxUses,
		Uses:              row.Uses,
		ExpiresAt:         row.ExpiresAt,
		Owner:             row.Owner,
		Disabled:          row.Disabled,
		ProjectionVersion: row.ProjectionVersion,
	}
	copy(state.Hash[:], row.TokenHash)
	return state, nil
}

func registrationTokenEvent(tokenID, eventType string, payload []byte) Event {
	return Event{
		StreamType:     registrationTokenStreamType,
		StreamID:       tokenID,
		EventType:      eventType,
		PayloadVersion: registrationTokenPayloadVersion,
		Payload:        payload,
	}
}

func canonicalRegistrationTokenID(tokenID string) (string, error) {
	if err := validate.ULIDPathID(tokenID); err != nil {
		return "", fmt.Errorf("store: invalid registration-token ID: %w", err)
	}
	return strings.ToUpper(tokenID), nil
}

func validateRegistrationTokenMetadata(maxUses int32, expiresAt time.Time, owner string) error {
	if maxUses <= 0 {
		return errors.New("store: registration-token max uses must be positive")
	}
	if expiresAt.IsZero() {
		return errors.New("store: registration-token expiry is zero")
	}
	if !utf8.ValidString(owner) || strings.ContainsRune(owner, '\x00') {
		return errors.New("store: registration-token owner is invalid")
	}
	if len(owner) > maxRegistrationTokenOwnerBytes {
		return fmt.Errorf("store: registration-token owner exceeds %d bytes", maxRegistrationTokenOwnerBytes)
	}
	return nil
}

func registrationTokenEventDefinitions() map[string]eventDefinition {
	return map[string]eventDefinition{
		registrationTokenMintedEventType: {
			PayloadVersion: registrationTokenPayloadVersion,
			PayloadType:    registrationTokenMintedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(registrationTokenMintedPayload{
					TokenHash: make([]byte, sha256.Size),
					MaxUses:   3,
					ExpiresAt: time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC),
					Owner:     "owner@example.com",
				})
			},
			Projector: projectRegistrationTokenMint,
		},
		registrationTokenConsumedEventType: {
			PayloadVersion: registrationTokenPayloadVersion,
			PayloadType:    registrationTokenConsumedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(registrationTokenConsumedPayload{})
			},
			Projector: projectRegistrationTokenConsume,
		},
		registrationTokenDisabledEventType: {
			PayloadVersion: registrationTokenPayloadVersion,
			PayloadType:    registrationTokenDisabledPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(registrationTokenDisabledPayload{})
			},
			Projector: projectRegistrationTokenDisable,
		},
	}
}

func registrationTokenGoldenCorpus() map[string]goldenEvent {
	return map[string]goldenEvent{
		registrationTokenMintedEventType: {
			PayloadVersion: registrationTokenPayloadVersion,
			Payload: []byte(
				`{"token_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","max_uses":3,"expires_at":"2030-01-02T03:04:05Z","owner":"owner@example.com"}`,
			),
		},
		registrationTokenConsumedEventType: {
			PayloadVersion: registrationTokenPayloadVersion,
			Payload:        []byte(`{}`),
		},
		registrationTokenDisabledEventType: {
			PayloadVersion: registrationTokenPayloadVersion,
			Payload:        []byte(`{}`),
		},
	}
}

func projectRegistrationTokenMint(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion != 1 {
		return fmt.Errorf("store: registration-token mint must be stream version 1, got %d", event.StreamVersion)
	}
	payload, err := decodeEventPayload[registrationTokenMintedPayload](event, registrationTokenPayloadVersion)
	if err != nil {
		return err
	}
	if len(payload.TokenHash) != sha256.Size {
		return errors.New("store: registration-token mint payload has an invalid hash")
	}
	if err := validateRegistrationTokenMetadata(payload.MaxUses, payload.ExpiresAt, payload.Owner); err != nil {
		return err
	}
	affected, err := generated.New(tx).UpsertRegistrationToken(ctx, generated.UpsertRegistrationTokenParams{
		TokenID:           event.StreamID,
		ProjectionVersion: event.StreamVersion,
		TokenHash:         payload.TokenHash,
		MaxUses:           payload.MaxUses,
		ExpiresAt:         payload.ExpiresAt,
		Owner:             payload.Owner,
		UpdatedAt:         event.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("store: project registration-token mint: %w", err)
	}
	return validateRegistrationTokenProjectionResult(ctx, tx, event, affected, "mint")
}

func projectRegistrationTokenConsume(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return fmt.Errorf("store: registration-token consume requires a prior mint")
	}
	if _, err := decodeEventPayload[registrationTokenConsumedPayload](event, registrationTokenPayloadVersion); err != nil {
		return err
	}
	affected, err := generated.New(tx).ProjectRegistrationTokenConsume(
		ctx,
		generated.ProjectRegistrationTokenConsumeParams{
			TokenID:           event.StreamID,
			ProjectionVersion: event.StreamVersion,
			UpdatedAt:         event.CreatedAt,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project registration-token consume: %w", err)
	}
	return validateRegistrationTokenProjectionResult(ctx, tx, event, affected, "consume")
}

func projectRegistrationTokenDisable(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return fmt.Errorf("store: registration-token disable requires a prior mint")
	}
	if _, err := decodeEventPayload[registrationTokenDisabledPayload](event, registrationTokenPayloadVersion); err != nil {
		return err
	}
	affected, err := generated.New(tx).ProjectRegistrationTokenDisable(
		ctx,
		generated.ProjectRegistrationTokenDisableParams{
			TokenID:           event.StreamID,
			ProjectionVersion: event.StreamVersion,
			UpdatedAt:         event.CreatedAt,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project registration-token disable: %w", err)
	}
	return validateRegistrationTokenProjectionResult(ctx, tx, event, affected, "disable")
}

func resetRegistrationTokens(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetRegistrationTokens(ctx); err != nil {
		return fmt.Errorf("store: reset registration tokens: %w", err)
	}
	return nil
}

func validateRegistrationTokenProjectionResult(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
	affected int64,
	operation string,
) error {
	if affected == 1 {
		return nil
	}
	if affected != 0 {
		return fmt.Errorf("store: registration-token %s affected %d rows; want one", operation, affected)
	}
	row, err := generated.New(tx).GetRegistrationToken(ctx, event.StreamID)
	if err != nil {
		if IsNotFound(err) {
			return fmt.Errorf("store: registration-token %s has no minted projection", operation)
		}
		return fmt.Errorf("store: inspect registration-token %s projection: %w", operation, err)
	}
	if row.ProjectionVersion >= event.StreamVersion {
		return nil
	}
	return fmt.Errorf("store: registration-token %s is invalid for the current state", operation)
}
