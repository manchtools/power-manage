package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	registrationTokenStreamType        = "registration-token"
	registrationTokenMintedEventType   = "RegistrationTokenMinted"
	gatewayTokenMintedEventType        = "GatewayRegistrationTokenMinted"
	registrationTokenConsumedEventType = "RegistrationTokenConsumed"
	registrationTokenDisabledEventType = "RegistrationTokenDisabled"
	registrationTokenPayloadVersion    = 1
	maxRegistrationTokenOwnerBytes     = 256
	maxGatewayDNSNames                 = 16
	maxDNSNameBytes                    = 253
)

// RegistrationTokenRebuildTarget is the CLI-only token recovery target.
const RegistrationTokenRebuildTarget = "registration-tokens"

// RegistrationTokenPurpose binds one token to exactly one enrollment class.
type RegistrationTokenPurpose string

const (
	RegistrationTokenPurposeAgent   RegistrationTokenPurpose = "agent"
	RegistrationTokenPurposeGateway RegistrationTokenPurpose = "gateway"
)

// RegistrationToken is the hash-only token state used during admission.
type RegistrationToken struct {
	TokenID           string
	Hash              [sha256.Size]byte
	Purpose           RegistrationTokenPurpose
	DNSNames          []string
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

type gatewayRegistrationTokenMintedPayload struct {
	TokenHash []byte    `json:"token_hash"`
	MaxUses   int32     `json:"max_uses"`
	ExpiresAt time.Time `json:"expires_at"`
	Owner     string    `json:"owner"`
	DNSNames  []string  `json:"dns_names"`
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

// GatewayRegistrationTokenMintedEvent returns a purpose-bound gateway token
// event whose DNS names are authored by control and replayed exactly.
func GatewayRegistrationTokenMintedEvent(
	tokenID string,
	hash [sha256.Size]byte,
	maxUses int32,
	expiresAt time.Time,
	owner string,
	dnsNames []string,
) (Event, error) {
	tokenID, err := canonicalRegistrationTokenID(tokenID)
	if err != nil {
		return Event{}, err
	}
	if err := validateRegistrationTokenMetadata(maxUses, expiresAt, owner); err != nil {
		return Event{}, err
	}
	dnsNames, err = validateRegistrationTokenPurpose(RegistrationTokenPurposeGateway, dnsNames)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(gatewayRegistrationTokenMintedPayload{
		TokenHash: append([]byte(nil), hash[:]...),
		MaxUses:   maxUses,
		ExpiresAt: expiresAt.UTC(),
		Owner:     owner,
		DNSNames:  dnsNames,
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode gateway registration-token mint: %w", err)
	}
	return registrationTokenEvent(tokenID, gatewayTokenMintedEventType, payload), nil
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
	purpose := RegistrationTokenPurpose(row.Purpose)
	dnsNames, err := validateRegistrationTokenPurpose(purpose, row.DnsNames)
	if err != nil {
		return RegistrationToken{}, fmt.Errorf("store: invalid registration-token projection: %w", err)
	}
	if row.Uses < 0 || row.Uses > row.MaxUses {
		return RegistrationToken{}, errors.New("store: registration-token projection has an invalid use count")
	}
	state := RegistrationToken{
		TokenID:           row.TokenID,
		Purpose:           purpose,
		DNSNames:          dnsNames,
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

func validateRegistrationTokenPurpose(purpose RegistrationTokenPurpose, dnsNames []string) ([]string, error) {
	switch purpose {
	case RegistrationTokenPurposeAgent:
		if len(dnsNames) != 0 {
			return nil, errors.New("store: agent registration token must not contain DNS names")
		}
		return []string{}, nil
	case RegistrationTokenPurposeGateway:
		if len(dnsNames) == 0 || len(dnsNames) > maxGatewayDNSNames {
			return nil, fmt.Errorf("store: gateway registration token must contain 1..%d DNS names", maxGatewayDNSNames)
		}
	default:
		return nil, errors.New("store: registration-token purpose is invalid")
	}
	validated := slices.Clone(dnsNames)
	seen := make(map[string]struct{}, len(validated))
	for _, name := range validated {
		if !validGatewayDNSName(name) {
			return nil, fmt.Errorf("store: invalid gateway DNS name %q", name)
		}
		key := strings.ToLower(strings.TrimSuffix(name, "."))
		if _, exists := seen[key]; exists {
			return nil, fmt.Errorf("store: duplicate gateway DNS name %q", name)
		}
		seen[key] = struct{}{}
	}
	return validated, nil
}

func validGatewayDNSName(name string) bool {
	if name == "" || len(name) > maxDNSNameBytes || net.ParseIP(name) != nil {
		return false
	}
	trimmed := strings.TrimSuffix(name, ".")
	if trimmed == "" {
		return false
	}
	for _, label := range strings.Split(trimmed, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
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
		gatewayTokenMintedEventType: {
			PayloadVersion: registrationTokenPayloadVersion,
			PayloadType:    gatewayRegistrationTokenMintedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(gatewayRegistrationTokenMintedPayload{
					TokenHash: make([]byte, sha256.Size),
					MaxUses:   2,
					ExpiresAt: time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC),
					Owner:     "gateway-owner@example.com",
					DNSNames:  []string{"gateway.internal.example"},
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
		gatewayTokenMintedEventType: {
			PayloadVersion: registrationTokenPayloadVersion,
			Payload: []byte(
				`{"token_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","max_uses":2,"expires_at":"2030-01-02T03:04:05Z","owner":"gateway-owner@example.com","dns_names":["gateway.internal.example"]}`,
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
	var (
		tokenHash []byte
		purpose   RegistrationTokenPurpose
		dnsNames  []string
		maxUses   int32
		expiresAt time.Time
		owner     string
	)
	switch event.EventType {
	case registrationTokenMintedEventType:
		payload, err := decodeEventPayload[registrationTokenMintedPayload](event, registrationTokenPayloadVersion)
		if err != nil {
			return err
		}
		tokenHash = payload.TokenHash
		purpose = RegistrationTokenPurposeAgent
		dnsNames = []string{}
		maxUses = payload.MaxUses
		expiresAt = payload.ExpiresAt
		owner = payload.Owner
	case gatewayTokenMintedEventType:
		payload, err := decodeEventPayload[gatewayRegistrationTokenMintedPayload](event, registrationTokenPayloadVersion)
		if err != nil {
			return err
		}
		tokenHash = payload.TokenHash
		purpose = RegistrationTokenPurposeGateway
		dnsNames = payload.DNSNames
		maxUses = payload.MaxUses
		expiresAt = payload.ExpiresAt
		owner = payload.Owner
	default:
		return fmt.Errorf("store: event type %q is not a registration-token mint", event.EventType)
	}
	if len(tokenHash) != sha256.Size {
		return errors.New("store: registration-token mint payload has an invalid hash")
	}
	if err := validateRegistrationTokenMetadata(maxUses, expiresAt, owner); err != nil {
		return err
	}
	dnsNames, err := validateRegistrationTokenPurpose(purpose, dnsNames)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).UpsertRegistrationToken(ctx, generated.UpsertRegistrationTokenParams{
		TokenID:           event.StreamID,
		ProjectionVersion: event.StreamVersion,
		TokenHash:         tokenHash,
		Purpose:           string(purpose),
		DnsNames:          dnsNames,
		MaxUses:           maxUses,
		ExpiresAt:         expiresAt,
		Owner:             owner,
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
