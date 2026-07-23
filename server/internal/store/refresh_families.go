package store

import (
	"bytes"
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
	refreshFamilyStreamType       = "refresh-family"
	refreshFamilyStartedEventType = "RefreshFamilyStarted"
	refreshTokenRotatedEventType  = "RefreshTokenRotated"
	refreshFamilyRevokedEventType = "RefreshFamilyRevoked"
	refreshFamilyPayloadVersion   = 1
	maxRefreshSubjectBytes        = 1024
)

// RefreshFamilyRebuildTarget is the CLI-only refresh-session recovery target.
const RefreshFamilyRebuildTarget = "refresh-families"

// RefreshFamilyToken is one hash-only token-history row joined to its family.
type RefreshFamilyToken struct {
	FamilyID          string
	Subject           string
	Hash              [sha256.Size]byte
	ActiveHash        [sha256.Size]byte
	ExpiresAt         time.Time
	Superseded        bool
	Revoked           bool
	ProjectionVersion int64
}

type refreshFamilyStartedPayload struct {
	Subject   string    `json:"subject"`
	TokenHash []byte    `json:"token_hash"`
	ExpiresAt time.Time `json:"expires_at"`
}

type refreshTokenRotatedPayload struct {
	PreviousTokenHash []byte    `json:"previous_token_hash"`
	NextTokenHash     []byte    `json:"next_token_hash"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type refreshFamilyRevokedPayload struct {
	ReplayedTokenHash []byte `json:"replayed_token_hash"`
}

// RefreshFamilyStartedEvent creates a hash-only refresh-family stream.
func RefreshFamilyStartedEvent(
	familyID string,
	subject string,
	tokenHash [sha256.Size]byte,
	expiresAt time.Time,
) (Event, error) {
	familyID, err := canonicalRefreshFamilyID(familyID)
	if err != nil {
		return Event{}, err
	}
	if err := validateRefreshSubject(subject); err != nil {
		return Event{}, err
	}
	if err := validateRefreshExpiry(expiresAt); err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(refreshFamilyStartedPayload{
		Subject:   subject,
		TokenHash: append([]byte(nil), tokenHash[:]...),
		ExpiresAt: expiresAt.UTC(),
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode refresh-family start: %w", err)
	}
	return refreshFamilyEvent(familyID, refreshFamilyStartedEventType, payload), nil
}

// RefreshTokenRotatedEvent supersedes one family token with a hash-only successor.
func RefreshTokenRotatedEvent(
	familyID string,
	previousTokenHash [sha256.Size]byte,
	nextTokenHash [sha256.Size]byte,
	expiresAt time.Time,
) (Event, error) {
	familyID, err := canonicalRefreshFamilyID(familyID)
	if err != nil {
		return Event{}, err
	}
	if previousTokenHash == nextTokenHash {
		return Event{}, errors.New("store: refresh-token rotation hashes are identical")
	}
	if err := validateRefreshExpiry(expiresAt); err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(refreshTokenRotatedPayload{
		PreviousTokenHash: append([]byte(nil), previousTokenHash[:]...),
		NextTokenHash:     append([]byte(nil), nextTokenHash[:]...),
		ExpiresAt:         expiresAt.UTC(),
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode refresh-token rotation: %w", err)
	}
	return refreshFamilyEvent(familyID, refreshTokenRotatedEventType, payload), nil
}

// RefreshFamilyRevokedEvent records reuse of one superseded family token.
func RefreshFamilyRevokedEvent(
	familyID string,
	replayedTokenHash [sha256.Size]byte,
) (Event, error) {
	familyID, err := canonicalRefreshFamilyID(familyID)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(refreshFamilyRevokedPayload{
		ReplayedTokenHash: append([]byte(nil), replayedTokenHash[:]...),
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode refresh-family revocation: %w", err)
	}
	return refreshFamilyEvent(familyID, refreshFamilyRevokedEventType, payload), nil
}

// RefreshFamilyToken reads and validates token history by SHA-256 digest.
func (s *Store) RefreshFamilyToken(
	ctx context.Context,
	tokenHash [sha256.Size]byte,
) (RefreshFamilyToken, error) {
	if s == nil || s.pool == nil {
		return RefreshFamilyToken{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return RefreshFamilyToken{}, errors.New("store: nil refresh-family context")
	}
	row, err := generated.New(s.pool).GetRefreshFamilyToken(ctx, tokenHash[:])
	if err != nil {
		return RefreshFamilyToken{}, fmt.Errorf("store: read refresh-family token: %w", err)
	}
	return refreshFamilyTokenFromRow(row)
}

func refreshFamilyEvent(familyID, eventType string, payload []byte) Event {
	return Event{
		StreamType:     refreshFamilyStreamType,
		StreamID:       familyID,
		EventType:      eventType,
		PayloadVersion: refreshFamilyPayloadVersion,
		Payload:        payload,
	}
}

func canonicalRefreshFamilyID(familyID string) (string, error) {
	if err := validate.ULIDPathID(familyID); err != nil {
		return "", fmt.Errorf("store: invalid refresh-family ID: %w", err)
	}
	return strings.ToUpper(familyID), nil
}

func validateRefreshSubject(subject string) error {
	if len(subject) == 0 || len(subject) > maxRefreshSubjectBytes ||
		!utf8.ValidString(subject) || strings.ContainsRune(subject, '\x00') {
		return errors.New("store: refresh-family subject is invalid")
	}
	return nil
}

func validateRefreshExpiry(expiresAt time.Time) error {
	if expiresAt.IsZero() || expiresAt.Unix() <= 0 {
		return errors.New("store: refresh-token expiry is invalid")
	}
	return nil
}

func refreshFamilyEventDefinitions() map[string]eventDefinition {
	return map[string]eventDefinition{
		refreshFamilyStartedEventType: {
			PayloadVersion: refreshFamilyPayloadVersion,
			PayloadType:    refreshFamilyStartedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(refreshFamilyStartedPayload{
					Subject:   "01K0QJ3E5E8R4M0D8EV3Y4N6J7",
					TokenHash: make([]byte, sha256.Size),
					ExpiresAt: time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC),
				})
			},
			Projector: projectRefreshFamilyStart,
		},
		refreshTokenRotatedEventType: {
			PayloadVersion: refreshFamilyPayloadVersion,
			PayloadType:    refreshTokenRotatedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(refreshTokenRotatedPayload{
					PreviousTokenHash: bytes.Repeat([]byte{1}, sha256.Size),
					NextTokenHash:     bytes.Repeat([]byte{2}, sha256.Size),
					ExpiresAt:         time.Date(2030, time.January, 3, 3, 4, 5, 0, time.UTC),
				})
			},
			Projector: projectRefreshTokenRotation,
		},
		refreshFamilyRevokedEventType: {
			PayloadVersion: refreshFamilyPayloadVersion,
			PayloadType:    refreshFamilyRevokedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(refreshFamilyRevokedPayload{
					ReplayedTokenHash: bytes.Repeat([]byte{1}, sha256.Size),
				})
			},
			Projector: projectRefreshFamilyRevocation,
		},
	}
}

func refreshFamilyGoldenCorpus() map[string]goldenEvent {
	return map[string]goldenEvent{
		refreshFamilyStartedEventType: {
			PayloadVersion: refreshFamilyPayloadVersion,
			Payload: []byte(
				`{"subject":"01K0QJ3E5E8R4M0D8EV3Y4N6J7","token_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","expires_at":"2030-01-02T03:04:05Z"}`,
			),
		},
		refreshTokenRotatedEventType: {
			PayloadVersion: refreshFamilyPayloadVersion,
			Payload: []byte(
				`{"previous_token_hash":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","next_token_hash":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","expires_at":"2030-01-03T03:04:05Z"}`,
			),
		},
		refreshFamilyRevokedEventType: {
			PayloadVersion: refreshFamilyPayloadVersion,
			Payload: []byte(
				`{"replayed_token_hash":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}`,
			),
		},
	}
}

func projectRefreshFamilyStart(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion != 1 {
		return fmt.Errorf("store: refresh-family start must be stream version 1, got %d", event.StreamVersion)
	}
	payload, err := decodeEventPayload[refreshFamilyStartedPayload](event, refreshFamilyPayloadVersion)
	if err != nil {
		return err
	}
	if err := validateRefreshSubject(payload.Subject); err != nil {
		return err
	}
	if len(payload.TokenHash) != sha256.Size {
		return errors.New("store: refresh-family start payload has an invalid hash")
	}
	if err := validateRefreshExpiry(payload.ExpiresAt); err != nil {
		return err
	}
	queries := generated.New(tx)
	affected, err := queries.InsertRefreshFamily(ctx, generated.InsertRefreshFamilyParams{
		FamilyID:          event.StreamID,
		Subject:           payload.Subject,
		ProjectionVersion: event.StreamVersion,
		ActiveTokenHash:   payload.TokenHash,
		UpdatedAt:         event.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("store: project refresh-family start: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: refresh-family start affected %d families; want one", affected)
	}
	affected, err = queries.InsertRefreshToken(ctx, generated.InsertRefreshTokenParams{
		TokenHash: payload.TokenHash,
		FamilyID:  event.StreamID,
		ExpiresAt: payload.ExpiresAt,
	})
	if err != nil {
		return fmt.Errorf("store: project initial refresh token: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: refresh-family start affected %d tokens; want one", affected)
	}
	return nil
}

func projectRefreshTokenRotation(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: refresh-token rotation requires a prior family start")
	}
	payload, err := decodeEventPayload[refreshTokenRotatedPayload](event, refreshFamilyPayloadVersion)
	if err != nil {
		return err
	}
	if len(payload.PreviousTokenHash) != sha256.Size || len(payload.NextTokenHash) != sha256.Size {
		return errors.New("store: refresh-token rotation payload has an invalid hash")
	}
	if bytes.Equal(payload.PreviousTokenHash, payload.NextTokenHash) {
		return errors.New("store: refresh-token rotation hashes are identical")
	}
	if err := validateRefreshExpiry(payload.ExpiresAt); err != nil {
		return err
	}
	queries := generated.New(tx)
	family, err := queries.GetRefreshFamily(ctx, event.StreamID)
	if err != nil {
		if IsNotFound(err) {
			return errors.New("store: refresh-token rotation requires a prior family start")
		}
		return fmt.Errorf("store: inspect refresh family before rotation: %w", err)
	}
	if family.ProjectionVersion != event.StreamVersion-1 {
		return errors.New("store: refresh-family projection version is inconsistent")
	}
	if family.Revoked {
		return errors.New("store: cannot rotate a revoked refresh family")
	}
	if !bytes.Equal(family.ActiveTokenHash, payload.PreviousTokenHash) {
		return errors.New("store: refresh-token rotation does not match the active token")
	}
	affected, err := queries.ProjectRefreshFamilyRotation(ctx, generated.ProjectRefreshFamilyRotationParams{
		ProjectionVersion: event.StreamVersion,
		NextTokenHash:     payload.NextTokenHash,
		UpdatedAt:         event.CreatedAt,
		FamilyID:          event.StreamID,
		PreviousTokenHash: payload.PreviousTokenHash,
	})
	if err != nil {
		return fmt.Errorf("store: project refresh-family rotation: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: refresh-token rotation affected %d families; want one", affected)
	}
	affected, err = queries.ProjectRefreshTokenSuperseded(ctx, generated.ProjectRefreshTokenSupersededParams{
		FamilyID:  event.StreamID,
		TokenHash: payload.PreviousTokenHash,
	})
	if err != nil {
		return fmt.Errorf("store: supersede refresh token: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: refresh-token rotation affected %d prior tokens; want one", affected)
	}
	affected, err = queries.InsertRefreshToken(ctx, generated.InsertRefreshTokenParams{
		TokenHash: payload.NextTokenHash,
		FamilyID:  event.StreamID,
		ExpiresAt: payload.ExpiresAt,
	})
	if err != nil {
		return fmt.Errorf("store: project rotated refresh token: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: refresh-token rotation affected %d next tokens; want one", affected)
	}
	return nil
}

func projectRefreshFamilyRevocation(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: refresh-family revocation requires a prior family start")
	}
	payload, err := decodeEventPayload[refreshFamilyRevokedPayload](event, refreshFamilyPayloadVersion)
	if err != nil {
		return err
	}
	if len(payload.ReplayedTokenHash) != sha256.Size {
		return errors.New("store: refresh-family revocation payload has an invalid hash")
	}
	queries := generated.New(tx)
	family, err := queries.GetRefreshFamily(ctx, event.StreamID)
	if err != nil {
		if IsNotFound(err) {
			return errors.New("store: refresh-family revocation requires a prior family start")
		}
		return fmt.Errorf("store: inspect refresh family before revocation: %w", err)
	}
	if family.ProjectionVersion != event.StreamVersion-1 {
		return errors.New("store: refresh-family projection version is inconsistent")
	}
	if family.Revoked {
		return errors.New("store: refresh family is already revoked")
	}
	replayed, err := queries.GetRefreshFamilyToken(ctx, payload.ReplayedTokenHash)
	if err != nil {
		if IsNotFound(err) {
			return errors.New("store: refresh-family revocation token is not in the family")
		}
		return fmt.Errorf("store: inspect replayed refresh token: %w", err)
	}
	if replayed.FamilyID != event.StreamID {
		return errors.New("store: refresh-family revocation token belongs to another family")
	}
	if !replayed.Superseded {
		return errors.New("store: refresh-family revocation token is not superseded")
	}
	affected, err := queries.ProjectRefreshFamilyRevocation(ctx, generated.ProjectRefreshFamilyRevocationParams{
		ProjectionVersion: event.StreamVersion,
		UpdatedAt:         event.CreatedAt,
		FamilyID:          event.StreamID,
	})
	if err != nil {
		return fmt.Errorf("store: project refresh-family revocation: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: refresh-family revocation affected %d families; want one", affected)
	}
	return nil
}

func refreshFamilyTokenFromRow(row generated.GetRefreshFamilyTokenRow) (RefreshFamilyToken, error) {
	if _, err := canonicalRefreshFamilyID(row.FamilyID); err != nil {
		return RefreshFamilyToken{}, errors.New("store: refresh-family projection has an invalid family ID")
	}
	if err := validateRefreshSubject(row.Subject); err != nil {
		return RefreshFamilyToken{}, fmt.Errorf("store: invalid refresh-family projection: %w", err)
	}
	if row.ProjectionVersion <= 0 {
		return RefreshFamilyToken{}, errors.New("store: refresh-family projection has an invalid version")
	}
	if len(row.TokenHash) != sha256.Size || len(row.ActiveTokenHash) != sha256.Size {
		return RefreshFamilyToken{}, errors.New("store: refresh-family projection has an invalid hash")
	}
	if err := validateRefreshExpiry(row.ExpiresAt); err != nil {
		return RefreshFamilyToken{}, fmt.Errorf("store: invalid refresh-token projection: %w", err)
	}
	state := RefreshFamilyToken{
		FamilyID:          row.FamilyID,
		Subject:           row.Subject,
		ExpiresAt:         row.ExpiresAt.UTC(),
		Superseded:        row.Superseded,
		Revoked:           row.Revoked,
		ProjectionVersion: row.ProjectionVersion,
	}
	copy(state.Hash[:], row.TokenHash)
	copy(state.ActiveHash[:], row.ActiveTokenHash)
	return state, nil
}

func resetRefreshFamilies(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetRefreshFamilies(ctx); err != nil {
		return fmt.Errorf("store: reset refresh families: %w", err)
	}
	return nil
}
