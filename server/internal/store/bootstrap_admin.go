package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	bootstrapLoginStreamType        = "bootstrap-login"
	bootstrapLoginMintedEventType   = "BootstrapLoginMinted"
	bootstrapLoginConsumedEventType = "BootstrapLoginConsumed"
	bootstrapLoginPayloadVersion    = 1
)

// BootstrapLoginRebuildTarget is the CLI-only break-glass recovery target.
const BootstrapLoginRebuildTarget = "bootstrap-logins"

// BootstrapLogin is one digest-keyed, single-use break-glass login.
type BootstrapLogin struct {
	LoginID           string
	UserID            string
	Hash              [sha256.Size]byte
	ExpiresAt         time.Time
	Consumed          bool
	ProjectionVersion int64
}

type bootstrapLoginMintedPayload struct {
	TokenHash []byte    `json:"token_hash"`
	UserID    string    `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type bootstrapLoginConsumedPayload struct{}

// BootstrapLoginMintedEvent records only the digest of one break-glass secret.
func BootstrapLoginMintedEvent(
	loginID string,
	userID string,
	tokenHash [sha256.Size]byte,
	expiresAt time.Time,
) (Event, error) {
	loginID, err := canonicalBootstrapID(loginID, "login")
	if err != nil {
		return Event{}, err
	}
	userID, err = canonicalBootstrapID(userID, "user")
	if err != nil {
		return Event{}, err
	}
	if expiresAt.IsZero() || expiresAt.Unix() <= 0 {
		return Event{}, errors.New("store: bootstrap login expiry is invalid")
	}
	payload, err := json.Marshal(bootstrapLoginMintedPayload{
		TokenHash: append([]byte(nil), tokenHash[:]...),
		UserID:    userID,
		ExpiresAt: expiresAt.UTC(),
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode bootstrap login mint: %w", err)
	}
	return bootstrapLoginEvent(loginID, bootstrapLoginMintedEventType, payload), nil
}

// BootstrapLoginConsumedEvent records the single successful redemption.
func BootstrapLoginConsumedEvent(loginID string) (Event, error) {
	loginID, err := canonicalBootstrapID(loginID, "login")
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(bootstrapLoginConsumedPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode bootstrap login consume: %w", err)
	}
	return bootstrapLoginEvent(loginID, bootstrapLoginConsumedEventType, payload), nil
}

// BootstrapLoginByHash reads one break-glass login by its secret digest.
func (s *Store) BootstrapLoginByHash(
	ctx context.Context,
	tokenHash [sha256.Size]byte,
) (BootstrapLogin, error) {
	if s == nil || s.pool == nil {
		return BootstrapLogin{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return BootstrapLogin{}, errors.New("store: nil bootstrap login context")
	}
	row, err := generated.New(s.pool).GetBootstrapLoginByHash(ctx, tokenHash[:])
	if err != nil {
		return BootstrapLogin{}, fmt.Errorf("store: read bootstrap login: %w", err)
	}
	return bootstrapLoginFromRow(
		row.LoginID,
		row.TokenHash,
		row.UserID,
		row.ExpiresAt,
		row.Consumed,
		row.ProjectionVersion,
	)
}

func bootstrapLoginEvent(loginID, eventType string, payload []byte) Event {
	return Event{
		StreamType:     bootstrapLoginStreamType,
		StreamID:       loginID,
		EventType:      eventType,
		PayloadVersion: bootstrapLoginPayloadVersion,
		Payload:        payload,
	}
}

func canonicalBootstrapID(value, kind string) (string, error) {
	if err := validate.ULIDPathID(value); err != nil {
		return "", fmt.Errorf("store: bootstrap %s ID is invalid: %w", kind, err)
	}
	return strings.ToUpper(value), nil
}

func bootstrapLoginEventDefinitions() map[string]eventDefinition {
	return map[string]eventDefinition{
		bootstrapLoginMintedEventType: {
			PayloadVersion: bootstrapLoginPayloadVersion,
			PayloadType:    bootstrapLoginMintedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(bootstrapLoginMintedPayload{
					TokenHash: make([]byte, sha256.Size),
					UserID:    "01K0QJ3E5E8R4M0D8EV3Y4N6K3",
					ExpiresAt: time.Date(
						2032,
						time.March,
						4,
						5,
						6,
						7,
						0,
						time.UTC,
					),
				})
			},
			Projector: projectBootstrapLoginMint,
		},
		bootstrapLoginConsumedEventType: {
			PayloadVersion: bootstrapLoginPayloadVersion,
			PayloadType:    bootstrapLoginConsumedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(bootstrapLoginConsumedPayload{})
			},
			Projector: projectBootstrapLoginConsume,
		},
	}
}

func bootstrapLoginGoldenCorpus() map[string]goldenEvent {
	return map[string]goldenEvent{
		bootstrapLoginMintedEventType: {
			PayloadVersion: bootstrapLoginPayloadVersion,
			Payload: []byte(
				`{"token_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","user_id":"01K0QJ3E5E8R4M0D8EV3Y4N6K3","expires_at":"2032-03-04T05:06:07Z"}`,
			),
		},
		bootstrapLoginConsumedEventType: {
			PayloadVersion: bootstrapLoginPayloadVersion,
			Payload:        []byte(`{}`),
		},
	}
}

func projectBootstrapLoginMint(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion != 1 {
		return fmt.Errorf(
			"store: bootstrap login mint must be stream version 1, got %d",
			event.StreamVersion,
		)
	}
	loginID, err := canonicalBootstrapID(event.StreamID, "login")
	if err != nil || loginID != event.StreamID {
		return errors.New("store: bootstrap login stream ID is not canonical")
	}
	payload, err := decodeEventPayload[bootstrapLoginMintedPayload](
		event,
		bootstrapLoginPayloadVersion,
	)
	if err != nil {
		return err
	}
	if len(payload.TokenHash) != sha256.Size {
		return errors.New("store: bootstrap login mint hash is invalid")
	}
	userID, err := canonicalBootstrapID(payload.UserID, "user")
	if err != nil || userID != payload.UserID {
		return errors.New("store: bootstrap login user ID is not canonical")
	}
	if payload.ExpiresAt.IsZero() || payload.ExpiresAt.Unix() <= 0 {
		return errors.New("store: bootstrap login expiry is invalid")
	}
	queries := generated.New(tx)
	if _, err := queries.GetUserByID(ctx, userID); err != nil {
		return fmt.Errorf("store: bootstrap login requires a user: %w", err)
	}
	affected, err := queries.InsertBootstrapLogin(ctx, generated.InsertBootstrapLoginParams{
		LoginID:           event.StreamID,
		TokenHash:         append([]byte(nil), payload.TokenHash...),
		UserID:            userID,
		ExpiresAt:         payload.ExpiresAt.UTC(),
		ProjectionVersion: event.StreamVersion,
		UpdatedAt:         event.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("store: project bootstrap login mint: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: bootstrap login mint affected %d rows; want one", affected)
	}
	return nil
}

func projectBootstrapLoginConsume(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: bootstrap login consume requires a prior mint")
	}
	if _, err := decodeEventPayload[bootstrapLoginConsumedPayload](
		event,
		bootstrapLoginPayloadVersion,
	); err != nil {
		return err
	}
	queries := generated.New(tx)
	current, err := queries.GetBootstrapLoginByID(ctx, event.StreamID)
	if err != nil {
		return fmt.Errorf("store: bootstrap login consume requires a prior mint: %w", err)
	}
	if current.ProjectionVersion != event.StreamVersion-1 {
		return errors.New("store: bootstrap login projection version is inconsistent")
	}
	affected, err := queries.ConsumeBootstrapLogin(ctx, generated.ConsumeBootstrapLoginParams{
		ProjectionVersion:         event.StreamVersion,
		UpdatedAt:                 event.CreatedAt,
		LoginID:                   event.StreamID,
		PreviousProjectionVersion: event.StreamVersion - 1,
	})
	if err != nil {
		return fmt.Errorf("store: project bootstrap login consume: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: bootstrap login consume affected %d rows; want one", affected)
	}
	return nil
}

func bootstrapLoginFromRow(
	loginID string,
	tokenHash []byte,
	userID string,
	expiresAt time.Time,
	consumed bool,
	projectionVersion int64,
) (BootstrapLogin, error) {
	canonicalLoginID, err := canonicalBootstrapID(loginID, "login")
	if err != nil || canonicalLoginID != loginID {
		return BootstrapLogin{}, errors.New("store: bootstrap login projection has invalid login ID")
	}
	canonicalUserID, err := canonicalBootstrapID(userID, "user")
	if err != nil || canonicalUserID != userID {
		return BootstrapLogin{}, errors.New("store: bootstrap login projection has invalid user ID")
	}
	if len(tokenHash) != sha256.Size ||
		expiresAt.IsZero() ||
		expiresAt.Unix() <= 0 ||
		projectionVersion <= 0 {
		return BootstrapLogin{}, errors.New("store: bootstrap login projection is invalid")
	}
	var hash [sha256.Size]byte
	copy(hash[:], tokenHash)
	return BootstrapLogin{
		LoginID:           loginID,
		UserID:            userID,
		Hash:              hash,
		ExpiresAt:         expiresAt.UTC(),
		Consumed:          consumed,
		ProjectionVersion: projectionVersion,
	}, nil
}

func resetBootstrapLogins(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetBootstrapLogins(ctx); err != nil {
		return fmt.Errorf("store: reset bootstrap logins: %w", err)
	}
	return nil
}
