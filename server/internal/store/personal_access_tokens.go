package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	personalAccessTokenStreamType       = "personal-access-token"
	personalAccessTokenMintedEventType  = "PersonalAccessTokenMinted"
	personalAccessTokenRevokedEventType = "PersonalAccessTokenRevoked"
	personalAccessTokenUpdatedEventType = "PersonalAccessTokenUpdated"
	personalAccessTokenDeletedEventType = "PersonalAccessTokenDeleted"
	personalAccessTokenPayloadVersion   = 1
	maxPATSubjectBytes                  = 1024
	maxPATScopes                        = 64
	maxPATScopeBytes                    = 128
)

// PersonalAccessTokenRebuildTarget is the CLI-only PAT recovery target.
const PersonalAccessTokenRebuildTarget = "personal-access-tokens"

// PersonalAccessToken is one hash-only PAT projection.
type PersonalAccessToken struct {
	TokenID           string
	Subject           string
	Hash              [sha256.Size]byte
	Scopes            []string
	ExpiresAt         time.Time
	Revoked           bool
	ProjectionVersion int64
}

// PersonalAccessTokenMetadata is the verifier-free management projection.
type PersonalAccessTokenMetadata struct {
	TokenID           string
	Subject           string
	Scopes            []string
	ExpiresAt         time.Time
	Revoked           bool
	ProjectionVersion int64
}

type personalAccessTokenMintedPayload struct {
	Subject   string    `json:"subject"`
	Scopes    []string  `json:"scopes"`
	TokenHash []byte    `json:"token_hash"`
	ExpiresAt time.Time `json:"expires_at"`
}

type personalAccessTokenRevokedPayload struct{}
type personalAccessTokenUpdatedPayload struct {
	Subject   string    `json:"subject"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}
type personalAccessTokenDeletedPayload struct{}

var errPersonalAccessTokenExists = errors.New("store: personal access token already exists")

// PersonalAccessTokenMintedEvent creates one hash-only PAT stream.
func PersonalAccessTokenMintedEvent(
	tokenID string,
	subject string,
	scopes []string,
	tokenHash [sha256.Size]byte,
	expiresAt time.Time,
) (Event, error) {
	tokenID, err := canonicalPATID(tokenID)
	if err != nil {
		return Event{}, err
	}
	if err := validatePATSubject(subject); err != nil {
		return Event{}, err
	}
	if err := validatePATScopes(scopes); err != nil {
		return Event{}, err
	}
	if err := validatePATExpiry(expiresAt); err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(personalAccessTokenMintedPayload{
		Subject:   subject,
		Scopes:    slices.Clone(scopes),
		TokenHash: append([]byte(nil), tokenHash[:]...),
		ExpiresAt: expiresAt.UTC(),
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode PAT mint: %w", err)
	}
	return personalAccessTokenEvent(tokenID, personalAccessTokenMintedEventType, payload), nil
}

// PersonalAccessTokenRevokedEvent records durable PAT revocation.
func PersonalAccessTokenRevokedEvent(tokenID string) (Event, error) {
	tokenID, err := canonicalPATID(tokenID)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(personalAccessTokenRevokedPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode PAT revocation: %w", err)
	}
	return personalAccessTokenEvent(tokenID, personalAccessTokenRevokedEventType, payload), nil
}

// PersonalAccessTokenUpdatedEvent replaces public PAT metadata while retaining
// the hash-only credential binding.
func PersonalAccessTokenUpdatedEvent(
	tokenID string,
	subject string,
	scopes []string,
	expiresAt time.Time,
	revoked bool,
) (Event, error) {
	tokenID, err := canonicalPATID(tokenID)
	if err != nil {
		return Event{}, err
	}
	if err := validatePATSubject(subject); err != nil {
		return Event{}, err
	}
	if err := validatePATScopes(scopes); err != nil {
		return Event{}, err
	}
	if err := validatePATExpiry(expiresAt); err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(personalAccessTokenUpdatedPayload{
		Subject:   subject,
		Scopes:    slices.Clone(scopes),
		ExpiresAt: expiresAt.UTC(),
		Revoked:   revoked,
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode PAT update: %w", err)
	}
	return personalAccessTokenEvent(tokenID, personalAccessTokenUpdatedEventType, payload), nil
}

// PersonalAccessTokenDeletedEvent removes one PAT projection.
func PersonalAccessTokenDeletedEvent(tokenID string) (Event, error) {
	tokenID, err := canonicalPATID(tokenID)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(personalAccessTokenDeletedPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode PAT deletion: %w", err)
	}
	return personalAccessTokenEvent(tokenID, personalAccessTokenDeletedEventType, payload), nil
}

// PersonalAccessTokenByHash reads and validates a PAT by secret digest.
func (s *Store) PersonalAccessTokenByHash(
	ctx context.Context,
	tokenHash [sha256.Size]byte,
) (PersonalAccessToken, error) {
	if s == nil || s.pool == nil {
		return PersonalAccessToken{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return PersonalAccessToken{}, errors.New("store: nil PAT context")
	}
	row, err := generated.New(s.pool).GetPersonalAccessTokenByHash(ctx, tokenHash[:])
	if err != nil {
		return PersonalAccessToken{}, fmt.Errorf("store: read PAT by hash: %w", err)
	}
	return personalAccessTokenFromHashRow(row)
}

// PersonalAccessTokenByID reads and validates a PAT by canonical public ID.
func (s *Store) PersonalAccessTokenByID(
	ctx context.Context,
	tokenID string,
) (PersonalAccessToken, error) {
	if s == nil || s.pool == nil {
		return PersonalAccessToken{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return PersonalAccessToken{}, errors.New("store: nil PAT context")
	}
	tokenID, err := canonicalPATID(tokenID)
	if err != nil {
		return PersonalAccessToken{}, err
	}
	row, err := generated.New(s.pool).GetPersonalAccessTokenByID(ctx, tokenID)
	if err != nil {
		return PersonalAccessToken{}, fmt.Errorf("store: read PAT by ID: %w", err)
	}
	return personalAccessTokenFromIDRow(row)
}

// ScopedPersonalAccessTokenByID reads metadata through its subject relation.
func (s *Store) ScopedPersonalAccessTokenByID(
	ctx context.Context,
	tokenID string,
	global bool,
	userGroupIDs []string,
	selfID string,
) (PersonalAccessTokenMetadata, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return PersonalAccessTokenMetadata{}, errors.New("store: invalid scoped PAT lookup")
	}
	tokenID, err := canonicalPATID(tokenID)
	if err != nil {
		return PersonalAccessTokenMetadata{}, err
	}
	userGroupIDs, err = normalizeUserScopeIDs(userGroupIDs)
	if err != nil {
		return PersonalAccessTokenMetadata{}, err
	}
	if selfID != "" {
		selfID, err = canonicalUserID(selfID)
		if err != nil {
			return PersonalAccessTokenMetadata{}, err
		}
	}
	row, err := generated.New(s.pool).GetScopedPersonalAccessToken(
		ctx,
		generated.GetScopedPersonalAccessTokenParams{
			TokenID:      tokenID,
			GlobalScope:  global,
			SelfID:       selfID,
			UserGroupIds: userGroupIDs,
		},
	)
	if err != nil {
		return PersonalAccessTokenMetadata{}, fmt.Errorf("store: read scoped PAT: %w", err)
	}
	return validatePersonalAccessTokenMetadataProjection(
		row.TokenID, row.Subject, row.Scopes, row.ExpiresAt,
		row.Revoked, row.ProjectionVersion,
	)
}

// ListScopedPersonalAccessTokens returns one subject-confined metadata page.
func (s *Store) ListScopedPersonalAccessTokens(
	ctx context.Context,
	global bool,
	userGroupIDs []string,
	selfID string,
	limit int32,
) ([]PersonalAccessTokenMetadata, error) {
	if s == nil || s.pool == nil || ctx == nil || limit < 1 || limit > 200 {
		return nil, errors.New("store: invalid scoped PAT list")
	}
	userGroupIDs, err := normalizeUserScopeIDs(userGroupIDs)
	if err != nil {
		return nil, err
	}
	if selfID != "" {
		selfID, err = canonicalUserID(selfID)
		if err != nil {
			return nil, err
		}
	}
	rows, err := generated.New(s.pool).ListScopedPersonalAccessTokens(
		ctx,
		generated.ListScopedPersonalAccessTokensParams{
			GlobalScope:  global,
			SelfID:       selfID,
			UserGroupIds: userGroupIDs,
			PageLimit:    limit,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("store: list scoped PATs: %w", err)
	}
	tokens := make([]PersonalAccessTokenMetadata, len(rows))
	for index, row := range rows {
		tokens[index], err = validatePersonalAccessTokenMetadataProjection(
			row.TokenID, row.Subject, row.Scopes, row.ExpiresAt,
			row.Revoked, row.ProjectionVersion,
		)
		if err != nil {
			return nil, err
		}
	}
	return tokens, nil
}

// IsPersonalAccessTokenExists recognizes duplicate PAT creation.
func IsPersonalAccessTokenExists(err error) bool {
	return errors.Is(err, errPersonalAccessTokenExists)
}

// PersonalAccessTokenManagementEventTypes returns management-owned PAT events.
func PersonalAccessTokenManagementEventTypes() []string {
	return []string{
		personalAccessTokenMintedEventType,
		personalAccessTokenUpdatedEventType,
		personalAccessTokenDeletedEventType,
	}
}

func personalAccessTokenEvent(tokenID, eventType string, payload []byte) Event {
	return Event{
		StreamType:     personalAccessTokenStreamType,
		StreamID:       tokenID,
		EventType:      eventType,
		PayloadVersion: personalAccessTokenPayloadVersion,
		Payload:        payload,
	}
}

func canonicalPATID(tokenID string) (string, error) {
	if err := validate.ULIDPathID(tokenID); err != nil {
		return "", fmt.Errorf("store: PAT ID is invalid: %w", err)
	}
	return strings.ToUpper(tokenID), nil
}

func validatePATSubject(subject string) error {
	if len(subject) == 0 || len(subject) > maxPATSubjectBytes ||
		!utf8.ValidString(subject) || strings.ContainsRune(subject, '\x00') {
		return errors.New("store: PAT subject is invalid")
	}
	return nil
}

func validatePATScopes(scopes []string) error {
	if len(scopes) == 0 || len(scopes) > maxPATScopes {
		return errors.New("store: PAT scopes are invalid")
	}
	for index, scope := range scopes {
		if !validPATScope(scope) || index > 0 && scopes[index-1] >= scope {
			return errors.New("store: PAT scopes are invalid")
		}
	}
	return nil
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

func validatePATExpiry(expiresAt time.Time) error {
	if expiresAt.IsZero() || expiresAt.Unix() <= 0 {
		return errors.New("store: PAT expiry is invalid")
	}
	return nil
}

func personalAccessTokenEventDefinitions() map[string]eventDefinition {
	return map[string]eventDefinition{
		personalAccessTokenMintedEventType: {
			PayloadVersion: personalAccessTokenPayloadVersion,
			PayloadType:    personalAccessTokenMintedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(personalAccessTokenMintedPayload{
					Subject:   "01K0QJ3E5E8R4M0D8EV3Y4N6J8",
					Scopes:    []string{"actions.read", "devices.write"},
					TokenHash: make([]byte, sha256.Size),
					ExpiresAt: time.Date(2031, time.February, 3, 4, 5, 6, 0, time.UTC),
				})
			},
			Projector: projectPersonalAccessTokenMint,
		},
		personalAccessTokenRevokedEventType: {
			PayloadVersion: personalAccessTokenPayloadVersion,
			PayloadType:    personalAccessTokenRevokedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(personalAccessTokenRevokedPayload{})
			},
			Projector: projectPersonalAccessTokenRevocation,
		},
		personalAccessTokenUpdatedEventType: {
			PayloadVersion: personalAccessTokenPayloadVersion,
			PayloadType:    personalAccessTokenUpdatedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(personalAccessTokenUpdatedPayload{
					Subject:   "01K0QJ3E5E8R4M0D8EV3Y4N6J8",
					Scopes:    []string{"audit.read"},
					ExpiresAt: time.Date(2032, time.March, 4, 5, 6, 7, 0, time.UTC),
					Revoked:   true,
				})
			},
			Projector: projectPersonalAccessTokenUpdate,
		},
		personalAccessTokenDeletedEventType: {
			PayloadVersion: personalAccessTokenPayloadVersion,
			PayloadType:    personalAccessTokenDeletedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(personalAccessTokenDeletedPayload{})
			},
			Projector: projectPersonalAccessTokenDelete,
		},
	}
}

func personalAccessTokenGoldenCorpus() map[string]goldenEvent {
	return map[string]goldenEvent{
		personalAccessTokenMintedEventType: {
			PayloadVersion: personalAccessTokenPayloadVersion,
			Payload: []byte(
				`{"subject":"01K0QJ3E5E8R4M0D8EV3Y4N6J8","scopes":["actions.read","devices.write"],"token_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","expires_at":"2031-02-03T04:05:06Z"}`,
			),
		},
		personalAccessTokenRevokedEventType: {
			PayloadVersion: personalAccessTokenPayloadVersion,
			Payload:        []byte(`{}`),
		},
		personalAccessTokenUpdatedEventType: {
			PayloadVersion: personalAccessTokenPayloadVersion,
			Payload:        []byte(`{"subject":"01K0QJ3E5E8R4M0D8EV3Y4N6J8","scopes":["audit.read"],"expires_at":"2032-03-04T05:06:07Z","revoked":true}`),
		},
		personalAccessTokenDeletedEventType: {
			PayloadVersion: personalAccessTokenPayloadVersion,
			Payload:        []byte(`{}`),
		},
	}
}

func projectPersonalAccessTokenMint(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion != 1 {
		return fmt.Errorf(
			"store: PAT mint must be stream version 1, got %d: %w",
			event.StreamVersion,
			errPersonalAccessTokenExists,
		)
	}
	payload, err := decodeEventPayload[personalAccessTokenMintedPayload](
		event,
		personalAccessTokenPayloadVersion,
	)
	if err != nil {
		return err
	}
	if err := validatePATSubject(payload.Subject); err != nil {
		return err
	}
	if err := validatePATScopes(payload.Scopes); err != nil {
		return err
	}
	if len(payload.TokenHash) != sha256.Size {
		return errors.New("store: PAT mint payload has an invalid hash")
	}
	if err := validatePATExpiry(payload.ExpiresAt); err != nil {
		return err
	}
	affected, err := generated.New(tx).InsertPersonalAccessToken(
		ctx,
		generated.InsertPersonalAccessTokenParams{
			TokenID:           event.StreamID,
			Subject:           payload.Subject,
			Scopes:            payload.Scopes,
			TokenHash:         payload.TokenHash,
			ExpiresAt:         payload.ExpiresAt,
			ProjectionVersion: event.StreamVersion,
			UpdatedAt:         event.CreatedAt,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project PAT mint: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: PAT mint affected %d tokens; want one", affected)
	}
	return nil
}

func projectPersonalAccessTokenRevocation(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: PAT revocation requires a prior mint")
	}
	if _, err := decodeEventPayload[personalAccessTokenRevokedPayload](
		event,
		personalAccessTokenPayloadVersion,
	); err != nil {
		return err
	}
	queries := generated.New(tx)
	current, err := queries.GetPersonalAccessTokenByID(ctx, event.StreamID)
	if err != nil {
		if IsNotFound(err) {
			return errors.New("store: PAT revocation requires a prior mint")
		}
		return fmt.Errorf("store: inspect PAT before revocation: %w", err)
	}
	if current.Revoked {
		return errors.New("store: PAT is already revoked")
	}
	if current.ProjectionVersion != event.StreamVersion-1 {
		return errors.New("store: PAT projection version is inconsistent")
	}
	affected, err := queries.ProjectPersonalAccessTokenRevocation(
		ctx,
		generated.ProjectPersonalAccessTokenRevocationParams{
			ProjectionVersion: event.StreamVersion,
			UpdatedAt:         event.CreatedAt,
			TokenID:           event.StreamID,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project PAT revocation: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: PAT revocation affected %d tokens; want one", affected)
	}
	return nil
}

func projectPersonalAccessTokenUpdate(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: PAT update requires a prior mint")
	}
	payload, err := decodeEventPayload[personalAccessTokenUpdatedPayload](
		event,
		personalAccessTokenPayloadVersion,
	)
	if err != nil {
		return err
	}
	if err := validatePATSubject(payload.Subject); err != nil {
		return err
	}
	if err := validatePATScopes(payload.Scopes); err != nil {
		return err
	}
	if err := validatePATExpiry(payload.ExpiresAt); err != nil {
		return err
	}
	current, err := generated.New(tx).GetPersonalAccessTokenByID(ctx, event.StreamID)
	if err != nil {
		return fmt.Errorf("store: read PAT before update: %w", err)
	}
	if current.Subject != payload.Subject ||
		current.ProjectionVersion != event.StreamVersion-1 ||
		current.Revoked && !payload.Revoked {
		return errors.New("store: PAT update conflicts with the current projection")
	}
	affected, err := generated.New(tx).ReplacePersonalAccessTokenMetadata(
		ctx,
		generated.ReplacePersonalAccessTokenMetadataParams{
			Scopes:                    payload.Scopes,
			ExpiresAt:                 payload.ExpiresAt,
			Revoked:                   payload.Revoked,
			ProjectionVersion:         event.StreamVersion,
			UpdatedAt:                 event.CreatedAt,
			TokenID:                   event.StreamID,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project PAT update: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: PAT update affected %d tokens; want one", affected)
	}
	return nil
}

func projectPersonalAccessTokenDelete(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: PAT deletion requires a prior mint")
	}
	if _, err := decodeEventPayload[personalAccessTokenDeletedPayload](
		event,
		personalAccessTokenPayloadVersion,
	); err != nil {
		return err
	}
	affected, err := generated.New(tx).DeletePersonalAccessTokenProjection(
		ctx,
		generated.DeletePersonalAccessTokenProjectionParams{
			TokenID:                   event.StreamID,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project PAT deletion: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: PAT deletion affected %d tokens; want one", affected)
	}
	return nil
}

func personalAccessTokenFromHashRow(
	row generated.GetPersonalAccessTokenByHashRow,
) (PersonalAccessToken, error) {
	return validatePersonalAccessTokenProjection(
		row.TokenID,
		row.Subject,
		row.Scopes,
		row.TokenHash,
		row.ExpiresAt,
		row.Revoked,
		row.ProjectionVersion,
	)
}

func personalAccessTokenFromIDRow(
	row generated.GetPersonalAccessTokenByIDRow,
) (PersonalAccessToken, error) {
	return validatePersonalAccessTokenProjection(
		row.TokenID,
		row.Subject,
		row.Scopes,
		row.TokenHash,
		row.ExpiresAt,
		row.Revoked,
		row.ProjectionVersion,
	)
}

func validatePersonalAccessTokenProjection(
	tokenID string,
	subject string,
	scopes []string,
	tokenHash []byte,
	expiresAt time.Time,
	revoked bool,
	projectionVersion int64,
) (PersonalAccessToken, error) {
	if _, err := canonicalPATID(tokenID); err != nil {
		return PersonalAccessToken{}, errors.New("store: PAT projection has an invalid token ID")
	}
	if err := validatePATSubject(subject); err != nil {
		return PersonalAccessToken{}, fmt.Errorf("store: invalid PAT projection: %w", err)
	}
	if err := validatePATScopes(scopes); err != nil {
		return PersonalAccessToken{}, fmt.Errorf("store: invalid PAT projection: %w", err)
	}
	if len(tokenHash) != sha256.Size {
		return PersonalAccessToken{}, errors.New("store: PAT projection has an invalid hash")
	}
	if err := validatePATExpiry(expiresAt); err != nil {
		return PersonalAccessToken{}, fmt.Errorf("store: invalid PAT projection: %w", err)
	}
	if projectionVersion < 1 {
		return PersonalAccessToken{}, errors.New("store: PAT projection has an invalid version")
	}
	token := PersonalAccessToken{
		TokenID:           tokenID,
		Subject:           subject,
		Scopes:            slices.Clone(scopes),
		ExpiresAt:         expiresAt.UTC(),
		Revoked:           revoked,
		ProjectionVersion: projectionVersion,
	}
	copy(token.Hash[:], tokenHash)
	return token, nil
}

func validatePersonalAccessTokenMetadataProjection(
	tokenID string,
	subject string,
	scopes []string,
	expiresAt time.Time,
	revoked bool,
	projectionVersion int64,
) (PersonalAccessTokenMetadata, error) {
	if _, err := canonicalPATID(tokenID); err != nil {
		return PersonalAccessTokenMetadata{}, errors.New("store: PAT metadata has an invalid token ID")
	}
	if err := validatePATSubject(subject); err != nil {
		return PersonalAccessTokenMetadata{}, fmt.Errorf("store: invalid PAT metadata: %w", err)
	}
	if err := validatePATScopes(scopes); err != nil {
		return PersonalAccessTokenMetadata{}, fmt.Errorf("store: invalid PAT metadata: %w", err)
	}
	if err := validatePATExpiry(expiresAt); err != nil {
		return PersonalAccessTokenMetadata{}, fmt.Errorf("store: invalid PAT metadata: %w", err)
	}
	if projectionVersion < 1 {
		return PersonalAccessTokenMetadata{}, errors.New("store: PAT metadata has an invalid version")
	}
	return PersonalAccessTokenMetadata{
		TokenID:           tokenID,
		Subject:           subject,
		Scopes:            slices.Clone(scopes),
		ExpiresAt:         expiresAt.UTC(),
		Revoked:           revoked,
		ProjectionVersion: projectionVersion,
	}, nil
}

func resetPersonalAccessTokens(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetPersonalAccessTokens(ctx); err != nil {
		return fmt.Errorf("store: reset PATs: %w", err)
	}
	return nil
}
