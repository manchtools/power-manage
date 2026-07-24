package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/manchtools/power-manage/sdk/ulidx"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	scimProviderStreamType                  = "scim-provider"
	scimGroupStreamType                     = "scim-group"
	scimProviderCreatedEventType            = "SCIMProviderCreated"
	scimProviderTokenRotatedEventType       = "SCIMProviderTokenRotated"
	scimProviderDisabledEventType           = "SCIMProviderDisabled"
	scimProviderDeletedEventType            = "SCIMProviderDeleted"
	scimIdentityLinkedEventType             = "SCIMIdentityLinked"
	scimIdentityUnlinkedEventType           = "SCIMIdentityUnlinked"
	scimUserDeprovisionedEventType          = "SCIMUserDeprovisioned"
	scimGroupCreatedEventType               = "SCIMGroupCreated"
	scimGroupUpdatedEventType               = "SCIMGroupUpdated"
	scimGroupMembershipsEventType           = "SCIMGroupMembershipsReplaced"
	scimGroupDeletedEventType               = "SCIMGroupDeleted"
	scimPayloadVersion                      = 1
	maxSCIMExternalIDBytes                  = 1024
	maxSCIMGroupDisplayNameBytes            = 512
	maxSCIMGroupMembers                     = 1000
	maxSCIMPageSize                   int32 = 1000
)

const (
	// SCIMProviderRebuildTarget is the provider-credential recovery target.
	SCIMProviderRebuildTarget = "scim-providers"
	// SCIMGroupRebuildTarget is the SCIM group recovery target.
	SCIMGroupRebuildTarget = "scim-groups"
)

var (
	// ErrSCIMInvalid identifies a rejected SCIM projection transition.
	ErrSCIMInvalid        = errors.New("store: invalid SCIM transition")
	errSCIMProviderExists = errors.New("store: SCIM provider already exists")
)

// SCIMProvider is one event-derived provider credential projection.
type SCIMProvider struct {
	Slug              string
	TokenHash         string
	Disabled          bool
	ProjectionVersion int64
}

// SCIMProviderMetadata is the verifier-free management projection.
type SCIMProviderMetadata struct {
	Slug              string
	Disabled          bool
	ProjectionVersion int64
}

// SCIMUser is one provider identity joined to its live user projection.
type SCIMUser struct {
	ProviderSlug      string
	ExternalID        string
	UserID            string
	Email             string
	ProjectionVersion int64
}

// SCIMGroup is one provider group and its current user membership.
type SCIMGroup struct {
	GroupID           string
	ProviderSlug      string
	ExternalID        string
	DisplayName       string
	Members           []string
	ProjectionVersion int64
}

type scimProviderPayload struct {
	ProviderSlug string `json:"provider_slug"`
	TokenHash    string `json:"token_hash,omitempty"`
}

type scimIdentityLinkedPayload struct {
	ProviderSlug string `json:"provider_slug"`
	ExternalID   string `json:"external_id"`
	Email        string `json:"email"`
}

type scimIdentityUnlinkedPayload struct {
	ProviderSlug string `json:"provider_slug"`
	ExternalID   string `json:"external_id"`
}

type scimUserDeprovisionedPayload struct{}

type scimGroupPayload struct {
	ProviderSlug string `json:"provider_slug"`
	ExternalID   string `json:"external_id"`
	DisplayName  string `json:"display_name"`
}

type scimGroupMembershipsPayload struct {
	UserIDs []string `json:"user_ids"`
}

type scimGroupDeletedPayload struct {
	ProviderSlug string `json:"provider_slug"`
}

// SCIMProviderCreatedEvent stores only the bcrypt verifier for a new provider.
func SCIMProviderCreatedEvent(providerSlug string, tokenHash []byte) (Event, error) {
	return newSCIMProviderEvent(providerSlug, tokenHash, scimProviderCreatedEventType)
}

// SCIMProviderTokenRotatedEvent replaces one provider's bcrypt verifier.
func SCIMProviderTokenRotatedEvent(providerSlug string, tokenHash []byte) (Event, error) {
	return newSCIMProviderEvent(providerSlug, tokenHash, scimProviderTokenRotatedEventType)
}

// SCIMProviderDisabledEvent disables one provider without retaining a bearer.
func SCIMProviderDisabledEvent(providerSlug string) (Event, error) {
	if !validProviderSlug(providerSlug) {
		return Event{}, errors.New("store: SCIM provider slug is invalid")
	}
	payload, err := json.Marshal(scimProviderPayload{ProviderSlug: providerSlug})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode SCIM provider disable: %w", err)
	}
	return scimProviderEvent(providerSlug, scimProviderDisabledEventType, payload)
}

// SCIMProviderDeletedEvent removes one provider credential projection.
func SCIMProviderDeletedEvent(providerSlug string) (Event, error) {
	if !validProviderSlug(providerSlug) {
		return Event{}, errors.New("store: SCIM provider slug is invalid")
	}
	payload, err := json.Marshal(scimProviderPayload{ProviderSlug: providerSlug})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode SCIM provider deletion: %w", err)
	}
	return scimProviderEvent(providerSlug, scimProviderDeletedEventType, payload)
}

func newSCIMProviderEvent(providerSlug string, tokenHash []byte, eventType string) (Event, error) {
	if !validProviderSlug(providerSlug) {
		return Event{}, errors.New("store: SCIM provider slug is invalid")
	}
	if err := validateSCIMTokenHash(tokenHash); err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(scimProviderPayload{
		ProviderSlug: providerSlug,
		TokenHash:    string(tokenHash),
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode SCIM provider credential: %w", err)
	}
	return scimProviderEvent(providerSlug, eventType, payload)
}

func scimProviderEvent(providerSlug, eventType string, payload []byte) (Event, error) {
	streamID, err := scimProviderStreamID(providerSlug)
	if err != nil {
		return Event{}, err
	}
	return Event{
		StreamType:     scimProviderStreamType,
		StreamID:       streamID,
		EventType:      eventType,
		PayloadVersion: scimPayloadVersion,
		Payload:        payload,
	}, nil
}

func scimProviderStreamID(providerSlug string) (string, error) {
	digest := sha256.Sum256([]byte(providerSlug))
	streamID, err := ulidx.NewWithReader(time.Unix(0, 0), bytes.NewReader(digest[:10]))
	if err != nil {
		return "", fmt.Errorf("store: derive SCIM provider stream ID: %w", err)
	}
	return streamID, nil
}

// SCIMIdentityLinkedEvent links one provider identity to a live user stream.
func SCIMIdentityLinkedEvent(
	userID string,
	providerSlug string,
	externalID string,
	email string,
) (Event, error) {
	userID, err := canonicalUserID(userID)
	if err != nil {
		return Event{}, err
	}
	if !validProviderSlug(providerSlug) || !validBoundedText(externalID, maxSCIMExternalIDBytes) {
		return Event{}, errors.New("store: SCIM identity is invalid")
	}
	email, err = CanonicalUserEmail(email)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(scimIdentityLinkedPayload{
		ProviderSlug: providerSlug,
		ExternalID:   externalID,
		Email:        email,
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode SCIM identity link: %w", err)
	}
	return userEvent(userID, scimIdentityLinkedEventType, payload), nil
}

// SCIMIdentityUnlinkedEvent removes one provider identity from a user stream.
func SCIMIdentityUnlinkedEvent(userID, providerSlug, externalID string) (Event, error) {
	userID, err := canonicalUserID(userID)
	if err != nil {
		return Event{}, err
	}
	if !validProviderSlug(providerSlug) || !validBoundedText(externalID, maxSCIMExternalIDBytes) {
		return Event{}, errors.New("store: SCIM identity is invalid")
	}
	payload, err := json.Marshal(scimIdentityUnlinkedPayload{
		ProviderSlug: providerSlug,
		ExternalID:   externalID,
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode SCIM identity unlink: %w", err)
	}
	return userEvent(userID, scimIdentityUnlinkedEventType, payload), nil
}

// SCIMUserDeprovisionedEvent records terminal last-link deprovisioning.
func SCIMUserDeprovisionedEvent(userID string) (Event, error) {
	userID, err := canonicalUserID(userID)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(scimUserDeprovisionedPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode SCIM user deprovision: %w", err)
	}
	return userEvent(userID, scimUserDeprovisionedEventType, payload), nil
}

// SCIMGroupCreatedEvent creates one provider-owned group stream.
func SCIMGroupCreatedEvent(
	groupID string,
	providerSlug string,
	externalID string,
	displayName string,
) (Event, error) {
	return newSCIMGroupEvent(
		groupID,
		providerSlug,
		externalID,
		displayName,
		scimGroupCreatedEventType,
	)
}

// SCIMGroupUpdatedEvent replaces one provider-owned group's attributes.
func SCIMGroupUpdatedEvent(
	groupID string,
	providerSlug string,
	externalID string,
	displayName string,
) (Event, error) {
	return newSCIMGroupEvent(
		groupID,
		providerSlug,
		externalID,
		displayName,
		scimGroupUpdatedEventType,
	)
}

func newSCIMGroupEvent(
	groupID string,
	providerSlug string,
	externalID string,
	displayName string,
	eventType string,
) (Event, error) {
	groupID, err := canonicalUserID(groupID)
	if err != nil {
		return Event{}, errors.New("store: SCIM group ID is invalid")
	}
	if !validProviderSlug(providerSlug) ||
		!validBoundedText(externalID, maxSCIMExternalIDBytes) ||
		!validBoundedText(displayName, maxSCIMGroupDisplayNameBytes) {
		return Event{}, errors.New("store: SCIM group is invalid")
	}
	payload, err := json.Marshal(scimGroupPayload{
		ProviderSlug: providerSlug,
		ExternalID:   externalID,
		DisplayName:  displayName,
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode SCIM group: %w", err)
	}
	return Event{
		StreamType:     scimGroupStreamType,
		StreamID:       groupID,
		EventType:      eventType,
		PayloadVersion: scimPayloadVersion,
		Payload:        payload,
	}, nil
}

// SCIMGroupMembershipsReplacedEvent atomically replaces a group's user IDs.
func SCIMGroupMembershipsReplacedEvent(groupID string, userIDs []string) (Event, error) {
	groupID, err := canonicalUserID(groupID)
	if err != nil {
		return Event{}, errors.New("store: SCIM group ID is invalid")
	}
	if len(userIDs) > maxSCIMGroupMembers {
		return Event{}, errors.New("store: SCIM group membership is too large")
	}
	canonical := make([]string, len(userIDs))
	for index, userID := range userIDs {
		canonical[index], err = canonicalUserID(userID)
		if err != nil {
			return Event{}, errors.New("store: SCIM group member ID is invalid")
		}
	}
	slices.Sort(canonical)
	if len(slices.Compact(slices.Clone(canonical))) != len(canonical) {
		return Event{}, errors.New("store: SCIM group membership contains duplicates")
	}
	payload, err := json.Marshal(scimGroupMembershipsPayload{UserIDs: canonical})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode SCIM group membership: %w", err)
	}
	return Event{
		StreamType:     scimGroupStreamType,
		StreamID:       groupID,
		EventType:      scimGroupMembershipsEventType,
		PayloadVersion: scimPayloadVersion,
		Payload:        payload,
	}, nil
}

// SCIMGroupDeletedEvent deletes one provider-owned group.
func SCIMGroupDeletedEvent(groupID, providerSlug string) (Event, error) {
	groupID, err := canonicalUserID(groupID)
	if err != nil {
		return Event{}, errors.New("store: SCIM group ID is invalid")
	}
	if !validProviderSlug(providerSlug) {
		return Event{}, errors.New("store: SCIM provider slug is invalid")
	}
	payload, err := json.Marshal(scimGroupDeletedPayload{ProviderSlug: providerSlug})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode SCIM group delete: %w", err)
	}
	return Event{
		StreamType:     scimGroupStreamType,
		StreamID:       groupID,
		EventType:      scimGroupDeletedEventType,
		PayloadVersion: scimPayloadVersion,
		Payload:        payload,
	}, nil
}

// SCIMProvider reads one validated provider projection.
func (s *Store) SCIMProvider(ctx context.Context, providerSlug string) (SCIMProvider, error) {
	if s == nil || s.pool == nil {
		return SCIMProvider{}, errors.New("store: nil store")
	}
	if ctx == nil || !validProviderSlug(providerSlug) {
		return SCIMProvider{}, errors.New("store: invalid SCIM provider lookup")
	}
	row, err := generated.New(s.pool).GetSCIMProvider(ctx, providerSlug)
	if err != nil {
		return SCIMProvider{}, fmt.Errorf("store: read SCIM provider: %w", err)
	}
	return validateSCIMProviderProjection(
		row.ProviderSlug,
		row.TokenHash,
		row.Disabled,
		row.ProjectionVersion,
	)
}

// SCIMProviderMetadataBySlug returns verifier-free management metadata.
func (s *Store) SCIMProviderMetadataBySlug(
	ctx context.Context,
	providerSlug string,
) (SCIMProviderMetadata, error) {
	if s == nil || s.pool == nil || ctx == nil || !validProviderSlug(providerSlug) {
		return SCIMProviderMetadata{}, errors.New("store: invalid SCIM provider metadata lookup")
	}
	row, err := generated.New(s.pool).GetSCIMProviderMetadata(ctx, providerSlug)
	if err != nil {
		return SCIMProviderMetadata{}, fmt.Errorf("store: read SCIM provider metadata: %w", err)
	}
	return validateSCIMProviderMetadata(row.ProviderSlug, row.Disabled, row.ProjectionVersion)
}

// ListSCIMProviders returns one deterministic verifier-free metadata page.
func (s *Store) ListSCIMProviders(ctx context.Context, limit int32) ([]SCIMProviderMetadata, error) {
	if s == nil || s.pool == nil || ctx == nil || limit < 1 || limit > 200 {
		return nil, errors.New("store: invalid SCIM provider list")
	}
	rows, err := generated.New(s.pool).ListSCIMProviders(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list SCIM providers: %w", err)
	}
	providers := make([]SCIMProviderMetadata, len(rows))
	for index, row := range rows {
		providers[index], err = validateSCIMProviderMetadata(
			row.ProviderSlug,
			row.Disabled,
			row.ProjectionVersion,
		)
		if err != nil {
			return nil, err
		}
	}
	return providers, nil
}

func validateSCIMProviderMetadata(
	providerSlug string,
	disabled bool,
	projectionVersion int64,
) (SCIMProviderMetadata, error) {
	if !validProviderSlug(providerSlug) || projectionVersion < 1 {
		return SCIMProviderMetadata{}, errors.New("store: SCIM provider metadata is invalid")
	}
	return SCIMProviderMetadata{
		Slug:              providerSlug,
		Disabled:          disabled,
		ProjectionVersion: projectionVersion,
	}, nil
}

// SCIMProviderManagementEventTypes returns the exact management mutation set.
func SCIMProviderManagementEventTypes() []string {
	return []string{
		scimProviderCreatedEventType,
		scimProviderTokenRotatedEventType,
		scimProviderDisabledEventType,
		scimProviderDeletedEventType,
	}
}

// IsSCIMProviderExists recognizes duplicate provider creation.
func IsSCIMProviderExists(err error) bool {
	return errors.Is(err, errSCIMProviderExists)
}

func validateSCIMProviderProjection(
	slug string,
	tokenHash []byte,
	disabled bool,
	version int64,
) (SCIMProvider, error) {
	if !validProviderSlug(slug) ||
		validateSCIMTokenHash(tokenHash) != nil ||
		version <= 0 {
		return SCIMProvider{}, errors.New("store: SCIM provider projection is invalid")
	}
	return SCIMProvider{
		Slug:              slug,
		TokenHash:         string(tokenHash),
		Disabled:          disabled,
		ProjectionVersion: version,
	}, nil
}

// SCIMUser reads one provider-linked user by canonical user ID.
func (s *Store) SCIMUser(ctx context.Context, providerSlug, userID string) (SCIMUser, error) {
	if s == nil || s.pool == nil {
		return SCIMUser{}, errors.New("store: nil store")
	}
	if ctx == nil || !validProviderSlug(providerSlug) {
		return SCIMUser{}, errors.New("store: invalid SCIM user lookup")
	}
	userID, err := canonicalUserID(userID)
	if err != nil {
		return SCIMUser{}, err
	}
	row, err := generated.New(s.pool).GetSCIMIdentityByUser(
		ctx,
		generated.GetSCIMIdentityByUserParams{
			ProviderSlug: providerSlug,
			UserID:       userID,
		},
	)
	if err != nil {
		return SCIMUser{}, fmt.Errorf("store: read SCIM user: %w", err)
	}
	user, err := s.UserByID(ctx, userID)
	if err != nil {
		return SCIMUser{}, err
	}
	return validateSCIMUser(
		row.ProviderSlug,
		row.ExternalID,
		row.UserID,
		row.Email,
		user.ProjectionVersion,
	)
}

// SCIMUsers lists a bounded provider user page, optionally filtered by email.
func (s *Store) SCIMUsers(
	ctx context.Context,
	providerSlug string,
	email string,
	limit int32,
) ([]SCIMUser, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("store: nil store")
	}
	if ctx == nil || !validProviderSlug(providerSlug) || limit <= 0 || limit > maxSCIMPageSize {
		return nil, errors.New("store: invalid SCIM user list")
	}
	var err error
	if email != "" {
		email, err = CanonicalUserEmail(email)
		if err != nil {
			return nil, err
		}
	}
	rows, err := generated.New(s.pool).ListSCIMUsers(
		ctx,
		generated.ListSCIMUsersParams{
			ProviderSlug: providerSlug,
			Email:        email,
			PageSize:     limit,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("store: list SCIM users: %w", err)
	}
	users := make([]SCIMUser, 0, len(rows))
	for _, row := range rows {
		user, err := validateSCIMUser(
			row.ProviderSlug,
			row.ExternalID,
			row.UserID,
			row.Email,
			row.ProjectionVersion,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func validateSCIMUser(
	providerSlug, externalID, userID, email string,
	version int64,
) (SCIMUser, error) {
	canonicalID, err := canonicalUserID(userID)
	if err != nil || canonicalID != userID ||
		!validProviderSlug(providerSlug) ||
		!validBoundedText(externalID, maxSCIMExternalIDBytes) {
		return SCIMUser{}, errors.New("store: SCIM user projection is invalid")
	}
	canonicalEmail, err := CanonicalUserEmail(email)
	if err != nil || canonicalEmail != email || version <= 1 {
		return SCIMUser{}, errors.New("store: SCIM user projection is invalid")
	}
	return SCIMUser{
		ProviderSlug:      providerSlug,
		ExternalID:        externalID,
		UserID:            userID,
		Email:             email,
		ProjectionVersion: version,
	}, nil
}

// UserIdentityLinkCount counts OIDC and SCIM links for one live user.
func (s *Store) UserIdentityLinkCount(ctx context.Context, userID string) (int64, error) {
	if s == nil || s.pool == nil {
		return 0, errors.New("store: nil store")
	}
	if ctx == nil {
		return 0, errors.New("store: nil identity-link context")
	}
	userID, err := canonicalUserID(userID)
	if err != nil {
		return 0, err
	}
	count, err := generated.New(s.pool).CountUserIdentityLinks(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("store: count user identity links: %w", err)
	}
	if count < 0 {
		return 0, errors.New("store: user identity link count is invalid")
	}
	return count, nil
}

// SCIMGroup reads one provider-owned group with sorted membership.
func (s *Store) SCIMGroup(ctx context.Context, providerSlug, groupID string) (SCIMGroup, error) {
	if s == nil || s.pool == nil {
		return SCIMGroup{}, errors.New("store: nil store")
	}
	if ctx == nil || !validProviderSlug(providerSlug) {
		return SCIMGroup{}, errors.New("store: invalid SCIM group lookup")
	}
	groupID, err := canonicalUserID(groupID)
	if err != nil {
		return SCIMGroup{}, errors.New("store: SCIM group ID is invalid")
	}
	row, err := generated.New(s.pool).GetSCIMGroup(
		ctx,
		generated.GetSCIMGroupParams{
			ProviderSlug: providerSlug,
			GroupID:      groupID,
		},
	)
	if err != nil {
		return SCIMGroup{}, fmt.Errorf("store: read SCIM group: %w", err)
	}
	members, err := generated.New(s.pool).ListSCIMGroupMembers(ctx, groupID)
	if err != nil {
		return SCIMGroup{}, fmt.Errorf("store: read SCIM group members: %w", err)
	}
	return validateSCIMGroup(
		row.GroupID,
		row.ProviderSlug,
		row.ExternalID,
		row.DisplayName,
		members,
		row.ProjectionVersion,
	)
}

// SCIMGroups lists a bounded provider group page.
func (s *Store) SCIMGroups(
	ctx context.Context,
	providerSlug string,
	limit int32,
) ([]SCIMGroup, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("store: nil store")
	}
	if ctx == nil || !validProviderSlug(providerSlug) || limit <= 0 || limit > maxSCIMPageSize {
		return nil, errors.New("store: invalid SCIM group list")
	}
	rows, err := generated.New(s.pool).ListSCIMGroups(
		ctx,
		generated.ListSCIMGroupsParams{ProviderSlug: providerSlug, PageSize: limit},
	)
	if err != nil {
		return nil, fmt.Errorf("store: list SCIM groups: %w", err)
	}
	groups := make([]SCIMGroup, 0, len(rows))
	queries := generated.New(s.pool)
	for _, row := range rows {
		members, err := queries.ListSCIMGroupMembers(ctx, row.GroupID)
		if err != nil {
			return nil, fmt.Errorf("store: list SCIM group members: %w", err)
		}
		group, err := validateSCIMGroup(
			row.GroupID,
			row.ProviderSlug,
			row.ExternalID,
			row.DisplayName,
			members,
			row.ProjectionVersion,
		)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func validateSCIMGroup(
	groupID, providerSlug, externalID, displayName string,
	members []string,
	version int64,
) (SCIMGroup, error) {
	canonicalID, err := canonicalUserID(groupID)
	if err != nil || canonicalID != groupID ||
		!validProviderSlug(providerSlug) ||
		!validBoundedText(externalID, maxSCIMExternalIDBytes) ||
		!validBoundedText(displayName, maxSCIMGroupDisplayNameBytes) ||
		version <= 0 || len(members) > maxSCIMGroupMembers {
		return SCIMGroup{}, errors.New("store: SCIM group projection is invalid")
	}
	for _, member := range members {
		canonicalMember, err := canonicalUserID(member)
		if err != nil || canonicalMember != member {
			return SCIMGroup{}, errors.New("store: SCIM group member projection is invalid")
		}
	}
	return SCIMGroup{
		GroupID:           groupID,
		ProviderSlug:      providerSlug,
		ExternalID:        externalID,
		DisplayName:       displayName,
		Members:           slices.Clone(members),
		ProjectionVersion: version,
	}, nil
}

func validateSCIMTokenHash(tokenHash []byte) error {
	cost, err := bcrypt.Cost(tokenHash)
	if err != nil || cost < bcrypt.MinCost {
		return errors.New("store: SCIM token hash is invalid")
	}
	return nil
}

func scimProviderEventDefinitions() map[string]eventDefinition {
	goldenHash := "$2a$04$kHv1WwSPQ7H5ET9eFkFQeOq7cYcxlMiwbmU3pZTU8x5fUXAwAHYAy"
	return map[string]eventDefinition{
		scimProviderCreatedEventType: {
			PayloadVersion: scimPayloadVersion,
			PayloadType:    scimProviderPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(scimProviderPayload{
					ProviderSlug: "corporate",
					TokenHash:    goldenHash,
				})
			},
			Projector: projectSCIMProviderCreated,
		},
		scimProviderTokenRotatedEventType: {
			PayloadVersion: scimPayloadVersion,
			PayloadType:    scimProviderPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(scimProviderPayload{
					ProviderSlug: "corporate",
					TokenHash:    goldenHash,
				})
			},
			Projector: projectSCIMProviderTokenRotated,
		},
		scimProviderDisabledEventType: {
			PayloadVersion: scimPayloadVersion,
			PayloadType:    scimProviderPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(scimProviderPayload{ProviderSlug: "corporate"})
			},
			Projector: projectSCIMProviderDisabled,
		},
		scimProviderDeletedEventType: {
			PayloadVersion: scimPayloadVersion,
			PayloadType:    scimProviderPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(scimProviderPayload{ProviderSlug: "corporate"})
			},
			Projector: projectSCIMProviderDeleted,
		},
	}
}

func scimProviderGoldenCorpus() map[string]goldenEvent {
	const hash = "$2a$04$kHv1WwSPQ7H5ET9eFkFQeOq7cYcxlMiwbmU3pZTU8x5fUXAwAHYAy"
	return map[string]goldenEvent{
		scimProviderCreatedEventType: {
			PayloadVersion: scimPayloadVersion,
			Payload: []byte(
				`{"provider_slug":"corporate","token_hash":"` + hash + `"}`,
			),
		},
		scimProviderTokenRotatedEventType: {
			PayloadVersion: scimPayloadVersion,
			Payload: []byte(
				`{"provider_slug":"corporate","token_hash":"` + hash + `"}`,
			),
		},
		scimProviderDisabledEventType: {
			PayloadVersion: scimPayloadVersion,
			Payload:        []byte(`{"provider_slug":"corporate"}`),
		},
		scimProviderDeletedEventType: {
			PayloadVersion: scimPayloadVersion,
			Payload:        []byte(`{"provider_slug":"corporate"}`),
		},
	}
}

func scimUserEventDefinitions() map[string]eventDefinition {
	return map[string]eventDefinition{
		scimIdentityLinkedEventType: {
			PayloadVersion: scimPayloadVersion,
			PayloadType:    scimIdentityLinkedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(scimIdentityLinkedPayload{
					ProviderSlug: "corporate",
					ExternalID:   "external-user-1",
					Email:        "person@example.test",
				})
			},
			Projector: projectSCIMIdentityLinked,
		},
		scimIdentityUnlinkedEventType: {
			PayloadVersion: scimPayloadVersion,
			PayloadType:    scimIdentityUnlinkedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(scimIdentityUnlinkedPayload{
					ProviderSlug: "corporate",
					ExternalID:   "external-user-1",
				})
			},
			Projector: projectSCIMIdentityUnlinked,
		},
	}
}

func scimUserGoldenCorpus() map[string]goldenEvent {
	return map[string]goldenEvent{
		scimIdentityLinkedEventType: {
			PayloadVersion: scimPayloadVersion,
			Payload: []byte(
				`{"provider_slug":"corporate","external_id":"external-user-1","email":"person@example.test"}`,
			),
		},
		scimIdentityUnlinkedEventType: {
			PayloadVersion: scimPayloadVersion,
			Payload: []byte(
				`{"provider_slug":"corporate","external_id":"external-user-1"}`,
			),
		},
	}
}

func scimGroupEventDefinitions() map[string]eventDefinition {
	groupPayload := func() ([]byte, error) {
		return json.Marshal(scimGroupPayload{
			ProviderSlug: "corporate",
			ExternalID:   "external-group-1",
			DisplayName:  "Operators",
		})
	}
	return map[string]eventDefinition{
		scimGroupCreatedEventType: {
			PayloadVersion: scimPayloadVersion,
			PayloadType:    scimGroupPayload{},
			GoldenPayload:  groupPayload,
			Projector:      projectSCIMGroupCreated,
		},
		scimGroupUpdatedEventType: {
			PayloadVersion: scimPayloadVersion,
			PayloadType:    scimGroupPayload{},
			GoldenPayload:  groupPayload,
			Projector:      projectSCIMGroupUpdated,
		},
		scimGroupMembershipsEventType: {
			PayloadVersion: scimPayloadVersion,
			PayloadType:    scimGroupMembershipsPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(scimGroupMembershipsPayload{
					UserIDs: []string{"01J00000000000000000000001"},
				})
			},
			Projector: projectSCIMGroupMembershipsReplaced,
		},
		scimGroupDeletedEventType: {
			PayloadVersion: scimPayloadVersion,
			PayloadType:    scimGroupDeletedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(scimGroupDeletedPayload{ProviderSlug: "corporate"})
			},
			Projector: projectSCIMGroupDeleted,
		},
	}
}

func scimGroupGoldenCorpus() map[string]goldenEvent {
	const group = `{"provider_slug":"corporate","external_id":"external-group-1","display_name":"Operators"}`
	return map[string]goldenEvent{
		scimGroupCreatedEventType: {
			PayloadVersion: scimPayloadVersion,
			Payload:        []byte(group),
		},
		scimGroupUpdatedEventType: {
			PayloadVersion: scimPayloadVersion,
			Payload:        []byte(group),
		},
		scimGroupMembershipsEventType: {
			PayloadVersion: scimPayloadVersion,
			Payload:        []byte(`{"user_ids":["01J00000000000000000000001"]}`),
		},
		scimGroupDeletedEventType: {
			PayloadVersion: scimPayloadVersion,
			Payload:        []byte(`{"provider_slug":"corporate"}`),
		},
	}
}

func projectSCIMProviderCreated(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion < 1 {
		return errSCIMProviderExists
	}
	payload, err := decodeEventPayload[scimProviderPayload](event, scimPayloadVersion)
	if err != nil {
		return err
	}
	if err := validateSCIMProviderEvent(event, payload, true); err != nil {
		return err
	}
	affected, err := generated.New(tx).InsertSCIMProvider(
		ctx,
		generated.InsertSCIMProviderParams{
			ProviderSlug:      payload.ProviderSlug,
			TokenHash:         []byte(payload.TokenHash),
			ProjectionVersion: event.StreamVersion,
			UpdatedAt:         event.CreatedAt,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project SCIM provider creation: %w", err)
	}
	if affected != 1 {
		return errSCIMProviderExists
	}
	return nil
}

func projectSCIMProviderTokenRotated(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: SCIM provider rotation requires a prior provider")
	}
	payload, err := decodeEventPayload[scimProviderPayload](event, scimPayloadVersion)
	if err != nil {
		return err
	}
	if err := validateSCIMProviderEvent(event, payload, true); err != nil {
		return err
	}
	affected, err := generated.New(tx).RotateSCIMProviderToken(
		ctx,
		generated.RotateSCIMProviderTokenParams{
			TokenHash:                 []byte(payload.TokenHash),
			ProjectionVersion:         event.StreamVersion,
			UpdatedAt:                 event.CreatedAt,
			ProviderSlug:              payload.ProviderSlug,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project SCIM provider rotation: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: SCIM provider rotation affected %d rows; want one", affected)
	}
	return nil
}

func projectSCIMProviderDisabled(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: SCIM provider disable requires a prior provider")
	}
	payload, err := decodeEventPayload[scimProviderPayload](event, scimPayloadVersion)
	if err != nil {
		return err
	}
	if err := validateSCIMProviderEvent(event, payload, false); err != nil {
		return err
	}
	affected, err := generated.New(tx).DisableSCIMProvider(
		ctx,
		generated.DisableSCIMProviderParams{
			ProjectionVersion:         event.StreamVersion,
			UpdatedAt:                 event.CreatedAt,
			ProviderSlug:              payload.ProviderSlug,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project SCIM provider disable: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: SCIM provider disable affected %d rows; want one", affected)
	}
	return nil
}

func projectSCIMProviderDeleted(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: SCIM provider deletion requires a prior provider")
	}
	payload, err := decodeEventPayload[scimProviderPayload](event, scimPayloadVersion)
	if err != nil {
		return err
	}
	if err := validateSCIMProviderEvent(event, payload, false); err != nil {
		return err
	}
	affected, err := generated.New(tx).DeleteSCIMProvider(
		ctx,
		generated.DeleteSCIMProviderParams{
			ProviderSlug:              payload.ProviderSlug,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project SCIM provider deletion: %w", err)
	}
	if affected != 1 {
		return errors.New("store: SCIM provider deletion conflicts with projection")
	}
	return nil
}

func validateSCIMProviderEvent(
	event PersistedEvent,
	payload scimProviderPayload,
	requireHash bool,
) error {
	if !validProviderSlug(payload.ProviderSlug) {
		return errors.New("store: SCIM provider slug is invalid")
	}
	streamID, err := scimProviderStreamID(payload.ProviderSlug)
	if err != nil || streamID != event.StreamID {
		return errors.New("store: SCIM provider stream ID is invalid")
	}
	if requireHash {
		return validateSCIMTokenHash([]byte(payload.TokenHash))
	}
	if payload.TokenHash != "" {
		return errors.New("store: SCIM provider disable contains a token hash")
	}
	return nil
}

func projectSCIMIdentityLinked(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: SCIM identity link requires a prior user")
	}
	userID, err := canonicalUserID(event.StreamID)
	if err != nil || userID != event.StreamID {
		return errors.New("store: SCIM identity stream ID is invalid")
	}
	payload, err := decodeEventPayload[scimIdentityLinkedPayload](event, scimPayloadVersion)
	if err != nil {
		return err
	}
	email, err := CanonicalUserEmail(payload.Email)
	if err != nil || email != payload.Email ||
		!validProviderSlug(payload.ProviderSlug) ||
		!validBoundedText(payload.ExternalID, maxSCIMExternalIDBytes) {
		return errors.New("store: SCIM identity link is invalid")
	}
	queries := generated.New(tx)
	user, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("store: SCIM identity link requires a prior user: %w", err)
	}
	if user.Email != email || user.ProjectionVersion != event.StreamVersion-1 {
		return errors.New("store: SCIM identity link user is inconsistent")
	}
	affected, err := queries.InsertSCIMIdentity(ctx, generated.InsertSCIMIdentityParams{
		ProviderSlug:      payload.ProviderSlug,
		ExternalID:        payload.ExternalID,
		UserID:            userID,
		Email:             email,
		ProjectionVersion: event.StreamVersion,
		UpdatedAt:         event.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("store: project SCIM identity link: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: SCIM identity link affected %d identities; want one", affected)
	}
	return advanceSCIMUser(ctx, queries, userID, email, event)
}

func projectSCIMIdentityUnlinked(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: SCIM identity unlink requires a prior user")
	}
	userID, err := canonicalUserID(event.StreamID)
	if err != nil || userID != event.StreamID {
		return errors.New("store: SCIM identity stream ID is invalid")
	}
	payload, err := decodeEventPayload[scimIdentityUnlinkedPayload](event, scimPayloadVersion)
	if err != nil {
		return err
	}
	if !validProviderSlug(payload.ProviderSlug) ||
		!validBoundedText(payload.ExternalID, maxSCIMExternalIDBytes) {
		return errors.New("store: SCIM identity unlink is invalid")
	}
	queries := generated.New(tx)
	user, err := queries.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("store: SCIM identity unlink requires a prior user: %w", err)
	}
	if user.ProjectionVersion != event.StreamVersion-1 {
		return errors.New("store: SCIM identity unlink user version is inconsistent")
	}
	affected, err := queries.DeleteSCIMIdentity(ctx, generated.DeleteSCIMIdentityParams{
		ProviderSlug: payload.ProviderSlug,
		ExternalID:   payload.ExternalID,
		UserID:       userID,
	})
	if err != nil {
		return fmt.Errorf("store: project SCIM identity unlink: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: SCIM identity unlink affected %d identities; want one", affected)
	}
	return advanceSCIMUser(ctx, queries, userID, user.Email, event)
}

func advanceSCIMUser(
	ctx context.Context,
	queries *generated.Queries,
	userID, email string,
	event PersistedEvent,
) error {
	affected, err := queries.AdvanceUserProjectionVersionForSCIM(
		ctx,
		generated.AdvanceUserProjectionVersionForSCIMParams{
			ProjectionVersion:         event.StreamVersion,
			UpdatedAt:                 event.CreatedAt,
			UserID:                    userID,
			Email:                     email,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: advance user after SCIM identity change: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: SCIM identity change affected %d users; want one", affected)
	}
	return nil
}

func projectSCIMGroupCreated(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion != 1 {
		return errors.New("store: SCIM group creation must be stream version one")
	}
	payload, err := decodeEventPayload[scimGroupPayload](event, scimPayloadVersion)
	if err != nil {
		return err
	}
	if err := validateSCIMGroupPayload(event.StreamID, payload); err != nil {
		return err
	}
	affected, err := generated.New(tx).InsertSCIMGroup(ctx, generated.InsertSCIMGroupParams{
		GroupID:           event.StreamID,
		ProviderSlug:      payload.ProviderSlug,
		ExternalID:        payload.ExternalID,
		DisplayName:       payload.DisplayName,
		ProjectionVersion: event.StreamVersion,
		UpdatedAt:         event.CreatedAt,
	})
	if err != nil {
		return fmt.Errorf("store: project SCIM group creation: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: SCIM group creation affected %d rows; want one", affected)
	}
	return nil
}

func projectSCIMGroupUpdated(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: SCIM group update requires a prior group")
	}
	payload, err := decodeEventPayload[scimGroupPayload](event, scimPayloadVersion)
	if err != nil {
		return err
	}
	if err := validateSCIMGroupPayload(event.StreamID, payload); err != nil {
		return err
	}
	affected, err := generated.New(tx).UpdateSCIMGroup(ctx, generated.UpdateSCIMGroupParams{
		ExternalID:                payload.ExternalID,
		DisplayName:               payload.DisplayName,
		ProjectionVersion:         event.StreamVersion,
		UpdatedAt:                 event.CreatedAt,
		GroupID:                   event.StreamID,
		ProviderSlug:              payload.ProviderSlug,
		PreviousProjectionVersion: event.StreamVersion - 1,
	})
	if err != nil {
		return fmt.Errorf("store: project SCIM group update: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: SCIM group update affected %d rows; want one", affected)
	}
	return nil
}

func projectSCIMGroupMembershipsReplaced(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: SCIM group membership requires a prior group")
	}
	payload, err := decodeEventPayload[scimGroupMembershipsPayload](event, scimPayloadVersion)
	if err != nil {
		return err
	}
	if len(payload.UserIDs) > maxSCIMGroupMembers ||
		!slices.IsSorted(payload.UserIDs) ||
		len(slices.Compact(slices.Clone(payload.UserIDs))) != len(payload.UserIDs) {
		return errors.New("store: SCIM group membership payload is invalid")
	}
	queries := generated.New(tx)
	if err := queries.DeleteSCIMGroupMembers(ctx, event.StreamID); err != nil {
		return fmt.Errorf("store: clear SCIM group members: %w", err)
	}
	for _, userID := range payload.UserIDs {
		canonicalID, err := canonicalUserID(userID)
		if err != nil || canonicalID != userID {
			return errors.New("store: SCIM group member ID is invalid")
		}
		affected, err := queries.InsertSCIMGroupMember(
			ctx,
			generated.InsertSCIMGroupMemberParams{
				GroupID:           event.StreamID,
				ProjectionVersion: event.StreamVersion,
				UserID:            userID,
			},
		)
		if err != nil {
			return fmt.Errorf("store: insert SCIM group member: %w", err)
		}
		if affected != 1 {
			if rebuilding, ok := tx.(projectionTx); ok && rebuilding.skipWork {
				continue
			}
			return fmt.Errorf("%w: group membership requires existing users", ErrSCIMInvalid)
		}
	}
	affected, err := queries.AdvanceSCIMGroupProjectionVersion(
		ctx,
		generated.AdvanceSCIMGroupProjectionVersionParams{
			ProjectionVersion:         event.StreamVersion,
			UpdatedAt:                 event.CreatedAt,
			GroupID:                   event.StreamID,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: advance SCIM group membership projection: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: SCIM group membership affected %d groups; want one", affected)
	}
	return nil
}

func projectSCIMGroupDeleted(ctx context.Context, tx ProjectionTx, event PersistedEvent) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: SCIM group deletion requires a prior group")
	}
	payload, err := decodeEventPayload[scimGroupDeletedPayload](event, scimPayloadVersion)
	if err != nil {
		return err
	}
	if !validProviderSlug(payload.ProviderSlug) {
		return errors.New("store: SCIM group deletion provider is invalid")
	}
	affected, err := generated.New(tx).DeleteSCIMGroup(
		ctx,
		generated.DeleteSCIMGroupParams{
			GroupID:                   event.StreamID,
			ProviderSlug:              payload.ProviderSlug,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project SCIM group deletion: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("store: SCIM group deletion affected %d rows; want one", affected)
	}
	return nil
}

// IsSCIMInvalid recognizes validation failures safe to map to a static SCIM
// client rejection.
func IsSCIMInvalid(err error) bool {
	return errors.Is(err, ErrSCIMInvalid)
}

func validateSCIMGroupPayload(groupID string, payload scimGroupPayload) error {
	canonicalID, err := canonicalUserID(groupID)
	if err != nil || canonicalID != groupID ||
		!validProviderSlug(payload.ProviderSlug) ||
		!validBoundedText(payload.ExternalID, maxSCIMExternalIDBytes) ||
		!validBoundedText(payload.DisplayName, maxSCIMGroupDisplayNameBytes) {
		return errors.New("store: SCIM group payload is invalid")
	}
	return nil
}

func resetSCIMProviders(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetSCIMProviders(ctx); err != nil {
		return fmt.Errorf("store: reset SCIM providers: %w", err)
	}
	return nil
}

func resetSCIMGroups(ctx context.Context, tx ProjectionTx) error {
	queries := generated.New(tx)
	if err := queries.ResetSCIMGroupMembers(ctx); err != nil {
		return fmt.Errorf("store: reset SCIM group members: %w", err)
	}
	if err := queries.ResetSCIMGroups(ctx); err != nil {
		return fmt.Errorf("store: reset SCIM groups: %w", err)
	}
	return nil
}
