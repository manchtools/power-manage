package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	userGroupStreamType               = "managed-user-group"
	userGroupCreatedEventType         = "ManagedUserGroupCreated"
	userGroupUpdatedEventType         = "ManagedUserGroupUpdated"
	userGroupMetadataUpdatedEventType = "ManagedUserGroupMetadataUpdated"
	userGroupDeletedEventType         = "ManagedUserGroupDeleted"
	userGroupPayloadVersion           = 1
	maxUserGroupNameBytes             = 512
	maxUserGroupMembers               = 1000

	// UserGroupRebuildTarget is the CLI-only managed-group recovery target.
	UserGroupRebuildTarget = "managed-user-groups"
)

var errUserGroupExists = errors.New("store: user group already exists")

// UserGroup is one event-derived managed user-group projection.
type UserGroup struct {
	ID                string
	Name              string
	MemberUserIDs     []string
	ProjectionVersion int64
}

type userGroupPayload struct {
	Name          string   `json:"name"`
	MemberUserIDs []string `json:"member_user_ids"`
}

type userGroupDeletedPayload struct{}

// UserGroupCreatedEvent records a managed user group and its exact membership.
func UserGroupCreatedEvent(id, name string, memberUserIDs []string) (Event, error) {
	return newUserGroupEvent(id, name, memberUserIDs, userGroupCreatedEventType)
}

// UserGroupUpdatedEvent records full replacement of a managed user group.
func UserGroupUpdatedEvent(id, name string, memberUserIDs []string) (Event, error) {
	return newUserGroupEvent(id, name, memberUserIDs, userGroupUpdatedEventType)
}

// UserGroupMetadataUpdatedEvent replaces management-owned group metadata only.
func UserGroupMetadataUpdatedEvent(id, name string) (Event, error) {
	group, err := normalizeUserGroup(id, name, nil, 1)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(userGroupPayload{Name: group.Name})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode user-group metadata update: %w", err)
	}
	return userGroupEvent(group.ID, userGroupMetadataUpdatedEventType, payload), nil
}

// UserGroupDeletedEvent removes one managed user-group projection.
func UserGroupDeletedEvent(id string) (Event, error) {
	id, err := canonicalUserGroupID(id)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(userGroupDeletedPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode user-group deletion: %w", err)
	}
	return userGroupEvent(id, userGroupDeletedEventType, payload), nil
}

func newUserGroupEvent(
	id string,
	name string,
	memberUserIDs []string,
	eventType string,
) (Event, error) {
	group, err := normalizeUserGroup(id, name, memberUserIDs, 1)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(userGroupPayload{
		Name:          group.Name,
		MemberUserIDs: group.MemberUserIDs,
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode user group: %w", err)
	}
	return userGroupEvent(group.ID, eventType, payload), nil
}

// UserGroupByID reads one managed group through an explicit scope predicate.
func (s *Store) UserGroupByID(
	ctx context.Context,
	id string,
	global bool,
	userGroupIDs []string,
) (UserGroup, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return UserGroup{}, errors.New("store: invalid user-group lookup")
	}
	id, err := canonicalUserGroupID(id)
	if err != nil {
		return UserGroup{}, err
	}
	userGroupIDs, err = normalizeUserScopeIDs(userGroupIDs)
	if err != nil {
		return UserGroup{}, err
	}
	queries := generated.New(s.pool)
	row, err := queries.GetScopedManagedUserGroup(
		ctx,
		generated.GetScopedManagedUserGroupParams{
			GroupID:      id,
			GlobalScope:  global,
			UserGroupIds: userGroupIDs,
		},
	)
	if err != nil {
		return UserGroup{}, fmt.Errorf("store: read user group: %w", err)
	}
	members, err := queries.ListManagedUserGroupMembers(ctx, id)
	if err != nil {
		return UserGroup{}, fmt.Errorf("store: list user-group members: %w", err)
	}
	return normalizeUserGroup(row.GroupID, row.Name, members, row.ProjectionVersion)
}

// ListUserGroups returns one explicitly scope-confined group page.
func (s *Store) ListUserGroups(
	ctx context.Context,
	global bool,
	userGroupIDs []string,
	limit int32,
) ([]UserGroup, error) {
	if s == nil || s.pool == nil || ctx == nil || limit < 1 || limit > 200 {
		return nil, errors.New("store: invalid user-group list")
	}
	userGroupIDs, err := normalizeUserScopeIDs(userGroupIDs)
	if err != nil {
		return nil, err
	}
	queries := generated.New(s.pool)
	rows, err := queries.ListScopedManagedUserGroups(
		ctx,
		generated.ListScopedManagedUserGroupsParams{
			GlobalScope:  global,
			UserGroupIds: userGroupIDs,
			PageLimit:    limit,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("store: list user groups: %w", err)
	}
	groupIDs := make([]string, len(rows))
	for index, row := range rows {
		groupIDs[index] = row.GroupID
	}
	membersByGroup := make(map[string][]string, len(rows))
	if len(groupIDs) > 0 {
		memberRows, err := queries.ListManagedUserGroupMembersForGroups(ctx, groupIDs)
		if err != nil {
			return nil, fmt.Errorf("store: list user-group members: %w", err)
		}
		for _, member := range memberRows {
			membersByGroup[member.GroupID] = append(
				membersByGroup[member.GroupID],
				member.UserID,
			)
		}
	}
	groups := make([]UserGroup, len(rows))
	for index, row := range rows {
		groups[index], err = normalizeUserGroup(
			row.GroupID,
			row.Name,
			membersByGroup[row.GroupID],
			row.ProjectionVersion,
		)
		if err != nil {
			return nil, err
		}
	}
	return groups, nil
}

// IsUserGroupExists recognizes duplicate managed-group creation.
func IsUserGroupExists(err error) bool {
	return errors.Is(err, errUserGroupExists)
}

// UserGroupEventTypes returns the exact managed-group CRUD event set.
func UserGroupEventTypes() []string {
	return []string{
		userGroupCreatedEventType,
		userGroupUpdatedEventType,
		userGroupMetadataUpdatedEventType,
		userGroupDeletedEventType,
	}
}

func userGroupEvent(id, eventType string, payload []byte) Event {
	return Event{
		StreamType:     userGroupStreamType,
		StreamID:       id,
		EventType:      eventType,
		PayloadVersion: userGroupPayloadVersion,
		Payload:        payload,
	}
}

func canonicalUserGroupID(id string) (string, error) {
	if err := validate.ULIDPathID(id); err != nil {
		return "", fmt.Errorf("store: user-group ID is invalid: %w", err)
	}
	return strings.ToUpper(id), nil
}

func normalizeUserGroup(
	id string,
	name string,
	memberUserIDs []string,
	version int64,
) (UserGroup, error) {
	id, err := canonicalUserGroupID(id)
	if err != nil {
		return UserGroup{}, err
	}
	if !utf8.ValidString(name) || len(name) < 1 || len(name) > maxUserGroupNameBytes {
		return UserGroup{}, errors.New("store: user-group name is invalid")
	}
	if len(memberUserIDs) > maxUserGroupMembers {
		return UserGroup{}, errors.New("store: user-group membership is too large")
	}
	members := make([]string, len(memberUserIDs))
	for index, member := range memberUserIDs {
		members[index], err = canonicalUserID(member)
		if err != nil {
			return UserGroup{}, errors.New("store: user-group member is invalid")
		}
	}
	slices.Sort(members)
	if len(slices.Compact(slices.Clone(members))) != len(members) {
		return UserGroup{}, errors.New("store: user-group membership contains duplicates")
	}
	if version < 1 {
		return UserGroup{}, errors.New("store: user-group projection version is invalid")
	}
	return UserGroup{
		ID:                id,
		Name:              name,
		MemberUserIDs:     members,
		ProjectionVersion: version,
	}, nil
}

func userGroupEventDefinitions() map[string]eventDefinition {
	return map[string]eventDefinition{
		userGroupCreatedEventType: {
			PayloadVersion: userGroupPayloadVersion,
			PayloadType:    userGroupPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(userGroupPayload{
					Name:          "operators",
					MemberUserIDs: []string{"01J00000000000000000000001"},
				})
			},
			Projector: projectUserGroupCreated,
		},
		userGroupUpdatedEventType: {
			PayloadVersion: userGroupPayloadVersion,
			PayloadType:    userGroupPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(userGroupPayload{
					Name:          "updated-operators",
					MemberUserIDs: []string{},
				})
			},
			Projector: projectUserGroupUpdated,
		},
		userGroupMetadataUpdatedEventType: {
			PayloadVersion: userGroupPayloadVersion,
			PayloadType:    userGroupPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(userGroupPayload{
					Name:          "renamed-operators",
					MemberUserIDs: nil,
				})
			},
			Projector: projectUserGroupMetadataUpdated,
		},
		userGroupDeletedEventType: {
			PayloadVersion: userGroupPayloadVersion,
			PayloadType:    userGroupDeletedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(userGroupDeletedPayload{})
			},
			Projector: projectUserGroupDeleted,
		},
	}
}

func userGroupGoldenCorpus() map[string]goldenEvent {
	return map[string]goldenEvent{
		userGroupCreatedEventType: {
			PayloadVersion: userGroupPayloadVersion,
			Payload: []byte(
				`{"name":"operators","member_user_ids":["01J00000000000000000000001"]}`,
			),
		},
		userGroupUpdatedEventType: {
			PayloadVersion: userGroupPayloadVersion,
			Payload:        []byte(`{"name":"updated-operators","member_user_ids":[]}`),
		},
		userGroupMetadataUpdatedEventType: {
			PayloadVersion: userGroupPayloadVersion,
			Payload:        []byte(`{"name":"renamed-operators","member_user_ids":null}`),
		},
		userGroupDeletedEventType: {
			PayloadVersion: userGroupPayloadVersion,
			Payload:        []byte(`{}`),
		},
	}
}

func projectUserGroupCreated(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion != 1 {
		return errUserGroupExists
	}
	group, err := decodeUserGroupEvent(event)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).InsertManagedUserGroup(
		ctx,
		generated.InsertManagedUserGroupParams{
			GroupID:           group.ID,
			Name:              group.Name,
			ProjectionVersion: event.StreamVersion,
			UpdatedAt:         event.CreatedAt,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project user-group creation: %w", err)
	}
	if affected != 1 {
		return errUserGroupExists
	}
	return replaceUserGroupMembers(ctx, tx, group, event.StreamVersion)
}

func projectUserGroupUpdated(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion < 2 {
		return errors.New("store: user-group update version is invalid")
	}
	group, err := decodeUserGroupEvent(event)
	if err != nil {
		return err
	}
	queries := generated.New(tx)
	affected, err := queries.ReplaceManagedUserGroup(
		ctx,
		generated.ReplaceManagedUserGroupParams{
			Name:                      group.Name,
			ProjectionVersion:         event.StreamVersion,
			UpdatedAt:                 event.CreatedAt,
			GroupID:                   group.ID,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project user-group update: %w", err)
	}
	if affected != 1 {
		return errors.New("store: user-group update projection version mismatch")
	}
	if err := queries.DeleteManagedUserGroupMembers(ctx, group.ID); err != nil {
		return fmt.Errorf("store: clear user-group members: %w", err)
	}
	return replaceUserGroupMembers(ctx, tx, group, event.StreamVersion)
}

func projectUserGroupMetadataUpdated(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion < 2 {
		return errors.New("store: user-group metadata update version is invalid")
	}
	payload, err := decodeEventPayload[userGroupPayload](event, userGroupPayloadVersion)
	if err != nil {
		return err
	}
	if len(payload.MemberUserIDs) != 0 {
		return errors.New("store: user-group metadata update carries members")
	}
	group, err := normalizeUserGroup(event.StreamID, payload.Name, nil, event.StreamVersion)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).ReplaceManagedUserGroup(
		ctx,
		generated.ReplaceManagedUserGroupParams{
			Name:                      group.Name,
			ProjectionVersion:         event.StreamVersion,
			UpdatedAt:                 event.CreatedAt,
			GroupID:                   group.ID,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project user-group metadata update: %w", err)
	}
	if affected != 1 {
		return errors.New("store: user-group metadata update projection version mismatch")
	}
	return nil
}

func projectUserGroupDeleted(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion < 2 {
		return errors.New("store: user-group deletion version is invalid")
	}
	if _, err := decodeEventPayload[userGroupDeletedPayload](
		event,
		userGroupPayloadVersion,
	); err != nil {
		return err
	}
	affected, err := generated.New(tx).DeleteManagedUserGroup(
		ctx,
		generated.DeleteManagedUserGroupParams{
			GroupID:           event.StreamID,
			ProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project user-group deletion: %w", err)
	}
	if affected != 1 {
		return errors.New("store: user-group deletion projection version mismatch")
	}
	return nil
}

func decodeUserGroupEvent(event PersistedEvent) (UserGroup, error) {
	payload, err := decodeEventPayload[userGroupPayload](event, userGroupPayloadVersion)
	if err != nil {
		return UserGroup{}, err
	}
	return normalizeUserGroup(
		event.StreamID,
		payload.Name,
		payload.MemberUserIDs,
		event.StreamVersion,
	)
}

func replaceUserGroupMembers(
	ctx context.Context,
	tx ProjectionTx,
	group UserGroup,
	version int64,
) error {
	queries := generated.New(tx)
	for _, userID := range group.MemberUserIDs {
		affected, err := queries.InsertManagedUserGroupMember(
			ctx,
			generated.InsertManagedUserGroupMemberParams{
				GroupID:           group.ID,
				UserID:            userID,
				ProjectionVersion: version,
			},
		)
		if err != nil {
			return fmt.Errorf("store: project user-group member: %w", err)
		}
		if affected != 1 {
			return errors.New("store: user-group member does not exist")
		}
	}
	return nil
}

func resetUserGroups(ctx context.Context, tx ProjectionTx) error {
	queries := generated.New(tx)
	if err := queries.ResetManagedUserGroupMembers(ctx); err != nil {
		return fmt.Errorf("store: reset user-group members: %w", err)
	}
	if err := queries.ResetManagedUserGroups(ctx); err != nil {
		return fmt.Errorf("store: reset user groups: %w", err)
	}
	return nil
}
