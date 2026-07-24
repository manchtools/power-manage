package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	actionSetStreamType     = "managed-action-set"
	actionSetCreatedType    = "ManagedActionSetCreated"
	actionSetUpdatedType    = "ManagedActionSetUpdated"
	actionSetDeletedType    = "ManagedActionSetDeleted"
	actionSetPayloadVersion = 1
	maxActionSetNameBytes   = 200

	// ActionSetRebuildTarget is the CLI-only managed-set recovery target.
	ActionSetRebuildTarget = "managed-action-sets"
)

var errActionSetExists = errors.New("store: managed action set already exists")

// ManagedActionSet is M3's event-derived set metadata. Ordered membership is
// added by the nestable-set milestone.
type ManagedActionSet struct {
	ID                string
	Name              string
	ProjectionVersion int64
}

type actionSetPayload struct {
	Name string `json:"name"`
}

type actionSetDeletedPayload struct{}

// ManagedActionSetCreatedEvent records one set.
func ManagedActionSetCreatedEvent(id, name string) (Event, error) {
	return newManagedActionSetEvent(id, name, actionSetCreatedType)
}

// ManagedActionSetUpdatedEvent fully replaces set metadata.
func ManagedActionSetUpdatedEvent(id, name string) (Event, error) {
	return newManagedActionSetEvent(id, name, actionSetUpdatedType)
}

// ManagedActionSetDeletedEvent removes one set projection.
func ManagedActionSetDeletedEvent(id string) (Event, error) {
	id, err := canonicalActionSetID(id)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(actionSetDeletedPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode action-set deletion: %w", err)
	}
	return managedActionSetEvent(id, actionSetDeletedType, payload), nil
}

func newManagedActionSetEvent(id, name, eventType string) (Event, error) {
	set, err := normalizeManagedActionSet(id, name, 1)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(actionSetPayload{Name: set.Name})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode managed action set: %w", err)
	}
	return managedActionSetEvent(set.ID, eventType, payload), nil
}

func managedActionSetEvent(id, eventType string, payload []byte) Event {
	return Event{
		StreamType:     actionSetStreamType,
		StreamID:       id,
		EventType:      eventType,
		PayloadVersion: actionSetPayloadVersion,
		Payload:        payload,
	}
}

// ManagedActionSetByID reads one set through the transitive scope predicate.
func (s *Store) ManagedActionSetByID(
	ctx context.Context,
	id string,
	global bool,
	deviceGroupIDs []string,
	userGroupIDs []string,
	selfID string,
) (ManagedActionSet, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return ManagedActionSet{}, errors.New("store: invalid action-set lookup")
	}
	id, err := canonicalActionSetID(id)
	if err != nil {
		return ManagedActionSet{}, err
	}
	deviceGroupIDs, err = normalizeDeviceGroupScope(deviceGroupIDs)
	if err != nil {
		return ManagedActionSet{}, err
	}
	userGroupIDs, err = normalizeUserScopeIDs(userGroupIDs)
	if err != nil {
		return ManagedActionSet{}, err
	}
	if selfID != "" {
		selfID, err = canonicalUserID(selfID)
		if err != nil {
			return ManagedActionSet{}, err
		}
	}
	row, err := generated.New(s.pool).GetScopedManagedActionSet(
		ctx,
		generated.GetScopedManagedActionSetParams{
			ActionSetID:    id,
			GlobalScope:    global,
			DeviceGroupIds: deviceGroupIDs,
			UserGroupIds:   userGroupIDs,
			SelfID:         selfID,
		},
	)
	if err != nil {
		return ManagedActionSet{}, fmt.Errorf("store: read managed action set: %w", err)
	}
	return normalizeManagedActionSet(row.ActionSetID, row.Name, row.ProjectionVersion)
}

// ListManagedActionSets returns one scope-confined set page.
func (s *Store) ListManagedActionSets(
	ctx context.Context,
	global bool,
	deviceGroupIDs []string,
	userGroupIDs []string,
	selfID string,
	limit int32,
) ([]ManagedActionSet, error) {
	if s == nil || s.pool == nil || ctx == nil || limit < 1 || limit > 200 {
		return nil, errors.New("store: invalid action-set list")
	}
	var err error
	deviceGroupIDs, err = normalizeDeviceGroupScope(deviceGroupIDs)
	if err != nil {
		return nil, err
	}
	userGroupIDs, err = normalizeUserScopeIDs(userGroupIDs)
	if err != nil {
		return nil, err
	}
	if selfID != "" {
		selfID, err = canonicalUserID(selfID)
		if err != nil {
			return nil, err
		}
	}
	rows, err := generated.New(s.pool).ListScopedManagedActionSets(
		ctx,
		generated.ListScopedManagedActionSetsParams{
			GlobalScope:    global,
			DeviceGroupIds: deviceGroupIDs,
			UserGroupIds:   userGroupIDs,
			SelfID:         selfID,
			PageLimit:      limit,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("store: list managed action sets: %w", err)
	}
	sets := make([]ManagedActionSet, len(rows))
	for index, row := range rows {
		sets[index], err = normalizeManagedActionSet(
			row.ActionSetID,
			row.Name,
			row.ProjectionVersion,
		)
		if err != nil {
			return nil, err
		}
	}
	return sets, nil
}

// ManagedActionSetEventTypes returns the exact set mutation set.
func ManagedActionSetEventTypes() []string {
	return []string{actionSetCreatedType, actionSetUpdatedType, actionSetDeletedType}
}

// IsManagedActionSetExists recognizes duplicate set creation.
func IsManagedActionSetExists(err error) bool {
	return errors.Is(err, errActionSetExists)
}

func canonicalActionSetID(id string) (string, error) {
	if err := validate.ULIDPathID(id); err != nil {
		return "", fmt.Errorf("store: invalid action-set ID: %w", err)
	}
	return strings.ToUpper(id), nil
}

func normalizeManagedActionSet(id, name string, version int64) (ManagedActionSet, error) {
	id, err := canonicalActionSetID(id)
	if err != nil {
		return ManagedActionSet{}, err
	}
	if len(name) < 1 || len(name) > maxActionSetNameBytes ||
		!utf8.ValidString(name) || strings.ContainsRune(name, '\x00') ||
		version < 1 {
		return ManagedActionSet{}, errors.New("store: managed action set is invalid")
	}
	return ManagedActionSet{ID: id, Name: name, ProjectionVersion: version}, nil
}

func actionSetEventDefinitions() map[string]eventDefinition {
	goldenPayload := func() ([]byte, error) {
		return json.Marshal(actionSetPayload{Name: "workstation-baseline"})
	}
	return map[string]eventDefinition{
		actionSetCreatedType: {
			PayloadVersion: actionSetPayloadVersion,
			PayloadType:    actionSetPayload{},
			GoldenPayload:  goldenPayload,
			Projector:      projectManagedActionSetCreate,
		},
		actionSetUpdatedType: {
			PayloadVersion: actionSetPayloadVersion,
			PayloadType:    actionSetPayload{},
			GoldenPayload:  goldenPayload,
			Projector:      projectManagedActionSetUpdate,
		},
		actionSetDeletedType: {
			PayloadVersion: actionSetPayloadVersion,
			PayloadType:    actionSetDeletedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(actionSetDeletedPayload{})
			},
			Projector: projectManagedActionSetDelete,
		},
	}
}

func actionSetGoldenCorpus() map[string]goldenEvent {
	payload := []byte(`{"name":"workstation-baseline"}`)
	return map[string]goldenEvent{
		actionSetCreatedType: {PayloadVersion: actionSetPayloadVersion, Payload: payload},
		actionSetUpdatedType: {PayloadVersion: actionSetPayloadVersion, Payload: payload},
		actionSetDeletedType: {
			PayloadVersion: actionSetPayloadVersion,
			Payload:        []byte(`{}`),
		},
	}
}

func projectManagedActionSetCreate(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion != 1 {
		return errActionSetExists
	}
	set, err := managedActionSetFromEvent(event)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).InsertManagedActionSet(
		ctx,
		generated.InsertManagedActionSetParams{
			ActionSetID:       set.ID,
			Name:              set.Name,
			ProjectionVersion: event.StreamVersion,
			UpdatedAt:         event.CreatedAt,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project action-set creation: %w", err)
	}
	if affected != 1 {
		return errActionSetExists
	}
	return nil
}

func projectManagedActionSetUpdate(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: action-set update requires creation")
	}
	set, err := managedActionSetFromEvent(event)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).ReplaceManagedActionSet(
		ctx,
		generated.ReplaceManagedActionSetParams{
			Name:                      set.Name,
			ProjectionVersion:         event.StreamVersion,
			UpdatedAt:                 event.CreatedAt,
			ActionSetID:               set.ID,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project action-set update: %w", err)
	}
	if affected != 1 {
		return errors.New("store: action-set update conflicts with projection")
	}
	return nil
}

func projectManagedActionSetDelete(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: action-set deletion requires creation")
	}
	if _, err := decodeEventPayload[actionSetDeletedPayload](
		event,
		actionSetPayloadVersion,
	); err != nil {
		return err
	}
	id, err := canonicalActionSetID(event.StreamID)
	if err != nil || id != event.StreamID {
		return errors.New("store: action-set deletion ID is invalid")
	}
	affected, err := generated.New(tx).DeleteManagedActionSet(
		ctx,
		generated.DeleteManagedActionSetParams{
			ActionSetID:               id,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project action-set deletion: %w", err)
	}
	if affected != 1 {
		return errors.New("store: action-set deletion conflicts with projection")
	}
	return nil
}

func managedActionSetFromEvent(event PersistedEvent) (ManagedActionSet, error) {
	payload, err := decodeEventPayload[actionSetPayload](event, actionSetPayloadVersion)
	if err != nil {
		return ManagedActionSet{}, err
	}
	return normalizeManagedActionSet(event.StreamID, payload.Name, event.StreamVersion)
}

func resetManagedActionSets(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetManagedActionSets(ctx); err != nil {
		return fmt.Errorf("store: reset managed action sets: %w", err)
	}
	return nil
}
