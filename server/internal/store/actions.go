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
	actionStreamType     = "managed-action"
	actionCreatedType    = "ManagedActionCreated"
	actionUpdatedType    = "ManagedActionUpdated"
	actionDeletedType    = "ManagedActionDeleted"
	actionPayloadVersion = 1
	maxActionNameBytes   = 200
	maxActionParamsBytes = 2 << 20

	// ActionRebuildTarget is the CLI-only managed-action recovery target.
	ActionRebuildTarget = "managed-actions"
)

var errActionExists = errors.New("store: managed action already exists")

// ManagedAction is one public action definition and its projection version.
type ManagedAction struct {
	ID                string
	Name              string
	Params            []byte
	ProjectionVersion int64
}

type actionPayload struct {
	Name   string `json:"name"`
	Params []byte `json:"params"`
}

type actionDeletedPayload struct{}

// ManagedActionCreatedEvent records one action definition.
func ManagedActionCreatedEvent(id, name string, params []byte) (Event, error) {
	return newManagedActionEvent(id, name, params, actionCreatedType)
}

// ManagedActionUpdatedEvent fully replaces one action definition.
func ManagedActionUpdatedEvent(id, name string, params []byte) (Event, error) {
	return newManagedActionEvent(id, name, params, actionUpdatedType)
}

// ManagedActionDeletedEvent removes one action projection.
func ManagedActionDeletedEvent(id string) (Event, error) {
	id, err := canonicalActionID(id)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(actionDeletedPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode managed-action deletion: %w", err)
	}
	return managedActionEvent(id, actionDeletedType, payload), nil
}

func newManagedActionEvent(id, name string, params []byte, eventType string) (Event, error) {
	action, err := normalizeManagedAction(id, name, params, 1)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(actionPayload{Name: action.Name, Params: action.Params})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode managed action: %w", err)
	}
	return managedActionEvent(action.ID, eventType, payload), nil
}

func managedActionEvent(id, eventType string, payload []byte) Event {
	return Event{
		StreamType:     actionStreamType,
		StreamID:       id,
		EventType:      eventType,
		PayloadVersion: actionPayloadVersion,
		Payload:        payload,
	}
}

// ManagedActionByID reads one action through the transitive scope predicate.
func (s *Store) ManagedActionByID(
	ctx context.Context,
	id string,
	global bool,
	deviceGroupIDs []string,
	userGroupIDs []string,
	selfID string,
) (ManagedAction, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return ManagedAction{}, errors.New("store: invalid managed-action lookup")
	}
	id, err := canonicalActionID(id)
	if err != nil {
		return ManagedAction{}, err
	}
	deviceGroupIDs, err = normalizeDeviceGroupScope(deviceGroupIDs)
	if err != nil {
		return ManagedAction{}, err
	}
	userGroupIDs, err = normalizeUserScopeIDs(userGroupIDs)
	if err != nil {
		return ManagedAction{}, err
	}
	if selfID != "" {
		selfID, err = canonicalUserID(selfID)
		if err != nil {
			return ManagedAction{}, err
		}
	}
	row, err := generated.New(s.pool).GetScopedManagedAction(
		ctx,
		generated.GetScopedManagedActionParams{
			ActionID:       id,
			GlobalScope:    global,
			DeviceGroupIds: deviceGroupIDs,
			UserGroupIds:   userGroupIDs,
			SelfID:         selfID,
		},
	)
	if err != nil {
		return ManagedAction{}, fmt.Errorf("store: read managed action: %w", err)
	}
	return normalizeManagedAction(row.ActionID, row.Name, row.Params, row.ProjectionVersion)
}

// ListManagedActions returns one scope-confined action page.
func (s *Store) ListManagedActions(
	ctx context.Context,
	global bool,
	deviceGroupIDs []string,
	userGroupIDs []string,
	selfID string,
	limit int32,
) ([]ManagedAction, error) {
	if s == nil || s.pool == nil || ctx == nil || limit < 1 || limit > 200 {
		return nil, errors.New("store: invalid managed-action list")
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
	rows, err := generated.New(s.pool).ListScopedManagedActions(
		ctx,
		generated.ListScopedManagedActionsParams{
			GlobalScope:    global,
			DeviceGroupIds: deviceGroupIDs,
			UserGroupIds:   userGroupIDs,
			SelfID:         selfID,
			PageLimit:      limit,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("store: list managed actions: %w", err)
	}
	actions := make([]ManagedAction, len(rows))
	for index, row := range rows {
		actions[index], err = normalizeManagedAction(
			row.ActionID,
			row.Name,
			row.Params,
			row.ProjectionVersion,
		)
		if err != nil {
			return nil, err
		}
	}
	return actions, nil
}

// ManagedActionEventTypes returns the exact action mutation set.
func ManagedActionEventTypes() []string {
	return []string{actionCreatedType, actionUpdatedType, actionDeletedType}
}

// IsManagedActionExists recognizes duplicate action creation.
func IsManagedActionExists(err error) bool {
	return errors.Is(err, errActionExists)
}

func canonicalActionID(id string) (string, error) {
	if err := validate.ULIDPathID(id); err != nil {
		return "", fmt.Errorf("store: invalid action ID: %w", err)
	}
	return strings.ToUpper(id), nil
}

func normalizeManagedAction(
	id string,
	name string,
	params []byte,
	version int64,
) (ManagedAction, error) {
	id, err := canonicalActionID(id)
	if err != nil {
		return ManagedAction{}, err
	}
	if len(name) < 1 || len(name) > maxActionNameBytes ||
		!utf8.ValidString(name) || strings.ContainsRune(name, '\x00') ||
		len(params) < 1 || len(params) > maxActionParamsBytes ||
		version < 1 {
		return ManagedAction{}, errors.New("store: managed action is invalid")
	}
	return ManagedAction{
		ID:                id,
		Name:              name,
		Params:            slices.Clone(params),
		ProjectionVersion: version,
	}, nil
}

func actionEventDefinitions() map[string]eventDefinition {
	golden := actionPayload{Name: "install-agent", Params: []byte{0x0a, 0x00}}
	return map[string]eventDefinition{
		actionCreatedType: {
			PayloadVersion: actionPayloadVersion,
			PayloadType:    actionPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(golden)
			},
			Projector: projectManagedActionCreate,
		},
		actionUpdatedType: {
			PayloadVersion: actionPayloadVersion,
			PayloadType:    actionPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(golden)
			},
			Projector: projectManagedActionUpdate,
		},
		actionDeletedType: {
			PayloadVersion: actionPayloadVersion,
			PayloadType:    actionDeletedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(actionDeletedPayload{})
			},
			Projector: projectManagedActionDelete,
		},
	}
}

func actionGoldenCorpus() map[string]goldenEvent {
	payload := []byte(`{"name":"install-agent","params":"CgA="}`)
	return map[string]goldenEvent{
		actionCreatedType: {PayloadVersion: actionPayloadVersion, Payload: payload},
		actionUpdatedType: {PayloadVersion: actionPayloadVersion, Payload: payload},
		actionDeletedType: {
			PayloadVersion: actionPayloadVersion,
			Payload:        []byte(`{}`),
		},
	}
}

func projectManagedActionCreate(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion != 1 {
		return errActionExists
	}
	action, err := managedActionFromEvent(event)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).InsertManagedAction(
		ctx,
		generated.InsertManagedActionParams{
			ActionID:          action.ID,
			Name:              action.Name,
			Params:            action.Params,
			ProjectionVersion: event.StreamVersion,
			UpdatedAt:         event.CreatedAt,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project managed-action creation: %w", err)
	}
	if affected != 1 {
		return errActionExists
	}
	return nil
}

func projectManagedActionUpdate(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: managed-action update requires creation")
	}
	action, err := managedActionFromEvent(event)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).ReplaceManagedAction(
		ctx,
		generated.ReplaceManagedActionParams{
			Name:                      action.Name,
			Params:                    action.Params,
			ProjectionVersion:         event.StreamVersion,
			UpdatedAt:                 event.CreatedAt,
			ActionID:                  action.ID,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project managed-action update: %w", err)
	}
	if affected != 1 {
		return errors.New("store: managed-action update conflicts with projection")
	}
	return nil
}

func projectManagedActionDelete(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: managed-action deletion requires creation")
	}
	if _, err := decodeEventPayload[actionDeletedPayload](
		event,
		actionPayloadVersion,
	); err != nil {
		return err
	}
	id, err := canonicalActionID(event.StreamID)
	if err != nil || id != event.StreamID {
		return errors.New("store: managed-action deletion ID is invalid")
	}
	affected, err := generated.New(tx).DeleteManagedAction(
		ctx,
		generated.DeleteManagedActionParams{
			ActionID:                  id,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project managed-action deletion: %w", err)
	}
	if affected != 1 {
		return errors.New("store: managed-action deletion conflicts with projection")
	}
	return nil
}

func managedActionFromEvent(event PersistedEvent) (ManagedAction, error) {
	payload, err := decodeEventPayload[actionPayload](event, actionPayloadVersion)
	if err != nil {
		return ManagedAction{}, err
	}
	return normalizeManagedAction(
		event.StreamID,
		payload.Name,
		payload.Params,
		event.StreamVersion,
	)
}

func resetManagedActions(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetManagedActions(ctx); err != nil {
		return fmt.Errorf("store: reset managed actions: %w", err)
	}
	return nil
}
