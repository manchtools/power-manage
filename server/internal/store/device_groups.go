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
	deviceGroupStreamType       = "device-group"
	deviceGroupCreatedEventType = "DeviceGroupCreated"
	deviceGroupUpdatedEventType = "DeviceGroupUpdated"
	deviceGroupDeletedEventType = "DeviceGroupDeleted"
	deviceGroupPayloadVersion   = 1
	maxDeviceGroupNameRunes     = 200
	maxDeviceGroupQueryRunes    = 4096

	// DeviceGroupRebuildTarget is the CLI-only device-group recovery target.
	DeviceGroupRebuildTarget = "device-groups"
)

var errDeviceGroupExists = errors.New("store: device group already exists")

// DeviceGroup is one event-derived device-group projection.
type DeviceGroup struct {
	ID                string
	Name              string
	DynamicQuery      string
	ProjectionVersion int64
}

type deviceGroupPayload struct {
	Name         string `json:"name"`
	DynamicQuery string `json:"dynamic_query"`
}

type deviceGroupDeletedPayload struct{}

// DeviceGroupCreatedEvent records a new static or dynamic device group.
func DeviceGroupCreatedEvent(id, name, dynamicQuery string) (Event, error) {
	id, name, dynamicQuery, err := normalizeDeviceGroup(id, name, dynamicQuery)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(deviceGroupPayload{Name: name, DynamicQuery: dynamicQuery})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode device-group creation: %w", err)
	}
	return deviceGroupEvent(id, deviceGroupCreatedEventType, payload), nil
}

// DeviceGroupUpdatedEvent records a full replacement of a device group.
func DeviceGroupUpdatedEvent(id, name, dynamicQuery string) (Event, error) {
	id, name, dynamicQuery, err := normalizeDeviceGroup(id, name, dynamicQuery)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(deviceGroupPayload{Name: name, DynamicQuery: dynamicQuery})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode device-group update: %w", err)
	}
	return deviceGroupEvent(id, deviceGroupUpdatedEventType, payload), nil
}

// DeviceGroupDeletedEvent records removal of a device group projection.
func DeviceGroupDeletedEvent(id string) (Event, error) {
	id, err := canonicalDeviceGroupID(id)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(deviceGroupDeletedPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode device-group deletion: %w", err)
	}
	return deviceGroupEvent(id, deviceGroupDeletedEventType, payload), nil
}

// DeviceGroupByID reads one device group through an explicit scope predicate.
func (s *Store) DeviceGroupByID(
	ctx context.Context,
	id string,
	global bool,
	ids []string,
) (DeviceGroup, error) {
	if s == nil || s.pool == nil {
		return DeviceGroup{}, errors.New("store: nil store")
	}
	if ctx == nil {
		return DeviceGroup{}, errors.New("store: nil device-group context")
	}
	id, err := canonicalDeviceGroupID(id)
	if err != nil {
		return DeviceGroup{}, err
	}
	ids, err = normalizeDeviceGroupScope(ids)
	if err != nil {
		return DeviceGroup{}, err
	}
	row, err := generated.New(s.pool).GetScopedDeviceGroup(
		ctx,
		generated.GetScopedDeviceGroupParams{
			DeviceGroupID:  id,
			GlobalScope:    global,
			DeviceGroupIds: ids,
		},
	)
	if err != nil {
		return DeviceGroup{}, fmt.Errorf("store: read device group: %w", err)
	}
	return validateDeviceGroupProjection(
		row.DeviceGroupID,
		row.Name,
		row.DynamicQuery,
		row.ProjectionVersion,
	)
}

// ListDeviceGroups returns one explicitly scope-confined page.
func (s *Store) ListDeviceGroups(
	ctx context.Context,
	global bool,
	ids []string,
	limit int32,
) ([]DeviceGroup, error) {
	if s == nil || s.pool == nil {
		return nil, errors.New("store: nil store")
	}
	if ctx == nil {
		return nil, errors.New("store: nil device-group context")
	}
	if limit < 1 || limit > 200 {
		return nil, errors.New("store: device-group limit is invalid")
	}
	ids, err := normalizeDeviceGroupScope(ids)
	if err != nil {
		return nil, err
	}
	rows, err := generated.New(s.pool).ListScopedDeviceGroups(
		ctx,
		generated.ListScopedDeviceGroupsParams{
			GlobalScope:    global,
			DeviceGroupIds: ids,
			PageLimit:      limit,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("store: list device groups: %w", err)
	}
	groups := make([]DeviceGroup, len(rows))
	for index, row := range rows {
		groups[index], err = validateDeviceGroupProjection(
			row.DeviceGroupID,
			row.Name,
			row.DynamicQuery,
			row.ProjectionVersion,
		)
		if err != nil {
			return nil, err
		}
	}
	return groups, nil
}

// IsDeviceGroupExists recognizes a duplicate device-group creation.
func IsDeviceGroupExists(err error) bool {
	return errors.Is(err, errDeviceGroupExists)
}

// DeviceGroupEventTypes returns the exact projector-backed mutation event set.
func DeviceGroupEventTypes() []string {
	return []string{
		deviceGroupCreatedEventType,
		deviceGroupUpdatedEventType,
		deviceGroupDeletedEventType,
	}
}

func deviceGroupEvent(id, eventType string, payload []byte) Event {
	return Event{
		StreamType:     deviceGroupStreamType,
		StreamID:       id,
		EventType:      eventType,
		PayloadVersion: deviceGroupPayloadVersion,
		Payload:        payload,
	}
}

func normalizeDeviceGroup(id, name, dynamicQuery string) (string, string, string, error) {
	id, err := canonicalDeviceGroupID(id)
	if err != nil {
		return "", "", "", err
	}
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) < 1 ||
		utf8.RuneCountInString(name) > maxDeviceGroupNameRunes {
		return "", "", "", errors.New("store: device-group name is invalid")
	}
	if !utf8.ValidString(dynamicQuery) ||
		utf8.RuneCountInString(dynamicQuery) > maxDeviceGroupQueryRunes {
		return "", "", "", errors.New("store: device-group query is invalid")
	}
	return id, name, dynamicQuery, nil
}

func canonicalDeviceGroupID(id string) (string, error) {
	if err := validate.ULIDPathID(id); err != nil {
		return "", fmt.Errorf("store: device-group ID is invalid: %w", err)
	}
	return strings.ToUpper(id), nil
}

func normalizeDeviceGroupScope(ids []string) ([]string, error) {
	normalized := make([]string, len(ids))
	for index, id := range ids {
		var err error
		normalized[index], err = canonicalDeviceGroupID(id)
		if err != nil {
			return nil, err
		}
	}
	slices.Sort(normalized)
	normalized = slices.Compact(normalized)
	return normalized, nil
}

func validateDeviceGroupProjection(
	id string,
	name string,
	dynamicQuery string,
	version int64,
) (DeviceGroup, error) {
	canonicalID, canonicalName, canonicalQuery, err := normalizeDeviceGroup(
		id,
		name,
		dynamicQuery,
	)
	if err != nil || canonicalID != id || canonicalName != name || canonicalQuery != dynamicQuery ||
		version < 1 {
		return DeviceGroup{}, errors.New("store: device-group projection is invalid")
	}
	return DeviceGroup{
		ID:                id,
		Name:              name,
		DynamicQuery:      dynamicQuery,
		ProjectionVersion: version,
	}, nil
}

func deviceGroupEventDefinitions() map[string]eventDefinition {
	return map[string]eventDefinition{
		deviceGroupCreatedEventType: {
			PayloadVersion: deviceGroupPayloadVersion,
			PayloadType:    deviceGroupPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(deviceGroupPayload{
					Name:         "production",
					DynamicQuery: "platform = 'linux'",
				})
			},
			Projector: projectDeviceGroupCreated,
		},
		deviceGroupUpdatedEventType: {
			PayloadVersion: deviceGroupPayloadVersion,
			PayloadType:    deviceGroupPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(deviceGroupPayload{
					Name:         "production-linux",
					DynamicQuery: "platform = 'linux' AND environment = 'production'",
				})
			},
			Projector: projectDeviceGroupUpdated,
		},
		deviceGroupDeletedEventType: {
			PayloadVersion: deviceGroupPayloadVersion,
			PayloadType:    deviceGroupDeletedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(deviceGroupDeletedPayload{})
			},
			Projector: projectDeviceGroupDeleted,
		},
	}
}

func deviceGroupGoldenCorpus() map[string]goldenEvent {
	return map[string]goldenEvent{
		deviceGroupCreatedEventType: {
			PayloadVersion: deviceGroupPayloadVersion,
			Payload: []byte(
				`{"name":"production","dynamic_query":"platform = 'linux'"}`,
			),
		},
		deviceGroupUpdatedEventType: {
			PayloadVersion: deviceGroupPayloadVersion,
			Payload: []byte(
				`{"name":"production-linux","dynamic_query":"platform = 'linux' AND environment = 'production'"}`,
			),
		},
		deviceGroupDeletedEventType: {
			PayloadVersion: deviceGroupPayloadVersion,
			Payload:        []byte(`{}`),
		},
	}
}

func projectDeviceGroupCreated(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion != 1 {
		return errDeviceGroupExists
	}
	payload, err := decodeEventPayload[deviceGroupPayload](event, deviceGroupPayloadVersion)
	if err != nil {
		return err
	}
	group, err := validateDeviceGroupProjection(
		event.StreamID,
		payload.Name,
		payload.DynamicQuery,
		event.StreamVersion,
	)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).InsertDeviceGroup(
		ctx,
		generated.InsertDeviceGroupParams{
			DeviceGroupID:     group.ID,
			Name:              group.Name,
			DynamicQuery:      group.DynamicQuery,
			ProjectionVersion: group.ProjectionVersion,
			UpdatedAt:         event.CreatedAt,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project device-group creation: %w", err)
	}
	if affected != 1 {
		return errDeviceGroupExists
	}
	return nil
}

func projectDeviceGroupUpdated(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion < 2 {
		return errors.New("store: device-group update version is invalid")
	}
	payload, err := decodeEventPayload[deviceGroupPayload](event, deviceGroupPayloadVersion)
	if err != nil {
		return err
	}
	group, err := validateDeviceGroupProjection(
		event.StreamID,
		payload.Name,
		payload.DynamicQuery,
		event.StreamVersion,
	)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).ReplaceDeviceGroup(
		ctx,
		generated.ReplaceDeviceGroupParams{
			Name:                      group.Name,
			DynamicQuery:              group.DynamicQuery,
			ProjectionVersion:         group.ProjectionVersion,
			UpdatedAt:                 event.CreatedAt,
			DeviceGroupID:             group.ID,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project device-group update: %w", err)
	}
	if affected != 1 {
		return errors.New("store: device-group update projection version mismatch")
	}
	return nil
}

func projectDeviceGroupDeleted(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion < 2 {
		return errors.New("store: device-group deletion version is invalid")
	}
	if _, err := decodeEventPayload[deviceGroupDeletedPayload](
		event,
		deviceGroupPayloadVersion,
	); err != nil {
		return err
	}
	affected, err := generated.New(tx).DeleteDeviceGroup(
		ctx,
		generated.DeleteDeviceGroupParams{
			DeviceGroupID:     event.StreamID,
			ProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project device-group deletion: %w", err)
	}
	if affected != 1 {
		return errors.New("store: device-group deletion projection version mismatch")
	}
	return nil
}

func resetDeviceGroups(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetDeviceGroups(ctx); err != nil {
		return fmt.Errorf("store: reset device groups: %w", err)
	}
	return nil
}
