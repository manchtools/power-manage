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
	serverSettingStreamType     = "server-setting"
	serverSettingCreatedType    = "ServerSettingCreated"
	serverSettingUpdatedType    = "ServerSettingUpdated"
	serverSettingDeletedType    = "ServerSettingDeleted"
	serverSettingPayloadVersion = 1
	maxServerSettingNameBytes   = 128
	maxServerSettingValueBytes  = 4096

	// ServerSettingRebuildTarget is the CLI-only settings recovery target.
	ServerSettingRebuildTarget = "server-settings"
)

var errServerSettingExists = errors.New("store: server setting already exists")

// ServerSetting is one event-derived global control-plane setting.
type ServerSetting struct {
	ID                string
	Name              string
	Value             string
	ProjectionVersion int64
}

type serverSettingPayload struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type serverSettingDeletedPayload struct{}

// ServerSettingCreatedEvent records one setting.
func ServerSettingCreatedEvent(id, name, value string) (Event, error) {
	return newServerSettingEvent(id, name, value, serverSettingCreatedType)
}

// ServerSettingUpdatedEvent fully replaces one setting.
func ServerSettingUpdatedEvent(id, name, value string) (Event, error) {
	return newServerSettingEvent(id, name, value, serverSettingUpdatedType)
}

// ServerSettingDeletedEvent removes one setting projection.
func ServerSettingDeletedEvent(id string) (Event, error) {
	id, err := canonicalServerSettingID(id)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(serverSettingDeletedPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode server-setting deletion: %w", err)
	}
	return serverSettingEvent(id, serverSettingDeletedType, payload), nil
}

func newServerSettingEvent(id, name, value, eventType string) (Event, error) {
	setting, err := normalizeServerSetting(id, name, value, 1)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(serverSettingPayload{Name: setting.Name, Value: setting.Value})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode server setting: %w", err)
	}
	return serverSettingEvent(setting.ID, eventType, payload), nil
}

func serverSettingEvent(id, eventType string, payload []byte) Event {
	return Event{
		StreamType:     serverSettingStreamType,
		StreamID:       id,
		EventType:      eventType,
		PayloadVersion: serverSettingPayloadVersion,
		Payload:        payload,
	}
}

// ServerSettingByID reads one setting.
func (s *Store) ServerSettingByID(ctx context.Context, id string) (ServerSetting, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return ServerSetting{}, errors.New("store: invalid server-setting lookup")
	}
	id, err := canonicalServerSettingID(id)
	if err != nil {
		return ServerSetting{}, err
	}
	row, err := generated.New(s.pool).GetServerSetting(ctx, id)
	if err != nil {
		return ServerSetting{}, fmt.Errorf("store: read server setting: %w", err)
	}
	return normalizeServerSetting(
		row.SettingID,
		row.Name,
		row.Value,
		row.ProjectionVersion,
	)
}

// ListServerSettings returns one deterministic settings page.
func (s *Store) ListServerSettings(ctx context.Context, limit int32) ([]ServerSetting, error) {
	if s == nil || s.pool == nil || ctx == nil || limit < 1 || limit > 200 {
		return nil, errors.New("store: invalid server-setting list")
	}
	rows, err := generated.New(s.pool).ListServerSettings(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("store: list server settings: %w", err)
	}
	settings := make([]ServerSetting, len(rows))
	for index, row := range rows {
		settings[index], err = normalizeServerSetting(
			row.SettingID,
			row.Name,
			row.Value,
			row.ProjectionVersion,
		)
		if err != nil {
			return nil, err
		}
	}
	return settings, nil
}

// ServerSettingEventTypes returns the exact setting mutation set.
func ServerSettingEventTypes() []string {
	return []string{
		serverSettingCreatedType,
		serverSettingUpdatedType,
		serverSettingDeletedType,
	}
}

// IsServerSettingExists recognizes duplicate setting creation.
func IsServerSettingExists(err error) bool {
	return errors.Is(err, errServerSettingExists)
}

func canonicalServerSettingID(id string) (string, error) {
	if err := validate.ULIDPathID(id); err != nil {
		return "", fmt.Errorf("store: invalid server-setting ID: %w", err)
	}
	return strings.ToUpper(id), nil
}

func normalizeServerSetting(
	id string,
	name string,
	value string,
	version int64,
) (ServerSetting, error) {
	id, err := canonicalServerSettingID(id)
	if err != nil {
		return ServerSetting{}, err
	}
	if !validServerSettingText(name, 1, maxServerSettingNameBytes) ||
		!validServerSettingText(value, 0, maxServerSettingValueBytes) ||
		version < 1 {
		return ServerSetting{}, errors.New("store: server setting is invalid")
	}
	return ServerSetting{
		ID:                id,
		Name:              name,
		Value:             value,
		ProjectionVersion: version,
	}, nil
}

func validServerSettingText(value string, minimum, maximum int) bool {
	return len(value) >= minimum &&
		len(value) <= maximum &&
		utf8.ValidString(value) &&
		!strings.ContainsRune(value, '\x00')
}

func serverSettingEventDefinitions() map[string]eventDefinition {
	goldenPayload := func() ([]byte, error) {
		return json.Marshal(serverSettingPayload{Name: "display-name", Value: "Power Manage"})
	}
	return map[string]eventDefinition{
		serverSettingCreatedType: {
			PayloadVersion: serverSettingPayloadVersion,
			PayloadType:    serverSettingPayload{},
			GoldenPayload:  goldenPayload,
			Projector:      projectServerSettingCreate,
		},
		serverSettingUpdatedType: {
			PayloadVersion: serverSettingPayloadVersion,
			PayloadType:    serverSettingPayload{},
			GoldenPayload:  goldenPayload,
			Projector:      projectServerSettingUpdate,
		},
		serverSettingDeletedType: {
			PayloadVersion: serverSettingPayloadVersion,
			PayloadType:    serverSettingDeletedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(serverSettingDeletedPayload{})
			},
			Projector: projectServerSettingDelete,
		},
	}
}

func serverSettingGoldenCorpus() map[string]goldenEvent {
	payload := []byte(`{"name":"display-name","value":"Power Manage"}`)
	return map[string]goldenEvent{
		serverSettingCreatedType: {
			PayloadVersion: serverSettingPayloadVersion,
			Payload:        payload,
		},
		serverSettingUpdatedType: {
			PayloadVersion: serverSettingPayloadVersion,
			Payload:        payload,
		},
		serverSettingDeletedType: {
			PayloadVersion: serverSettingPayloadVersion,
			Payload:        []byte(`{}`),
		},
	}
}

func projectServerSettingCreate(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion != 1 {
		return errServerSettingExists
	}
	setting, err := serverSettingFromEvent(event)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).InsertServerSetting(
		ctx,
		generated.InsertServerSettingParams{
			SettingID:         setting.ID,
			Name:              setting.Name,
			Value:             setting.Value,
			ProjectionVersion: event.StreamVersion,
			UpdatedAt:         event.CreatedAt,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project server-setting creation: %w", err)
	}
	if affected != 1 {
		return errServerSettingExists
	}
	return nil
}

func projectServerSettingUpdate(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: server-setting update requires creation")
	}
	setting, err := serverSettingFromEvent(event)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).ReplaceServerSetting(
		ctx,
		generated.ReplaceServerSettingParams{
			Name:                      setting.Name,
			Value:                     setting.Value,
			ProjectionVersion:         event.StreamVersion,
			UpdatedAt:                 event.CreatedAt,
			SettingID:                 setting.ID,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project server-setting update: %w", err)
	}
	if affected != 1 {
		return errors.New("store: server-setting update conflicts with projection")
	}
	return nil
}

func projectServerSettingDelete(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: server-setting deletion requires creation")
	}
	if _, err := decodeEventPayload[serverSettingDeletedPayload](
		event,
		serverSettingPayloadVersion,
	); err != nil {
		return err
	}
	id, err := canonicalServerSettingID(event.StreamID)
	if err != nil || id != event.StreamID {
		return errors.New("store: server-setting deletion ID is invalid")
	}
	affected, err := generated.New(tx).DeleteServerSetting(
		ctx,
		generated.DeleteServerSettingParams{
			SettingID:                 id,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project server-setting deletion: %w", err)
	}
	if affected != 1 {
		return errors.New("store: server-setting deletion conflicts with projection")
	}
	return nil
}

func serverSettingFromEvent(event PersistedEvent) (ServerSetting, error) {
	payload, err := decodeEventPayload[serverSettingPayload](
		event,
		serverSettingPayloadVersion,
	)
	if err != nil {
		return ServerSetting{}, err
	}
	return normalizeServerSetting(
		event.StreamID,
		payload.Name,
		payload.Value,
		event.StreamVersion,
	)
}

func resetServerSettings(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetServerSettings(ctx); err != nil {
		return fmt.Errorf("store: reset server settings: %w", err)
	}
	return nil
}
