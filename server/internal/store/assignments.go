package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	assignmentStreamType     = "assignment"
	assignmentCreatedType    = "AssignmentCreated"
	assignmentDeletedType    = "AssignmentDeleted"
	assignmentPayloadVersion = 1

	// AssignmentRebuildTarget is the CLI-only assignment recovery target.
	AssignmentRebuildTarget = "assignments"
)

// AssignmentSourceKind identifies the assigned definition class.
type AssignmentSourceKind string

const (
	AssignmentSourceAction    AssignmentSourceKind = "action"
	AssignmentSourceActionSet AssignmentSourceKind = "action_set"
)

// AssignmentTargetKind identifies one direct assignment target.
type AssignmentTargetKind string

const (
	AssignmentTargetDevice      AssignmentTargetKind = "device"
	AssignmentTargetUser        AssignmentTargetKind = "user"
	AssignmentTargetDeviceGroup AssignmentTargetKind = "device_group"
	AssignmentTargetUserGroup   AssignmentTargetKind = "user_group"
)

// AssignmentMode controls whether authored state is applied or forced absent.
type AssignmentMode string

const (
	AssignmentModeApply     AssignmentMode = "apply"
	AssignmentModeUninstall AssignmentMode = "uninstall"
)

var errAssignmentExists = errors.New("store: assignment already exists")

// Assignment is one immutable source-to-target binding.
type Assignment struct {
	ID                string
	SourceKind        AssignmentSourceKind
	SourceID          string
	TargetKind        AssignmentTargetKind
	TargetID          string
	Mode              AssignmentMode
	ProjectionVersion int64
}

type assignmentPayload struct {
	SourceKind AssignmentSourceKind `json:"source_kind"`
	SourceID   string               `json:"source_id"`
	TargetKind AssignmentTargetKind `json:"target_kind"`
	TargetID   string               `json:"target_id"`
	Mode       AssignmentMode       `json:"mode"`
}

type assignmentDeletedPayload struct{}

// AssignmentCreatedEvent records one immutable assignment.
func AssignmentCreatedEvent(assignment Assignment) (Event, error) {
	assignment, err := normalizeAssignment(assignment, 1)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(assignmentPayload{
		SourceKind: assignment.SourceKind,
		SourceID:   assignment.SourceID,
		TargetKind: assignment.TargetKind,
		TargetID:   assignment.TargetID,
		Mode:       assignment.Mode,
	})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode assignment: %w", err)
	}
	return assignmentEvent(assignment.ID, assignmentCreatedType, payload), nil
}

// AssignmentDeletedEvent removes one assignment projection.
func AssignmentDeletedEvent(id string) (Event, error) {
	id, err := canonicalAssignmentID(id)
	if err != nil {
		return Event{}, err
	}
	payload, err := json.Marshal(assignmentDeletedPayload{})
	if err != nil {
		return Event{}, fmt.Errorf("store: encode assignment deletion: %w", err)
	}
	return assignmentEvent(id, assignmentDeletedType, payload), nil
}

func assignmentEvent(id, eventType string, payload []byte) Event {
	return Event{
		StreamType:     assignmentStreamType,
		StreamID:       id,
		EventType:      eventType,
		PayloadVersion: assignmentPayloadVersion,
		Payload:        payload,
	}
}

// AssignmentByID reads one assignment through its direct target predicate.
func (s *Store) AssignmentByID(
	ctx context.Context,
	id string,
	global bool,
	deviceGroupIDs []string,
	userGroupIDs []string,
	selfID string,
) (Assignment, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return Assignment{}, errors.New("store: invalid assignment lookup")
	}
	id, err := canonicalAssignmentID(id)
	if err != nil {
		return Assignment{}, err
	}
	deviceGroupIDs, err = normalizeDeviceGroupScope(deviceGroupIDs)
	if err != nil {
		return Assignment{}, err
	}
	userGroupIDs, err = normalizeUserScopeIDs(userGroupIDs)
	if err != nil {
		return Assignment{}, err
	}
	if selfID != "" {
		selfID, err = canonicalUserID(selfID)
		if err != nil {
			return Assignment{}, err
		}
	}
	row, err := generated.New(s.pool).GetScopedAssignment(
		ctx,
		generated.GetScopedAssignmentParams{
			AssignmentID:   id,
			GlobalScope:    global,
			DeviceGroupIds: deviceGroupIDs,
			UserGroupIds:   userGroupIDs,
			SelfID:         selfID,
		},
	)
	if err != nil {
		return Assignment{}, fmt.Errorf("store: read assignment: %w", err)
	}
	return normalizeAssignment(Assignment{
		ID: row.AssignmentID, SourceKind: AssignmentSourceKind(row.SourceKind),
		SourceID: row.SourceID, TargetKind: AssignmentTargetKind(row.TargetKind),
		TargetID: row.TargetID, Mode: AssignmentMode(row.Mode),
	}, row.ProjectionVersion)
}

// ListAssignments returns one scope-confined assignment page.
func (s *Store) ListAssignments(
	ctx context.Context,
	global bool,
	deviceGroupIDs []string,
	userGroupIDs []string,
	selfID string,
	limit int32,
) ([]Assignment, error) {
	if s == nil || s.pool == nil || ctx == nil || limit < 1 || limit > 200 {
		return nil, errors.New("store: invalid assignment list")
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
	rows, err := generated.New(s.pool).ListScopedAssignments(
		ctx,
		generated.ListScopedAssignmentsParams{
			GlobalScope:    global,
			DeviceGroupIds: deviceGroupIDs,
			UserGroupIds:   userGroupIDs,
			SelfID:         selfID,
			PageLimit:      limit,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("store: list assignments: %w", err)
	}
	assignments := make([]Assignment, len(rows))
	for index, row := range rows {
		assignments[index], err = normalizeAssignment(Assignment{
			ID: row.AssignmentID, SourceKind: AssignmentSourceKind(row.SourceKind),
			SourceID: row.SourceID, TargetKind: AssignmentTargetKind(row.TargetKind),
			TargetID: row.TargetID, Mode: AssignmentMode(row.Mode),
		}, row.ProjectionVersion)
		if err != nil {
			return nil, err
		}
	}
	return assignments, nil
}

// AssignmentEventTypes returns the exact immutable assignment mutation set.
func AssignmentEventTypes() []string {
	return []string{assignmentCreatedType, assignmentDeletedType}
}

// IsAssignmentExists recognizes duplicate assignment creation.
func IsAssignmentExists(err error) bool {
	return errors.Is(err, errAssignmentExists)
}

func canonicalAssignmentID(id string) (string, error) {
	if err := validate.ULIDPathID(id); err != nil {
		return "", fmt.Errorf("store: invalid assignment ID: %w", err)
	}
	return strings.ToUpper(id), nil
}

func normalizeAssignment(assignment Assignment, version int64) (Assignment, error) {
	id, err := canonicalAssignmentID(assignment.ID)
	if err != nil {
		return Assignment{}, err
	}
	sourceID, err := canonicalActionID(assignment.SourceID)
	if err != nil {
		return Assignment{}, errors.New("store: invalid assignment ID: source")
	}
	targetID, err := canonicalAssignmentID(assignment.TargetID)
	if err != nil {
		return Assignment{}, errors.New("store: invalid assignment ID: target")
	}
	if assignment.SourceKind != AssignmentSourceAction &&
		assignment.SourceKind != AssignmentSourceActionSet ||
		assignment.TargetKind != AssignmentTargetDevice &&
			assignment.TargetKind != AssignmentTargetUser &&
			assignment.TargetKind != AssignmentTargetDeviceGroup &&
			assignment.TargetKind != AssignmentTargetUserGroup ||
		assignment.Mode != AssignmentModeApply &&
			assignment.Mode != AssignmentModeUninstall ||
		version < 1 {
		return Assignment{}, errors.New("store: assignment is invalid")
	}
	assignment.ID = id
	assignment.SourceID = sourceID
	assignment.TargetID = targetID
	assignment.ProjectionVersion = version
	return assignment, nil
}

func assignmentEventDefinitions() map[string]eventDefinition {
	golden := assignmentPayload{
		SourceKind: AssignmentSourceAction,
		SourceID:   "01J00000000000000000000001",
		TargetKind: AssignmentTargetDeviceGroup,
		TargetID:   "01J00000000000000000000002",
		Mode:       AssignmentModeApply,
	}
	return map[string]eventDefinition{
		assignmentCreatedType: {
			PayloadVersion: assignmentPayloadVersion,
			PayloadType:    assignmentPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(golden)
			},
			Projector: projectAssignmentCreate,
		},
		assignmentDeletedType: {
			PayloadVersion: assignmentPayloadVersion,
			PayloadType:    assignmentDeletedPayload{},
			GoldenPayload: func() ([]byte, error) {
				return json.Marshal(assignmentDeletedPayload{})
			},
			Projector: projectAssignmentDelete,
		},
	}
}

func assignmentGoldenCorpus() map[string]goldenEvent {
	return map[string]goldenEvent{
		assignmentCreatedType: {
			PayloadVersion: assignmentPayloadVersion,
			Payload: []byte(
				`{"source_kind":"action","source_id":"01J00000000000000000000001","target_kind":"device_group","target_id":"01J00000000000000000000002","mode":"apply"}`,
			),
		},
		assignmentDeletedType: {
			PayloadVersion: assignmentPayloadVersion,
			Payload:        []byte(`{}`),
		},
	}
}

func projectAssignmentCreate(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion != 1 {
		return errAssignmentExists
	}
	assignment, err := assignmentFromEvent(event)
	if err != nil {
		return err
	}
	affected, err := generated.New(tx).InsertAssignment(
		ctx,
		generated.InsertAssignmentParams{
			AssignmentID:      assignment.ID,
			SourceKind:        string(assignment.SourceKind),
			SourceID:          assignment.SourceID,
			TargetKind:        string(assignment.TargetKind),
			TargetID:          assignment.TargetID,
			Mode:              string(assignment.Mode),
			ProjectionVersion: event.StreamVersion,
			UpdatedAt:         event.CreatedAt,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project assignment creation: %w", err)
	}
	if affected != 1 {
		return errAssignmentExists
	}
	return nil
}

func projectAssignmentDelete(
	ctx context.Context,
	tx ProjectionTx,
	event PersistedEvent,
) error {
	if event.StreamVersion <= 1 {
		return errors.New("store: assignment deletion requires creation")
	}
	if _, err := decodeEventPayload[assignmentDeletedPayload](
		event,
		assignmentPayloadVersion,
	); err != nil {
		return err
	}
	id, err := canonicalAssignmentID(event.StreamID)
	if err != nil || id != event.StreamID {
		return errors.New("store: invalid assignment ID: deletion stream")
	}
	affected, err := generated.New(tx).DeleteAssignment(
		ctx,
		generated.DeleteAssignmentParams{
			AssignmentID:              id,
			PreviousProjectionVersion: event.StreamVersion - 1,
		},
	)
	if err != nil {
		return fmt.Errorf("store: project assignment deletion: %w", err)
	}
	if affected != 1 {
		return errors.New("store: assignment deletion conflicts with projection")
	}
	return nil
}

func assignmentFromEvent(event PersistedEvent) (Assignment, error) {
	payload, err := decodeEventPayload[assignmentPayload](
		event,
		assignmentPayloadVersion,
	)
	if err != nil {
		return Assignment{}, err
	}
	if id, err := canonicalAssignmentID(event.StreamID); err != nil ||
		id != event.StreamID {
		return Assignment{}, errors.New("store: invalid assignment ID: stream")
	}
	return normalizeAssignment(Assignment{
		ID: event.StreamID, SourceKind: payload.SourceKind, SourceID: payload.SourceID,
		TargetKind: payload.TargetKind, TargetID: payload.TargetID, Mode: payload.Mode,
	}, event.StreamVersion)
}

func resetAssignments(ctx context.Context, tx ProjectionTx) error {
	if err := generated.New(tx).ResetAssignments(ctx); err != nil {
		return fmt.Errorf("store: reset assignments: %w", err)
	}
	return nil
}
