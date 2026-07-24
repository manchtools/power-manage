package store

import (
	"strings"
	"testing"
)

func TestActionRebuilds_PreserveSystemManagedRows(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	const (
		systemActionID    = "01J00000000000000000000188"
		systemActionSetID = "01J00000000000000000000189"
	)
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO managed_actions (
			action_id, name, params, system_managed, projection_version, updated_at
		) VALUES (
			$1, 'system action', '\x01', true, 1, now()
		)`,
		systemActionID,
	); err != nil {
		t.Fatalf("seed system-managed action: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `
		INSERT INTO managed_action_sets (
			action_set_id, name, system_managed, projection_version, updated_at
		) VALUES (
			$1, 'system set', true, 1, now()
		)`,
		systemActionSetID,
	); err != nil {
		t.Fatalf("seed system-managed action set: %v", err)
	}
	for _, target := range []string{ActionRebuildTarget, ActionSetRebuildTarget} {
		if err := eventStore.RebuildAll(t.Context(), target); err != nil {
			t.Fatalf("rebuild %s: %v", target, err)
		}
	}
	var actionExists, actionSetExists bool
	if err := pool.QueryRow(t.Context(), `
		SELECT
			EXISTS (
				SELECT 1 FROM managed_actions
				WHERE action_id = $1 AND system_managed
			),
			EXISTS (
				SELECT 1 FROM managed_action_sets
				WHERE action_set_id = $2 AND system_managed
			)`,
		systemActionID,
		systemActionSetID,
	).Scan(&actionExists, &actionSetExists); err != nil {
		t.Fatalf("inspect seeded system-managed action rows: %v", err)
	}
	if !actionExists || !actionSetExists {
		t.Fatalf(
			"seeded system-managed rows after rebuild = (%t action, %t set); want both true",
			actionExists,
			actionSetExists,
		)
	}
}

func TestAssignmentFromEvent_RejectsNoncanonicalStreamID(t *testing.T) {
	event, err := AssignmentCreatedEvent(Assignment{
		ID:         "01J00000000000000000000190",
		SourceKind: AssignmentSourceAction,
		SourceID:   "01J00000000000000000000191",
		TargetKind: AssignmentTargetDevice,
		TargetID:   "01J00000000000000000000192",
		Mode:       AssignmentModeApply,
	})
	if err != nil {
		t.Fatalf("create assignment event: %v", err)
	}
	event.StreamID = strings.ToLower(event.StreamID)
	_, err = assignmentFromEvent(PersistedEvent{Event: event, StreamVersion: 1})
	if err == nil || err.Error() != "store: invalid assignment ID: stream" {
		t.Fatalf(
			"assignment projector stream error = %v; want exact noncanonical stream rejection",
			err,
		)
	}
}
