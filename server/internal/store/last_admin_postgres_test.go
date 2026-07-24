package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/manchtools/power-manage/server/internal/authz"
	"github.com/manchtools/power-manage/server/internal/store/generated"
)

const (
	lastAdminUserOneID     = "01J00000000000000000000210"
	lastAdminUserTwoID     = "01J00000000000000000000211"
	lastAdminGroupID       = "01J00000000000000000000212"
	lastAdminRoleID        = "01J00000000000000000000213"
	lastAdminGrantOneID    = "01J00000000000000000000214"
	lastAdminGrantTwoID    = "01J00000000000000000000215"
	lastAdminGroupGrantID  = "01J00000000000000000000216"
	lastAdminBootstrapID   = "01J00000000000000000000217"
	lastAdminFallbackID    = "01J00000000000000000000218"
	lastAdminFallbackRole  = "01J00000000000000000000219"
	lastAdminFallbackGrant = "01J00000000000000000000220"
)

func TestLastAdminProtection_RejectsDirectRemovalPaths(t *testing.T) {
	tests := map[string]struct {
		event func(*testing.T) Event
	}{
		"delete grant": {
			event: func(t *testing.T) Event {
				t.Helper()
				event, err := AuthorizationGrantDeletedEvent(lastAdminGrantOneID)
				if err != nil {
					t.Fatalf("create grant deletion: %v", err)
				}
				return event
			},
		},
		"remove permission from role": {
			event: func(t *testing.T) Event {
				t.Helper()
				event, err := AuthorizationRoleUpdatedEvent(
					lastAdminRoleID,
					"administrators",
					[]authz.Permission{"devices.manage"},
				)
				if err != nil {
					t.Fatalf("create role update: %v", err)
				}
				return event
			},
		},
		"disable user": {
			event: func(t *testing.T) Event {
				t.Helper()
				event, err := UserDisabledEvent(lastAdminUserOneID)
				if err != nil {
					t.Fatalf("create user disable: %v", err)
				}
				return event
			},
		},
		"delete user": {
			event: func(t *testing.T) Event {
				t.Helper()
				event, err := UserManagedDeletedEvent(lastAdminUserOneID)
				if err != nil {
					t.Fatalf("create user deletion: %v", err)
				}
				return event
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			eventStore := newLastAdminStore(t)
			seedDirectAdmins(t, eventStore, lastAdminUserOneID)
			event := test.event(t)
			if err := eventStore.AppendEventWithVersion(
				t.Context(),
				event,
				1,
			); !errors.Is(err, ErrLastAdmin) {
				t.Fatalf("last-admin mutation error = %v; want ErrLastAdmin", err)
			}
			if got := enabledAdminCount(t, eventStore); got != 1 {
				t.Fatalf("enabled admins after rejection = %d; want one", got)
			}
			var eventCount int
			observeLastAdminDatabase(t, eventStore, func(observer *pgx.Conn) error {
				return observer.QueryRow(
					t.Context(),
					`SELECT count(*) FROM events WHERE event_type = $1`,
					event.EventType,
				).Scan(&eventCount)
			})
			if eventCount != 0 {
				t.Fatalf("rejected event count = %d; want zero", eventCount)
			}
		})
	}
}

func TestLastAdminProtection_PreservesGroupInheritedAdmin(t *testing.T) {
	eventStore := newLastAdminStore(t)
	seedDirectAdmins(t, eventStore, lastAdminUserOneID, lastAdminUserTwoID)
	group, err := UserGroupCreatedEvent(
		lastAdminGroupID,
		"admin-group",
		[]string{lastAdminUserTwoID},
	)
	if err != nil {
		t.Fatalf("create admin group: %v", err)
	}
	groupGrant, err := AuthorizationGrantCreatedEvent(
		lastAdminGroupGrantID,
		authz.PrincipalUserGroup,
		lastAdminGroupID,
		lastAdminRoleID,
		authz.Scope{Kind: authz.ScopeGlobal},
	)
	if err != nil {
		t.Fatalf("create group grant: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{group, groupGrant}); err != nil {
		t.Fatalf("append group admin facts: %v", err)
	}

	for _, grantID := range []string{lastAdminGrantOneID, lastAdminGrantTwoID} {
		deleted, err := AuthorizationGrantDeletedEvent(grantID)
		if err != nil {
			t.Fatalf("create direct grant deletion: %v", err)
		}
		if err := eventStore.AppendEventWithVersion(t.Context(), deleted, 1); err != nil {
			t.Fatalf("delete direct grant %s: %v", grantID, err)
		}
	}
	if got := enabledAdminCount(t, eventStore); got != 1 {
		t.Fatalf("group-inherited admins = %d; want one", got)
	}

	removeMember, err := UserGroupUpdatedEvent(lastAdminGroupID, "admin-group", nil)
	if err != nil {
		t.Fatalf("create group membership removal: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(
		t.Context(),
		removeMember,
		1,
	); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last group-admin removal error = %v; want ErrLastAdmin", err)
	}
	groupProjection, err := eventStore.UserGroupByID(
		t.Context(),
		lastAdminGroupID,
		true,
		nil,
	)
	if err != nil || len(groupProjection.MemberUserIDs) != 1 ||
		groupProjection.MemberUserIDs[0] != lastAdminUserTwoID {
		t.Fatalf(
			"group after rejected removal = (%+v, %v); want second user",
			groupProjection,
			err,
		)
	}
}

func TestLastAdminProtection_ConcurrentRemovalsLeaveOne(t *testing.T) {
	eventStore := newLastAdminStore(t)
	seedDirectAdmins(t, eventStore, lastAdminUserOneID, lastAdminUserTwoID)
	events := make([]Event, 0, 2)
	for _, grantID := range []string{lastAdminGrantOneID, lastAdminGrantTwoID} {
		event, err := AuthorizationGrantDeletedEvent(grantID)
		if err != nil {
			t.Fatalf("create concurrent grant deletion: %v", err)
		}
		events = append(events, event)
	}

	operationCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	start := make(chan struct{})
	ready := make(chan struct{}, len(events))
	results := make(chan error, len(events))
	for _, event := range events {
		go func(event Event) {
			ready <- struct{}{}
			select {
			case <-start:
				results <- eventStore.AppendEventWithVersion(operationCtx, event, 1)
			case <-operationCtx.Done():
				results <- operationCtx.Err()
			}
		}(event)
	}
	for range events {
		select {
		case <-ready:
		case <-operationCtx.Done():
			t.Fatal("timed out waiting for concurrent removals to become ready")
		}
	}
	close(start)

	var succeeded, protected int
	for range events {
		var err error
		select {
		case err = <-results:
		case <-operationCtx.Done():
			t.Fatal("timed out waiting for concurrent removal result")
		}
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrLastAdmin):
			protected++
		default:
			t.Fatalf("concurrent admin removal error = %v", err)
		}
	}
	if succeeded != 1 || protected != 1 {
		t.Fatalf(
			"concurrent removals = (%d succeeded, %d protected); want (1, 1)",
			succeeded,
			protected,
		)
	}
	if got := enabledAdminCount(t, eventStore); got != 1 {
		t.Fatalf("enabled admins after concurrent removals = %d; want one", got)
	}
}

func TestLastAdminProtection_ProtectsBootstrapRoleRevocation(t *testing.T) {
	eventStore := newLastAdminStore(t)
	created, err := UserCreatedEvent(lastAdminBootstrapID, "bootstrap@example.test")
	if err != nil {
		t.Fatalf("create bootstrap user: %v", err)
	}
	granted, err := BootstrapAdminRoleGrantedEvent(lastAdminBootstrapID)
	if err != nil {
		t.Fatalf("create bootstrap role grant: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{created, granted}); err != nil {
		t.Fatalf("append bootstrap admin: %v", err)
	}
	if got := enabledAdminCount(t, eventStore); got != 1 {
		t.Fatalf("bootstrap admin count = %d; want one", got)
	}

	revoked, err := RoleRevokedEvent(lastAdminBootstrapID, "admin")
	if err != nil {
		t.Fatalf("create bootstrap role revocation: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(
		t.Context(),
		revoked,
		2,
	); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("bootstrap revocation error = %v; want ErrLastAdmin", err)
	}

	seedFallbackAdmin(t, eventStore)
	if err := eventStore.AppendEventWithVersion(t.Context(), revoked, 2); err != nil {
		t.Fatalf("revoke bootstrap role with fallback admin: %v", err)
	}
	if got := enabledAdminCount(t, eventStore); got != 1 {
		t.Fatalf("admins after bootstrap revocation = %d; want one fallback", got)
	}
}

func TestEnabledAdminCount_MalformedHistoricalRevocationDoesNotFail(t *testing.T) {
	eventStore := newLastAdminStore(t)
	created, err := UserCreatedEvent(lastAdminBootstrapID, "bootstrap@example.test")
	if err != nil {
		t.Fatalf("create bootstrap user: %v", err)
	}
	granted, err := BootstrapAdminRoleGrantedEvent(lastAdminBootstrapID)
	if err != nil {
		t.Fatalf("create bootstrap role grant: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{created, granted}); err != nil {
		t.Fatalf("append bootstrap admin: %v", err)
	}
	// events.payload is bytea, so non-JSON bytes are constraint-valid and
	// reproduce the historical row that the count query must tolerate.
	observeLastAdminDatabase(t, eventStore, func(observer *pgx.Conn) error {
		_, err := observer.Exec(
			t.Context(),
			`INSERT INTO events (
				stream_type, stream_id, stream_version,
				event_type, payload_version, payload
			) VALUES ('user', $1, 3, 'RoleRevoked', 1, $2)`,
			lastAdminBootstrapID,
			[]byte("malformed historical payload"),
		)
		return err
	})
	if got := enabledAdminCount(t, eventStore); got != 1 {
		t.Fatalf("bootstrap admins after malformed revocation = %d; want one", got)
	}
}

func newLastAdminStore(t *testing.T) *Store {
	t.Helper()
	pool := testPostgres(t) // The shared harness registers pool.Close with t.Cleanup.
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	return eventStore
}

func seedDirectAdmins(t *testing.T, eventStore *Store, userIDs ...string) {
	t.Helper()
	emails := []string{"admin-a@example.test", "admin-b@example.test"}
	grantIDs := []string{lastAdminGrantOneID, lastAdminGrantTwoID}
	if len(userIDs) > len(grantIDs) {
		t.Fatalf("seed direct admins: %d users exceeds fixture capacity", len(userIDs))
	}
	events := make([]Event, 0, len(userIDs)*2+1)
	for index, userID := range userIDs {
		user, err := UserCreatedEvent(userID, emails[index])
		if err != nil {
			t.Fatalf("create admin user: %v", err)
		}
		events = append(events, user)
	}
	role, err := AuthorizationRoleCreatedEvent(
		lastAdminRoleID,
		"administrators",
		[]authz.Permission{"devices.manage", "roles.manage"},
	)
	if err != nil {
		t.Fatalf("create admin role: %v", err)
	}
	events = append(events, role)
	for index, userID := range userIDs {
		grant, err := AuthorizationGrantCreatedEvent(
			grantIDs[index],
			authz.PrincipalUser,
			userID,
			lastAdminRoleID,
			authz.Scope{Kind: authz.ScopeGlobal},
		)
		if err != nil {
			t.Fatalf("create admin grant: %v", err)
		}
		events = append(events, grant)
	}
	if err := eventStore.AppendEvents(t.Context(), events); err != nil {
		t.Fatalf("append direct admins: %v", err)
	}
}

func seedFallbackAdmin(t *testing.T, eventStore *Store) {
	t.Helper()
	user, err := UserCreatedEvent(lastAdminFallbackID, "fallback@example.test")
	if err != nil {
		t.Fatalf("create fallback user: %v", err)
	}
	role, err := AuthorizationRoleCreatedEvent(
		lastAdminFallbackRole,
		"fallback-administrators",
		[]authz.Permission{"roles.manage"},
	)
	if err != nil {
		t.Fatalf("create fallback role: %v", err)
	}
	grant, err := AuthorizationGrantCreatedEvent(
		lastAdminFallbackGrant,
		authz.PrincipalUser,
		lastAdminFallbackID,
		lastAdminFallbackRole,
		authz.Scope{Kind: authz.ScopeGlobal},
	)
	if err != nil {
		t.Fatalf("create fallback grant: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{user, role, grant}); err != nil {
		t.Fatalf("append fallback admin: %v", err)
	}
}

func enabledAdminCount(t *testing.T, eventStore *Store) int64 {
	t.Helper()
	var count int64
	observeLastAdminDatabase(t, eventStore, func(observer *pgx.Conn) error {
		var err error
		count, err = generated.New(observer).CountEnabledAdmins(
			t.Context(),
			string(authz.Permission("roles.manage")),
		)
		return err
	})
	return count
}

func observeLastAdminDatabase(
	t *testing.T,
	eventStore *Store,
	observe func(*pgx.Conn) error,
) {
	t.Helper()
	if eventStore == nil || eventStore.pool == nil || observe == nil {
		t.Fatal("observe last-admin database: invalid fixture")
	}
	observer, err := pgx.Connect(
		t.Context(),
		eventStore.pool.Config().ConnString(),
	)
	if err != nil {
		t.Fatalf("connect last-admin observer: %v", err)
	}
	observeErr := observe(observer)
	closeCtx, cancelClose := context.WithTimeout(context.Background(), 5*time.Second)
	closeErr := observer.Close(closeCtx)
	cancelClose()
	if observeErr != nil {
		t.Fatalf("observe last-admin database: %v", observeErr)
	}
	if closeErr != nil {
		t.Fatalf("close last-admin observer: %v", closeErr)
	}
}
