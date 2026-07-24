package store

import (
	"errors"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manchtools/power-manage/server/internal/authz"
)

const (
	testAuthorizationRoleID        = "01K0QJ3E5E8R4M0D8EV3Y4N6N0"
	testAuthorizationGrantID       = "01K0QJ3E5E8R4M0D8EV3Y4N6N1"
	testAuthorizationGroupGrantID  = "01K0QJ3E5E8R4M0D8EV3Y4N6N2"
	testAuthorizationNonmemberID   = "01K0QJ3E5E8R4M0D8EV3Y4N6N3"
	testAuthorizationDeviceGroupID = "01K0QJ3E5E8R4M0D8EV3Y4N6N4"
)

func TestAuthorization_GroupGrantResolvesOnlyForMembersAndRebuilds(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	appendAuthorizationUsers(t, eventStore, testBootstrapUserID, testAuthorizationNonmemberID)

	group, err := SCIMGroupCreatedEvent(
		testSCIMGroupID,
		testSCIMProviderSlug,
		"authorization-group",
		"Authorization Operators",
	)
	if err != nil {
		t.Fatalf("create authorization group: %v", err)
	}
	members, err := SCIMGroupMembershipsReplacedEvent(
		testSCIMGroupID,
		[]string{testBootstrapUserID},
	)
	if err != nil {
		t.Fatalf("create authorization group membership: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{group, members}); err != nil {
		t.Fatalf("append authorization group: %v", err)
	}

	role, err := AuthorizationRoleCreatedEvent(
		testAuthorizationRoleID,
		"device-readers",
		[]authz.Permission{"devices.manage", "roles.manage"},
	)
	if err != nil {
		t.Fatalf("create authorization role: %v", err)
	}
	grant, err := AuthorizationGrantCreatedEvent(
		testAuthorizationGroupGrantID,
		authz.PrincipalUserGroup,
		testSCIMGroupID,
		testAuthorizationRoleID,
		authz.Scope{
			Kind: authz.ScopeDeviceGroups,
			IDs:  []string{testAuthorizationDeviceGroupID},
		},
	)
	if err != nil {
		t.Fatalf("create authorization grant: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{role, grant}); err != nil {
		t.Fatalf("append authorization role and grant: %v", err)
	}

	want := authz.EffectiveAccess{
		Grants: []authz.GrantAccess{{
			GrantID:             testAuthorizationGroupGrantID,
			ActivePermissions:   []authz.Permission{"devices.manage"},
			StrippedPermissions: []authz.Permission{"roles.manage"},
		}},
		Permissions: map[authz.Permission]authz.Reach{
			"devices.manage": {DeviceGroupIDs: []string{testAuthorizationDeviceGroupID}},
		},
	}
	got, err := eventStore.ResolveEffectiveAccess(t.Context(), testBootstrapUserID)
	if err != nil {
		t.Fatalf("resolve member access: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("member access = %#v; want %#v", got, want)
	}
	nonmember, err := eventStore.ResolveEffectiveAccess(t.Context(), testAuthorizationNonmemberID)
	if err != nil {
		t.Fatalf("resolve nonmember access: %v", err)
	}
	if len(nonmember.Grants) != 0 || len(nonmember.Permissions) != 0 {
		t.Fatalf("nonmember inherited group access: %#v", nonmember)
	}

	if _, err := pool.Exec(
		t.Context(),
		`DELETE FROM authorization_grants; DELETE FROM authorization_roles`,
	); err != nil {
		t.Fatalf("delete authorization projections: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), AuthorizationRebuildTarget); err != nil {
		t.Fatalf("rebuild authorization projections: %v", err)
	}
	rebuilt, err := eventStore.ResolveEffectiveAccess(t.Context(), testBootstrapUserID)
	if err != nil {
		t.Fatalf("resolve rebuilt member access: %v", err)
	}
	if !reflect.DeepEqual(rebuilt, want) {
		t.Fatalf("rebuilt member access = %#v; want %#v", rebuilt, want)
	}
}

func TestAuthorization_InvalidFactsWriteNothing(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	appendAuthorizationUsers(t, eventStore, testBootstrapUserID)

	tests := map[string]struct {
		makeEvent func() (Event, error)
		wantErr   error
	}{
		"unknown permission": {
			makeEvent: func() (Event, error) {
				return AuthorizationRoleCreatedEvent(
					testAuthorizationRoleID,
					"invalid-role",
					[]authz.Permission{"unknown.manage"},
				)
			},
			wantErr: authz.ErrInvalidRole,
		},
		"duplicate permission": {
			makeEvent: func() (Event, error) {
				return AuthorizationRoleCreatedEvent(
					testAuthorizationRoleID,
					"invalid-role",
					[]authz.Permission{"devices.manage", "devices.manage"},
				)
			},
			wantErr: authz.ErrInvalidRole,
		},
		"global scope with ID": {
			makeEvent: func() (Event, error) {
				return AuthorizationGrantCreatedEvent(
					testAuthorizationGrantID,
					authz.PrincipalUser,
					testBootstrapUserID,
					testAuthorizationRoleID,
					authz.Scope{
						Kind: authz.ScopeGlobal,
						IDs:  []string{testAuthorizationDeviceGroupID},
					},
				)
			},
			wantErr: authz.ErrInvalidGrant,
		},
		"duplicate scope ID": {
			makeEvent: func() (Event, error) {
				return AuthorizationGrantCreatedEvent(
					testAuthorizationGrantID,
					authz.PrincipalUser,
					testBootstrapUserID,
					testAuthorizationRoleID,
					authz.Scope{
						Kind: authz.ScopeDeviceGroups,
						IDs: []string{
							testAuthorizationDeviceGroupID,
							testAuthorizationDeviceGroupID,
						},
					},
				)
			},
			wantErr: authz.ErrInvalidGrant,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if event, err := test.makeEvent(); !errors.Is(err, test.wantErr) {
				t.Fatalf("event = %#v, error = %v; want %v", event, err, test.wantErr)
			}
		})
	}
	assertAuthorizationEventCount(t, pool, 0)

	validRole, err := AuthorizationRoleCreatedEvent(
		testAuthorizationRoleID,
		"operators",
		[]authz.Permission{"devices.manage"},
	)
	if err != nil {
		t.Fatalf("create valid role: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), validRole, 0); err != nil {
		t.Fatalf("append valid role: %v", err)
	}
	missingRoleGrant, err := AuthorizationGrantCreatedEvent(
		testAuthorizationGrantID,
		authz.PrincipalUser,
		testBootstrapUserID,
		testAuthorizationNonmemberID,
		authz.Scope{Kind: authz.ScopeGlobal},
	)
	if err != nil {
		t.Fatalf("create grant with missing role: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(
		t.Context(),
		missingRoleGrant,
		0,
	); !errors.Is(err, errAuthorizationRoleMissing) {
		t.Fatalf("append grant with missing role error = %v; want role missing", err)
	}
	assertAuthorizationEventCount(t, pool, 1)

	missingPrincipalGrant, err := AuthorizationGrantCreatedEvent(
		testAuthorizationGrantID,
		authz.PrincipalUser,
		testAuthorizationNonmemberID,
		testAuthorizationRoleID,
		authz.Scope{Kind: authz.ScopeGlobal},
	)
	if err != nil {
		t.Fatalf("create grant with missing principal: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(
		t.Context(),
		missingPrincipalGrant,
		0,
	); !errors.Is(err, errAuthorizationPrincipalMissing) {
		t.Fatalf("append grant with missing principal error = %v; want principal missing", err)
	}
	assertAuthorizationEventCount(t, pool, 1)
}

func TestAuthorization_ResolutionRejectsMissingAndDisabledUsers(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	if _, err := eventStore.ResolveEffectiveAccess(
		t.Context(),
		testBootstrapUserID,
	); !IsNotFound(err) {
		t.Fatalf("resolve missing user error = %v; want not found", err)
	}
	appendAuthorizationUsers(t, eventStore, testBootstrapUserID)
	disabled, err := UserDisabledEvent(testBootstrapUserID)
	if err != nil {
		t.Fatalf("create disabled-user event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(t.Context(), disabled, 1); err != nil {
		t.Fatalf("append disabled-user event: %v", err)
	}
	if _, err := eventStore.ResolveEffectiveAccess(
		t.Context(),
		testBootstrapUserID,
	); !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("resolve disabled user error = %v; want ErrUserDisabled", err)
	}
}

func TestAuthorization_ResolutionFailsClosedOnCorruptProjection(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	appendAuthorizationUsers(t, eventStore, testBootstrapUserID)
	role, err := AuthorizationRoleCreatedEvent(
		testAuthorizationRoleID,
		"operators",
		[]authz.Permission{"devices.manage"},
	)
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	grant, err := AuthorizationGrantCreatedEvent(
		testAuthorizationGrantID,
		authz.PrincipalUser,
		testBootstrapUserID,
		testAuthorizationRoleID,
		authz.Scope{Kind: authz.ScopeGlobal},
	)
	if err != nil {
		t.Fatalf("create grant: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []Event{role, grant}); err != nil {
		t.Fatalf("append role and grant: %v", err)
	}
	if _, err := pool.Exec(
		t.Context(),
		`UPDATE authorization_roles SET permissions = ARRAY['unknown.manage']`,
	); err != nil {
		t.Fatalf("corrupt role projection: %v", err)
	}
	if _, err := eventStore.ResolveEffectiveAccess(
		t.Context(),
		testBootstrapUserID,
	); !errors.Is(err, authz.ErrInvalidGrant) {
		t.Fatalf("resolve corrupt projection error = %v; want invalid grant", err)
	}
}

func appendAuthorizationUsers(t *testing.T, eventStore *Store, ids ...string) {
	t.Helper()
	for index, id := range ids {
		event, err := UserCreatedEvent(id, "authorization-"+string(rune('a'+index))+"@example.test")
		if err != nil {
			t.Fatalf("create authorization user %s: %v", id, err)
		}
		if err := eventStore.AppendEventWithVersion(t.Context(), event, 0); err != nil {
			t.Fatalf("append authorization user %s: %v", id, err)
		}
	}
}

func assertAuthorizationEventCount(t *testing.T, pool *pgxpool.Pool, want int) {
	t.Helper()
	var got int
	if err := pool.QueryRow(
		t.Context(),
		`SELECT count(*) FROM events WHERE stream_type IN ('authorization-role', 'authorization-grant')`,
	).Scan(&got); err != nil {
		t.Fatalf("count authorization events: %v", err)
	}
	if got != want {
		t.Fatalf("authorization event count = %d; want %d", got, want)
	}
}
