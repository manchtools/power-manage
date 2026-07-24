package authz

import (
	"errors"
	"reflect"
	"testing"
)

const (
	testGrantID       = "01K0QJ3E5E8R4M0D8EV3Y4N6M2"
	testSecondGrantID = "01K0QJ3E5E8R4M0D8EV3Y4N6M3"
	testRoleID        = "01K0QJ3E5E8R4M0D8EV3Y4N6M4"
	testUserID        = "01K0QJ3E5E8R4M0D8EV3Y4N6M5"
	testGroupID       = "01K0QJ3E5E8R4M0D8EV3Y4N6M6"
	testDeviceGroupID = "01K0QJ3E5E8R4M0D8EV3Y4N6M7"
	testUserGroupID   = "01K0QJ3E5E8R4M0D8EV3Y4N6M8"
)

func TestResolve_ReportsScopedStripping(t *testing.T) {
	got, err := Resolve([]Grant{{
		ID:            testGrantID,
		PrincipalType: PrincipalUser,
		PrincipalID:   testUserID,
		RoleID:        testRoleID,
		Permissions:   []Permission{"devices.manage", "roles.manage"},
		Scope: Scope{
			Kind: ScopeDeviceGroups,
			IDs:  []string{testDeviceGroupID},
		},
	}})
	if err != nil {
		t.Fatalf("resolve scoped grant: %v", err)
	}
	want := EffectiveAccess{
		Grants: []GrantAccess{{
			GrantID:             testGrantID,
			ActivePermissions:   []Permission{"devices.manage"},
			StrippedPermissions: []Permission{"roles.manage"},
		}},
		Permissions: map[Permission]Reach{
			"devices.manage": {DeviceGroupIDs: []string{testDeviceGroupID}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Resolve() = %#v; want %#v", got, want)
	}
}

func TestResolve_GlobalGrantActivatesEntireRole(t *testing.T) {
	got, err := Resolve([]Grant{{
		ID:            testGrantID,
		PrincipalType: PrincipalUser,
		PrincipalID:   testUserID,
		RoleID:        testRoleID,
		Permissions:   []Permission{"devices.manage", "roles.manage"},
		Scope:         Scope{Kind: ScopeGlobal},
	}})
	if err != nil {
		t.Fatalf("resolve global grant: %v", err)
	}
	for _, permission := range []Permission{"devices.manage", "roles.manage"} {
		if reach := got.Permissions[permission]; !reach.Global {
			t.Fatalf("%s reach = %#v; want global", permission, reach)
		}
	}
	if stripped := got.Grants[0].StrippedPermissions; len(stripped) != 0 {
		t.Fatalf("global grant stripped permissions: %v", stripped)
	}
}

func TestResolve_UnionsOnlyMatchingPermissionReach(t *testing.T) {
	got, err := Resolve([]Grant{
		{
			ID:            testGrantID,
			PrincipalType: PrincipalUser,
			PrincipalID:   testUserID,
			RoleID:        testRoleID,
			Permissions:   []Permission{"audit.read", "devices.manage"},
			Scope: Scope{
				Kind: ScopeDeviceGroups,
				IDs:  []string{testDeviceGroupID},
			},
		},
		{
			ID:            testSecondGrantID,
			PrincipalType: PrincipalUserGroup,
			PrincipalID:   testGroupID,
			RoleID:        testRoleID,
			Permissions:   []Permission{"audit.read"},
			Scope:         Scope{Kind: ScopeGlobal},
		},
	})
	if err != nil {
		t.Fatalf("resolve direct and group grants: %v", err)
	}
	if reach := got.Permissions["audit.read"]; !reach.Global {
		t.Fatalf("audit.read reach = %#v; want global", reach)
	}
	if reach := got.Permissions["devices.manage"]; !reflect.DeepEqual(
		reach,
		Reach{DeviceGroupIDs: []string{testDeviceGroupID}},
	) {
		t.Fatalf("devices.manage reach = %#v; want only direct device-group scope", reach)
	}
}

func TestResolve_UnionsScopedReachDeterministically(t *testing.T) {
	got, err := Resolve([]Grant{
		{
			ID:            testSecondGrantID,
			PrincipalType: PrincipalUser,
			PrincipalID:   testUserID,
			RoleID:        testRoleID,
			Permissions:   []Permission{"users.manage"},
			Scope: Scope{
				Kind: ScopeUserGroups,
				IDs:  []string{testUserGroupID},
			},
		},
		{
			ID:            testGrantID,
			PrincipalType: PrincipalUser,
			PrincipalID:   testUserID,
			RoleID:        testRoleID,
			Permissions:   []Permission{"users.manage"},
			Scope:         Scope{Kind: ScopeSelf},
		},
	})
	if err != nil {
		t.Fatalf("resolve scoped union: %v", err)
	}
	want := Reach{UserGroupIDs: []string{testUserGroupID}, Self: true}
	if gotReach := got.Permissions["users.manage"]; !reflect.DeepEqual(gotReach, want) {
		t.Fatalf("users.manage reach = %#v; want %#v", gotReach, want)
	}
	if got.Grants[0].GrantID != testGrantID || got.Grants[1].GrantID != testSecondGrantID {
		t.Fatalf("grant order = %#v; want grant-ID order", got.Grants)
	}
}

func TestResolve_RejectsInvalidPersistedGrant(t *testing.T) {
	valid := Grant{
		ID:            testGrantID,
		PrincipalType: PrincipalUser,
		PrincipalID:   testUserID,
		RoleID:        testRoleID,
		Permissions:   []Permission{"devices.manage"},
		Scope:         Scope{Kind: ScopeGlobal},
	}
	tests := map[string]Grant{
		"unknown permission": func() Grant {
			grant := valid
			grant.Permissions = []Permission{"unknown.manage"}
			return grant
		}(),
		"duplicate permission": func() Grant {
			grant := valid
			grant.Permissions = []Permission{"devices.manage", "devices.manage"}
			return grant
		}(),
		"unknown principal type": func() Grant {
			grant := valid
			grant.PrincipalType = PrincipalType("unknown")
			return grant
		}(),
		"global scope with IDs": func() Grant {
			grant := valid
			grant.Scope.IDs = []string{testDeviceGroupID}
			return grant
		}(),
		"duplicate scope ID": func() Grant {
			grant := valid
			grant.Scope = Scope{
				Kind: ScopeDeviceGroups,
				IDs:  []string{testDeviceGroupID, testDeviceGroupID},
			}
			return grant
		}(),
	}
	for name, grant := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Resolve([]Grant{grant}); !errors.Is(err, ErrInvalidGrant) {
				t.Fatalf("Resolve() error = %v; want ErrInvalidGrant", err)
			}
		})
	}
}
