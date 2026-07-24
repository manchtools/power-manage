package contract_test

import (
	"testing"

	"google.golang.org/protobuf/proto"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
)

func TestGrantView_RoundTripPreservesVisibleActivation(t *testing.T) {
	want := &powermanagev1.GrantView{
		GrantId:       "01K0QJ3E5E8R4M0D8EV3Y4N6N1",
		PrincipalType: powermanagev1.AuthorizationPrincipalType_AUTHORIZATION_PRINCIPAL_TYPE_USER_GROUP,
		PrincipalId:   "01K0QJ3E5E8R4M0D8EV3Y4N6M0",
		RoleId:        "01K0QJ3E5E8R4M0D8EV3Y4N6N0",
		Scope: &powermanagev1.GrantScope{
			Kind: powermanagev1.AuthorizationScopeKind_AUTHORIZATION_SCOPE_KIND_DEVICE_GROUPS,
			ResourceIds: []string{
				"01K0QJ3E5E8R4M0D8EV3Y4N6N4",
			},
		},
		ActivePermissions:   []string{"devices.manage"},
		StrippedPermissions: []string{"roles.manage"},
		ProjectionVersion:   1,
	}
	encoded, err := proto.Marshal(want)
	if err != nil {
		t.Fatalf("marshal grant view: %v", err)
	}
	got := new(powermanagev1.GrantView)
	if err := proto.Unmarshal(encoded, got); err != nil {
		t.Fatalf("unmarshal grant view: %v", err)
	}
	if !proto.Equal(got, want) {
		t.Fatalf("grant view round trip = %v; want %v", got, want)
	}
}
