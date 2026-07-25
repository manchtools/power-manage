package control

import (
	"testing"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
)

func TestAuthorizationHandlers_LastAdminMapsStaticFailedPrecondition(t *testing.T) {
	eventStore, service := identityManagementService(t)
	_, err := service.DeleteGrant(
		identityContext(t, identityAdminID),
		connect.NewRequest(&powermanagev1.DeleteGrantRequest{
			Id:              identityAdminGrantID,
			ExpectedVersion: 1,
		}),
	)
	want := failedPreconditionCRUD()
	if err == nil ||
		connect.CodeOf(err) != connect.CodeOf(want) ||
		err.Error() != want.Error() {
		t.Fatalf("last-admin handler error = %v; want %v", err, want)
	}
	if _, err := eventStore.AuthorizationGrantByID(
		t.Context(),
		identityAdminGrantID,
	); err != nil {
		t.Fatalf("read grant after rejected deletion: %v", err)
	}
}
