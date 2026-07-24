package control

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
)

const managementRegistrationTokenID = "01J00000000000000000000142"

func TestRegistrationTokenHandlers_OneTimeCredentialMetadataAndDelete(t *testing.T) {
	eventStore, service := identityManagementService(t)
	admin := identityContext(t, identityAdminID)
	expiresAt := time.Now().UTC().Add(2 * time.Hour)
	created, err := service.CreateRegistrationToken(admin, connect.NewRequest(
		&powermanagev1.CreateRegistrationTokenRequest{
			Id:        managementRegistrationTokenID,
			Purpose:   powermanagev1.RegistrationTokenPurpose_REGISTRATION_TOKEN_PURPOSE_AGENT,
			MaxUses:   2,
			ExpiresAt: timestamppb.New(expiresAt),
			Owner:     "device-owner@example.test",
		},
	))
	if err != nil {
		t.Fatalf("create registration token: %v", err)
	}
	metadata := created.Msg.GetRegistrationToken()
	if metadata.GetId() != managementRegistrationTokenID ||
		metadata.GetState() != powermanagev1.RegistrationTokenState_REGISTRATION_TOKEN_STATE_ACTIVE ||
		metadata.GetVersion() != 1 {
		t.Fatalf("created registration-token metadata = %#v; want active version one", metadata)
	}
	parts := strings.Split(created.Msg.GetCredential(), ".")
	if len(parts) != 2 || parts[0] != managementRegistrationTokenID {
		t.Fatalf("created credential has invalid public framing")
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(secret) != registrationTokenSecretSize {
		t.Fatalf("decode created credential = (%d bytes, %v); want 32 bytes", len(secret), err)
	}
	persisted, err := eventStore.RegistrationToken(t.Context(), managementRegistrationTokenID)
	if err != nil {
		t.Fatalf("read registration-token projection: %v", err)
	}
	if persisted.Hash != sha256.Sum256(secret) {
		t.Fatal("registration-token projection does not contain the generated secret digest")
	}

	got, err := service.GetRegistrationToken(admin, connect.NewRequest(
		&powermanagev1.GetRegistrationTokenRequest{Id: managementRegistrationTokenID},
	))
	if err != nil || got.Msg.GetRegistrationToken().GetVersion() != 1 {
		t.Fatalf("get registration token = (%#v, %v); want metadata version one", got, err)
	}
	updated, err := service.UpdateRegistrationToken(admin, connect.NewRequest(
		&powermanagev1.UpdateRegistrationTokenRequest{
			Id:              managementRegistrationTokenID,
			MaxUses:         3,
			ExpiresAt:       timestamppb.New(expiresAt.Add(time.Hour)),
			Owner:           "updated-owner@example.test",
			State:           powermanagev1.RegistrationTokenState_REGISTRATION_TOKEN_STATE_DISABLED,
			ExpectedVersion: 1,
		},
	))
	if err != nil || updated.Msg.GetRegistrationToken().GetVersion() != 2 ||
		updated.Msg.GetRegistrationToken().GetState() != powermanagev1.RegistrationTokenState_REGISTRATION_TOKEN_STATE_DISABLED {
		t.Fatalf("update registration token = (%#v, %v); want disabled version two", updated, err)
	}
	if _, err := service.UpdateRegistrationToken(admin, connect.NewRequest(
		&powermanagev1.UpdateRegistrationTokenRequest{
			Id:              managementRegistrationTokenID,
			MaxUses:         3,
			ExpiresAt:       timestamppb.New(expiresAt.Add(time.Hour)),
			Owner:           "updated-owner@example.test",
			State:           powermanagev1.RegistrationTokenState_REGISTRATION_TOKEN_STATE_ACTIVE,
			ExpectedVersion: 2,
		},
	)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("registration-token re-enable code = %v; want InvalidArgument", connect.CodeOf(err))
	}
	if _, err := service.DeleteRegistrationToken(admin, connect.NewRequest(
		&powermanagev1.DeleteRegistrationTokenRequest{
			Id:              managementRegistrationTokenID,
			ExpectedVersion: 2,
		},
	)); err != nil {
		t.Fatalf("delete registration token: %v", err)
	}
}
