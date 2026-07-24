package control

import (
	"strings"
	"testing"

	"connectrpc.com/connect"
	"golang.org/x/crypto/bcrypt"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/store"
)

func TestScimConfigurationHandlers_OneTimeRotationDisableAndDelete(t *testing.T) {
	eventStore, service := identityManagementService(t)
	admin := identityContext(t, identityAdminID)

	created, err := service.CreateScimConfiguration(admin, connect.NewRequest(
		&powermanagev1.CreateScimConfigurationRequest{ProviderSlug: "provisioner"},
	))
	if err != nil || !strings.HasPrefix(created.Msg.GetCredential(), "pm_scim_") ||
		created.Msg.GetScimConfiguration().GetVersion() != 1 {
		t.Fatalf(
			"create SCIM configuration = (%#v, %v); want credential and version one",
			created.Msg.GetScimConfiguration(),
			err,
		)
	}
	firstCredential := created.Msg.GetCredential()
	persisted, err := eventStore.SCIMProvider(t.Context(), "provisioner")
	if err != nil || bcrypt.CompareHashAndPassword(
		[]byte(persisted.TokenHash),
		[]byte(firstCredential),
	) != nil {
		t.Fatalf("persisted SCIM verifier does not match one-time credential: %v", err)
	}
	listed, err := service.ListScimConfigurations(admin, connect.NewRequest(
		&powermanagev1.ListScimConfigurationsRequest{Limit: 100},
	))
	if err != nil || len(listed.Msg.GetScimConfigurations()) != 1 ||
		listed.Msg.GetScimConfigurations()[0].GetId() != "provisioner" {
		t.Fatalf("SCIM configuration list = (%#v, %v); want provisioner", listed, err)
	}

	rotated, err := service.UpdateScimConfiguration(admin, connect.NewRequest(
		&powermanagev1.UpdateScimConfigurationRequest{
			Id:               "provisioner",
			State:            powermanagev1.ScimConfigurationState_SCIM_CONFIGURATION_STATE_ENABLED,
			CredentialAction: powermanagev1.ScimCredentialAction_SCIM_CREDENTIAL_ACTION_ROTATE,
			ExpectedVersion:  1,
		},
	))
	if err != nil || rotated.Msg.GetCredential() == "" ||
		rotated.Msg.GetCredential() == firstCredential ||
		rotated.Msg.GetScimConfiguration().GetVersion() != 2 {
		t.Fatalf(
			"rotate SCIM configuration = (%#v, %v); want fresh credential and version two",
			rotated.Msg.GetScimConfiguration(),
			err,
		)
	}
	persisted, err = eventStore.SCIMProvider(t.Context(), "provisioner")
	if err != nil ||
		bcrypt.CompareHashAndPassword(
			[]byte(persisted.TokenHash),
			[]byte(rotated.Msg.GetCredential()),
		) != nil ||
		bcrypt.CompareHashAndPassword(
			[]byte(persisted.TokenHash),
			[]byte(firstCredential),
		) == nil {
		t.Fatalf("rotated SCIM verifier state is invalid: %v", err)
	}
	if _, err := service.UpdateScimConfiguration(admin, connect.NewRequest(
		&powermanagev1.UpdateScimConfigurationRequest{
			Id:               "provisioner",
			State:            powermanagev1.ScimConfigurationState_SCIM_CONFIGURATION_STATE_ENABLED,
			CredentialAction: powermanagev1.ScimCredentialAction_SCIM_CREDENTIAL_ACTION_KEEP,
			ExpectedVersion:  2,
		},
	)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("no-op SCIM update code = %v; want InvalidArgument", connect.CodeOf(err))
	}

	disabled, err := service.UpdateScimConfiguration(admin, connect.NewRequest(
		&powermanagev1.UpdateScimConfigurationRequest{
			Id:               "provisioner",
			State:            powermanagev1.ScimConfigurationState_SCIM_CONFIGURATION_STATE_DISABLED,
			CredentialAction: powermanagev1.ScimCredentialAction_SCIM_CREDENTIAL_ACTION_KEEP,
			ExpectedVersion:  2,
		},
	))
	if err != nil || disabled.Msg.GetCredential() != "" ||
		disabled.Msg.GetScimConfiguration().GetState() !=
			powermanagev1.ScimConfigurationState_SCIM_CONFIGURATION_STATE_DISABLED ||
		disabled.Msg.GetScimConfiguration().GetVersion() != 3 {
		t.Fatalf("disable SCIM configuration = (%#v, %v); want disabled version three", disabled, err)
	}
	if _, err := service.UpdateScimConfiguration(admin, connect.NewRequest(
		&powermanagev1.UpdateScimConfigurationRequest{
			Id:               "provisioner",
			State:            powermanagev1.ScimConfigurationState_SCIM_CONFIGURATION_STATE_ENABLED,
			CredentialAction: powermanagev1.ScimCredentialAction_SCIM_CREDENTIAL_ACTION_ROTATE,
			ExpectedVersion:  3,
		},
	)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("disabled SCIM rotation code = %v; want InvalidArgument", connect.CodeOf(err))
	}
	if _, err := service.DeleteScimConfiguration(admin, connect.NewRequest(
		&powermanagev1.DeleteScimConfigurationRequest{
			Id:              "provisioner",
			ExpectedVersion: 3,
		},
	)); err != nil {
		t.Fatalf("delete SCIM configuration: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), store.SCIMProviderRebuildTarget); err != nil {
		t.Fatalf("rebuild SCIM configurations: %v", err)
	}
	if _, err := eventStore.SCIMProvider(
		t.Context(),
		"provisioner",
	); !store.IsNotFound(err) {
		t.Fatalf("rebuilt deleted SCIM configuration error = %v; want not found", err)
	}
}
