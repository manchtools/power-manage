package control

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/store"
)

const (
	managementAPITokenID     = "01J00000000000000000000143"
	managementSelfAPITokenID = "01J00000000000000000000144"
)

func TestAPITokenHandlers_OneTimeCredentialScopeAndMonotonicRevoke(t *testing.T) {
	eventStore, service := identityManagementService(t)
	scoped := identityContext(t, identityScopedID)
	self := identityContext(t, identitySelfID)
	expiresAt := timestamppb.New(time.Now().UTC().Add(2 * time.Hour))

	created, err := service.CreateApiToken(scoped, connect.NewRequest(
		&powermanagev1.CreateApiTokenRequest{
			Id:        managementAPITokenID,
			SubjectId: identityInScopeID,
			Scopes:    []string{"devices.manage", "audit.read"},
			ExpiresAt: expiresAt,
		},
	))
	if err != nil {
		t.Fatalf("create scoped API token: %v", err)
	}
	if !strings.HasPrefix(created.Msg.GetCredential(), "pm_pat_") ||
		created.Msg.GetApiToken().GetSubjectId() != identityInScopeID ||
		created.Msg.GetApiToken().GetVersion() != 1 {
		t.Fatalf(
			"created API token = %#v; want one-time credential and version-one metadata",
			created.Msg.GetApiToken(),
		)
	}
	persisted, err := eventStore.PersonalAccessTokenByID(t.Context(), managementAPITokenID)
	if err != nil {
		t.Fatalf("read API-token projection: %v", err)
	}
	if persisted.Hash != sha256.Sum256([]byte(created.Msg.GetCredential())) {
		t.Fatal("API-token projection does not contain the generated credential digest")
	}
	if _, err := service.CreateApiToken(scoped, connect.NewRequest(
		&powermanagev1.CreateApiTokenRequest{
			Id:        "01J00000000000000000000145",
			SubjectId: identityOutOfScopeID,
			Scopes:    []string{"audit.read"},
			ExpiresAt: expiresAt,
		},
	)); connect.CodeOf(err) != connect.CodeNotFound {
		t.Fatalf("out-of-scope API-token create code = %v; want NotFound", connect.CodeOf(err))
	}

	updated, err := service.UpdateApiToken(scoped, connect.NewRequest(
		&powermanagev1.UpdateApiTokenRequest{
			Id:              managementAPITokenID,
			SubjectId:       identityInScopeID,
			Scopes:          []string{"audit.read"},
			ExpiresAt:       timestamppb.New(time.Now().UTC().Add(3 * time.Hour)),
			State:           powermanagev1.ApiTokenState_API_TOKEN_STATE_REVOKED,
			ExpectedVersion: 1,
		},
	))
	if err != nil || updated.Msg.GetApiToken().GetState() !=
		powermanagev1.ApiTokenState_API_TOKEN_STATE_REVOKED {
		t.Fatalf("revoke API token = (%#v, %v); want revoked metadata", updated, err)
	}
	if _, err := service.UpdateApiToken(scoped, connect.NewRequest(
		&powermanagev1.UpdateApiTokenRequest{
			Id:              managementAPITokenID,
			SubjectId:       identityInScopeID,
			Scopes:          []string{"audit.read"},
			ExpiresAt:       timestamppb.New(time.Now().UTC().Add(3 * time.Hour)),
			State:           powermanagev1.ApiTokenState_API_TOKEN_STATE_ACTIVE,
			ExpectedVersion: 2,
		},
	)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("API-token reactivation code = %v; want InvalidArgument", connect.CodeOf(err))
	}

	if _, err := service.CreateApiToken(self, connect.NewRequest(
		&powermanagev1.CreateApiTokenRequest{
			Id:        managementSelfAPITokenID,
			SubjectId: identitySelfID,
			Scopes:    []string{"users.manage"},
			ExpiresAt: expiresAt,
		},
	)); err != nil {
		t.Fatalf("create self API token: %v", err)
	}
	selfTokens, err := service.ListApiTokens(self, connect.NewRequest(
		&powermanagev1.ListApiTokensRequest{Limit: 100},
	))
	if err != nil || len(selfTokens.Msg.GetApiTokens()) != 1 ||
		selfTokens.Msg.GetApiTokens()[0].GetId() != managementSelfAPITokenID {
		t.Fatalf("self API-token list = (%#v, %v); want only self token", selfTokens, err)
	}

	if _, err := service.DeleteApiToken(scoped, connect.NewRequest(
		&powermanagev1.DeleteApiTokenRequest{
			Id:              managementAPITokenID,
			ExpectedVersion: 2,
		},
	)); err != nil {
		t.Fatalf("delete scoped API token: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), store.PersonalAccessTokenRebuildTarget); err != nil {
		t.Fatalf("rebuild API tokens: %v", err)
	}
	if _, err := eventStore.PersonalAccessTokenByID(
		t.Context(),
		managementAPITokenID,
	); !store.IsNotFound(err) {
		t.Fatalf("rebuilt deleted API token error = %v; want not found", err)
	}
}
