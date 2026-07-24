package control

import (
	"testing"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/store"
)

func TestIdentityProviderHandlers_CRUDValidationAndRebuild(t *testing.T) {
	eventStore, service := identityManagementService(t)
	admin := identityContext(t, identityAdminID)
	createRequest := &powermanagev1.CreateIdentityProviderRequest{
		Id:                    "corporate",
		Issuer:                "https://issuer.example",
		ClientId:              "power-manage",
		AuthorizationEndpoint: "https://issuer.example/authorize?audience=control",
		TokenEndpoint:         "https://issuer.example/token",
		JwksUri:               "https://issuer.example/jwks?tenant=corporate",
		RedirectUris: []string{
			"https://control.example/callback",
			"http://127.0.0.1:8080/callback",
		},
		EmailAssertionPolicy: powermanagev1.EmailAssertionPolicy_EMAIL_ASSERTION_POLICY_TRUST_VERIFIED_EMAIL,
	}
	created, err := service.CreateIdentityProvider(
		admin,
		connect.NewRequest(createRequest),
	)
	if err != nil || created.Msg.GetIdentityProvider().GetVersion() != 1 ||
		created.Msg.GetIdentityProvider().GetState() !=
			powermanagev1.IdentityProviderState_IDENTITY_PROVIDER_STATE_ENABLED {
		t.Fatalf("create identity provider = (%#v, %v); want enabled version one", created, err)
	}
	if _, err := service.CreateIdentityProvider(admin, connect.NewRequest(
		&powermanagev1.CreateIdentityProviderRequest{
			Id:                    "unsafe",
			Issuer:                "https://issuer.example",
			ClientId:              "power-manage",
			AuthorizationEndpoint: "https://issuer.example/authorize",
			TokenEndpoint:         "https://user:secret@issuer.example/token",
			JwksUri:               "https://issuer.example/jwks",
			RedirectUris:          []string{"https://control.example/callback"},
			EmailAssertionPolicy:  powermanagev1.EmailAssertionPolicy_EMAIL_ASSERTION_POLICY_REQUIRE_EXPLICIT_LINK,
		},
	)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("unsafe identity-provider code = %v; want InvalidArgument", connect.CodeOf(err))
	}

	listed, err := service.ListIdentityProviders(admin, connect.NewRequest(
		&powermanagev1.ListIdentityProvidersRequest{Limit: 100},
	))
	if err != nil || len(listed.Msg.GetIdentityProviders()) != 1 ||
		listed.Msg.GetIdentityProviders()[0].GetId() != "corporate" {
		t.Fatalf("identity-provider list = (%#v, %v); want corporate provider", listed, err)
	}
	updated, err := service.UpdateIdentityProvider(admin, connect.NewRequest(
		&powermanagev1.UpdateIdentityProviderRequest{
			Id:                    createRequest.GetId(),
			Issuer:                createRequest.GetIssuer(),
			ClientId:              "power-manage-ui",
			AuthorizationEndpoint: createRequest.GetAuthorizationEndpoint(),
			TokenEndpoint:         createRequest.GetTokenEndpoint(),
			JwksUri:               createRequest.GetJwksUri(),
			RedirectUris:          createRequest.GetRedirectUris(),
			EmailAssertionPolicy:  powermanagev1.EmailAssertionPolicy_EMAIL_ASSERTION_POLICY_REQUIRE_EXPLICIT_LINK,
			State:                 powermanagev1.IdentityProviderState_IDENTITY_PROVIDER_STATE_DISABLED,
			ExpectedVersion:       1,
		},
	))
	if err != nil || updated.Msg.GetIdentityProvider().GetClientId() != "power-manage-ui" ||
		updated.Msg.GetIdentityProvider().GetState() !=
			powermanagev1.IdentityProviderState_IDENTITY_PROVIDER_STATE_DISABLED ||
		updated.Msg.GetIdentityProvider().GetVersion() != 2 {
		t.Fatalf("update identity provider = (%#v, %v); want disabled version two", updated, err)
	}
	if _, err := service.DeleteIdentityProvider(admin, connect.NewRequest(
		&powermanagev1.DeleteIdentityProviderRequest{
			Id:              createRequest.GetId(),
			ExpectedVersion: 1,
		},
	)); connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("stale identity-provider delete code = %v; want Aborted", connect.CodeOf(err))
	}
	if _, err := service.DeleteIdentityProvider(admin, connect.NewRequest(
		&powermanagev1.DeleteIdentityProviderRequest{
			Id:              createRequest.GetId(),
			ExpectedVersion: 2,
		},
	)); err != nil {
		t.Fatalf("delete identity provider: %v", err)
	}
	if err := eventStore.RebuildAll(t.Context(), store.OIDCProviderConfigRebuildTarget); err != nil {
		t.Fatalf("rebuild identity providers: %v", err)
	}
	if _, err := eventStore.OIDCProviderConfigBySlug(
		t.Context(),
		createRequest.GetId(),
	); !store.IsNotFound(err) {
		t.Fatalf("rebuilt deleted identity provider error = %v; want not found", err)
	}
}
