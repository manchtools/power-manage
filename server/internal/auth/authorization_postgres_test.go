package auth

import (
	"os"
	"testing"

	"github.com/manchtools/power-manage/server/internal/authz"
	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testpostgres"
)

var authorizationPostgres testpostgres.Harness

func TestMain(m *testing.M) {
	os.Exit(authorizationPostgres.Run(m))
}

func TestAuthorizationGate_DirectCallUsesRealEffectiveAccess(t *testing.T) {
	pool := authorizationPostgres.Database(t, store.Migrate)
	eventStore, err := store.NewProduction(pool)
	if err != nil {
		t.Fatalf("create production store: %v", err)
	}
	user, err := store.UserCreatedEvent(testAuthorizationSubject, "authorized@example.test")
	if err != nil {
		t.Fatalf("create authorization user: %v", err)
	}
	role, err := store.AuthorizationRoleCreatedEvent(
		testAuthorizationRole,
		"device-managers",
		[]authz.Permission{"devices.manage"},
	)
	if err != nil {
		t.Fatalf("create authorization role: %v", err)
	}
	grant, err := store.AuthorizationGrantCreatedEvent(
		testAuthorizationGrant,
		authz.PrincipalUser,
		testAuthorizationSubject,
		testAuthorizationRole,
		authz.Scope{Kind: authz.ScopeGlobal},
	)
	if err != nil {
		t.Fatalf("create authorization grant: %v", err)
	}
	if err := eventStore.AppendEvents(t.Context(), []store.Event{user, role, grant}); err != nil {
		t.Fatalf("append authorization fixture: %v", err)
	}

	gate, err := newAuthorizationGate(
		eventStore,
		func(procedure string) (ProcedureAuthorization, bool) {
			if procedure != testAuthorizationProcedure {
				return ProcedureAuthorization{}, false
			}
			return ProcedureAuthorization{
				Class:      ProcedurePermissionGated,
				Permission: "devices.manage",
			}, true
		},
	)
	if err != nil {
		t.Fatalf("create authorization gate: %v", err)
	}
	ctx, err := ContextWithSessionClaims(t.Context(), Claims{
		Subject:        testAuthorizationSubject,
		SessionVersion: 1,
	})
	if err != nil {
		t.Fatalf("attach session claims: %v", err)
	}
	authorized, err := gate.AuthorizeContext(ctx, testAuthorizationProcedure)
	if err != nil {
		t.Fatalf("direct authorization: %v", err)
	}
	decision, ok := AuthorizationDecisionFromContext(authorized)
	if !ok || !decision.EffectiveAccess.Permissions["devices.manage"].Global {
		t.Fatalf("direct decision = (%#v, %t); want global devices.manage", decision, ok)
	}
}
