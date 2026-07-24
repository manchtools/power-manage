package auth

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/sdk/guardtest"
	"github.com/manchtools/power-manage/server/internal/authz"
)

const (
	testAuthorizationProcedure = "/test.AuthorizationService/ManageDevices"
	testAuthorizationSubject   = "01K0QJ3E5E8R4M0D8EV3Y4N6P0"
	testAuthorizationGrant     = "01K0QJ3E5E8R4M0D8EV3Y4N6P1"
	testAuthorizationRole      = "01K0QJ3E5E8R4M0D8EV3Y4N6P2"
)

func TestGuard_RPCClassificationCarriesExactlyOneAuthorizationMode(t *testing.T) {
	policies := ProcedureAuthorizations()
	procedures := guardtest.Discover(t, "RPC authorization policies", 15, func() ([]string, error) {
		return slices.Sorted(maps.Keys(policies)), nil
	})
	if err := validateProcedureAuthorizations(policies); err != nil {
		t.Fatalf("validate production procedure authorizations: %v", err)
	}
	for _, procedure := range procedures {
		policy := policies[procedure]
		class, ok := ClassifyProcedure(procedure)
		if !ok || class != policy.Class {
			t.Fatalf("derived class for %s = (%v, %t); want (%v, true)",
				procedure, class, ok, policy.Class)
		}
	}
}

func TestValidateProcedureAuthorizations_RejectsInvalidPermissionPairing(t *testing.T) {
	tests := map[string]ProcedureAuthorization{
		"zero class": {},
		"public with permission": {
			Class:      ProcedurePublic,
			Permission: "devices.manage",
		},
		"alternate auth with permission": {
			Class:      ProcedureAltAuth,
			Permission: "devices.manage",
		},
		"permission missing name": {Class: ProcedurePermissionGated},
		"permission unknown name": {
			Class:      ProcedurePermissionGated,
			Permission: "unknown.manage",
		},
	}
	for name, policy := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateProcedureAuthorizations(
				map[string]ProcedureAuthorization{testAuthorizationProcedure: policy},
			)
			if !errors.Is(err, ErrProcedureAuthorizationInvalid) {
				t.Fatalf("validation error = %v; want ErrProcedureAuthorizationInvalid", err)
			}
		})
	}
}

func TestAuthorizationGate_FailsClosedForUnknownUnaryAndStreamingProcedures(t *testing.T) {
	resolverCalls := 0
	gate, err := NewAuthorizationGate(effectiveAccessResolverFunc(
		func(context.Context, string) (authz.EffectiveAccess, error) {
			resolverCalls++
			return authz.EffectiveAccess{}, nil
		},
	))
	if err != nil {
		t.Fatalf("create authorization gate: %v", err)
	}
	handlerCalled := false
	unary := gate.WrapUnary(
		func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
			handlerCalled = true
			return connect.NewResponse(&emptypb.Empty{}), nil
		},
	)
	if _, err := unary(t.Context(), connect.NewRequest(&emptypb.Empty{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("unknown unary code = %v (%v); want PermissionDenied", connect.CodeOf(err), err)
	}
	var typedNilRequest *connect.Request[emptypb.Empty]
	if _, err := unary(t.Context(), typedNilRequest); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("typed-nil unary code = %v (%v); want PermissionDenied", connect.CodeOf(err), err)
	}
	stream := gate.WrapStreamingHandler(
		func(context.Context, connect.StreamingHandlerConn) error {
			handlerCalled = true
			return nil
		},
	)
	if err := stream(t.Context(), authorizationTestStream{procedure: "/unknown.Service/Stream"}); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("unknown stream code = %v (%v); want PermissionDenied", connect.CodeOf(err), err)
	}
	var typedNilStream *typedNilAuthorizationStream
	if err := stream(t.Context(), typedNilStream); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("typed-nil stream code = %v (%v); want PermissionDenied", connect.CodeOf(err), err)
	}
	if resolverCalls != 0 || handlerCalled {
		t.Fatalf("unknown procedures reached resolver/handler = (%d, %t); want neither", resolverCalls, handlerCalled)
	}
}

func TestAuthorizationGate_PublicAndAlternateAuthBypassResolver(t *testing.T) {
	resolverCalls := 0
	gate, err := NewAuthorizationGate(effectiveAccessResolverFunc(
		func(context.Context, string) (authz.EffectiveAccess, error) {
			resolverCalls++
			return authz.EffectiveAccess{}, nil
		},
	))
	if err != nil {
		t.Fatalf("create authorization gate: %v", err)
	}
	ctx := t.Context()
	for _, procedure := range []string{
		powermanagev1connect.ControlServiceRefreshSessionProcedure,
		powermanagev1connect.AgentServiceStreamProcedure,
	} {
		authorized, err := gate.AuthorizeContext(ctx, procedure)
		if err != nil {
			t.Fatalf("authorize %s: %v", procedure, err)
		}
		if authorized != ctx {
			t.Fatalf("%s replaced a pass-through context", procedure)
		}
	}
	if resolverCalls != 0 {
		t.Fatalf("public/alternate authorization made %d resolver calls; want zero", resolverCalls)
	}
}

func TestAuthorizationPrincipalContextRejectsInvalidIdentity(t *testing.T) {
	for _, claims := range []Claims{
		{},
		{Subject: "not-a-ulid", SessionVersion: 1},
		{Subject: strings.ToLower(testAuthorizationSubject), SessionVersion: 1},
		{Subject: testAuthorizationSubject},
	} {
		if _, err := ContextWithSessionClaims(t.Context(), claims); !errors.Is(err, errAuthenticatedPrincipal) {
			t.Fatalf("ContextWithSessionClaims(%#v) error = %v; want invalid principal", claims, err)
		}
	}
	for _, principal := range []PATPrincipal{
		{},
		{
			Subject:       "not-a-ulid",
			TokenID:       testAuthorizationGrant,
			Scopes:        []string{"devices.manage"},
			AuditIdentity: "pat:" + testAuthorizationGrant,
		},
		{
			Subject:       testAuthorizationSubject,
			TokenID:       strings.ToLower(testAuthorizationGrant),
			Scopes:        []string{"devices.manage"},
			AuditIdentity: "pat:" + strings.ToLower(testAuthorizationGrant),
		},
		{
			Subject:       testAuthorizationSubject,
			TokenID:       testAuthorizationGrant,
			Scopes:        []string{"devices.manage", "devices.manage"},
			AuditIdentity: "pat:" + testAuthorizationGrant,
		},
	} {
		if _, err := ContextWithPATPrincipal(t.Context(), principal); !errors.Is(err, errAuthenticatedPrincipal) {
			t.Fatalf("ContextWithPATPrincipal(%#v) error = %v; want invalid principal", principal, err)
		}
	}
}

func TestAuthorizationGate_RequiresPrincipalAndExactPermission(t *testing.T) {
	resolverCalls := 0
	effective := authz.EffectiveAccess{
		Permissions: map[authz.Permission]authz.Reach{
			"devices.manage": {Global: true},
		},
	}
	gate := newTestAuthorizationGate(t, func(context.Context, string) (authz.EffectiveAccess, error) {
		resolverCalls++
		return effective, nil
	})

	if _, err := gate.AuthorizeContext(t.Context(), testAuthorizationProcedure); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("unauthenticated authorization code = %v (%v); want Unauthenticated", connect.CodeOf(err), err)
	}
	if resolverCalls != 0 {
		t.Fatalf("unauthenticated authorization made %d resolver calls; want zero", resolverCalls)
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
		t.Fatalf("authorize exact permission: %v", err)
	}
	decision, ok := AuthorizationDecisionFromContext(authorized)
	if !ok {
		t.Fatal("authorized context has no decision")
	}
	want := AuthorizationDecision{
		Subject:            testAuthorizationSubject,
		RequiredPermission: "devices.manage",
		EffectiveAccess: authz.EffectiveAccess{
			Grants:      []authz.GrantAccess{},
			Permissions: effective.Permissions,
		},
	}
	if !reflect.DeepEqual(decision, want) {
		t.Fatalf("authorization decision = %#v; want %#v", decision, want)
	}
	decision.EffectiveAccess.Permissions["devices.manage"] = authz.Reach{}
	second, ok := AuthorizationDecisionFromContext(authorized)
	if !ok || !second.EffectiveAccess.Permissions["devices.manage"].Global {
		t.Fatal("mutating returned decision changed authorization context")
	}
}

func TestAuthorizationGate_DirectAndInterceptorCallsShareDecision(t *testing.T) {
	effective := authz.EffectiveAccess{
		Permissions: map[authz.Permission]authz.Reach{
			"devices.manage": {Global: true},
		},
	}
	gate := newTestAuthorizationGate(t, func(context.Context, string) (authz.EffectiveAccess, error) {
		return effective, nil
	})
	ctx, err := ContextWithSessionClaims(t.Context(), Claims{
		Subject:        testAuthorizationSubject,
		SessionVersion: 1,
	})
	if err != nil {
		t.Fatalf("attach session claims: %v", err)
	}
	directContext, err := gate.AuthorizeContext(ctx, testAuthorizationProcedure)
	if err != nil {
		t.Fatalf("direct authorization: %v", err)
	}
	direct, ok := AuthorizationDecisionFromContext(directContext)
	if !ok {
		t.Fatal("direct authorization attached no decision")
	}

	var intercepted AuthorizationDecision
	handler := gate.WrapStreamingHandler(func(ctx context.Context, _ connect.StreamingHandlerConn) error {
		var ok bool
		intercepted, ok = AuthorizationDecisionFromContext(ctx)
		if !ok {
			t.Fatal("interceptor authorization attached no decision")
		}
		return nil
	})
	if err := handler(ctx, authorizationTestStream{procedure: testAuthorizationProcedure}); err != nil {
		t.Fatalf("interceptor authorization: %v", err)
	}
	if !reflect.DeepEqual(intercepted, direct) {
		t.Fatalf("interceptor decision = %#v; direct decision = %#v", intercepted, direct)
	}
}

func TestAuthorizationGate_PATScopeNarrowsRoleAccessBeforeLookup(t *testing.T) {
	resolverCalls := 0
	gate := newTestAuthorizationGate(t, func(context.Context, string) (authz.EffectiveAccess, error) {
		resolverCalls++
		return authz.EffectiveAccess{
			Permissions: map[authz.Permission]authz.Reach{
				"devices.manage": {Global: true},
			},
		}, nil
	})
	ctx, err := ContextWithPATPrincipal(t.Context(), PATPrincipal{
		Subject:       testAuthorizationSubject,
		TokenID:       testAuthorizationGrant,
		Scopes:        []string{"audit.read"},
		AuditIdentity: "pat:" + testAuthorizationGrant,
	})
	if err != nil {
		t.Fatalf("attach PAT principal: %v", err)
	}
	if _, err := gate.AuthorizeContext(ctx, testAuthorizationProcedure); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("out-of-scope PAT code = %v (%v); want PermissionDenied", connect.CodeOf(err), err)
	}
	if resolverCalls != 0 {
		t.Fatalf("out-of-scope PAT made %d resolver calls; want zero", resolverCalls)
	}

	ctx, err = ContextWithPATPrincipal(t.Context(), PATPrincipal{
		Subject:       testAuthorizationSubject,
		TokenID:       testAuthorizationGrant,
		Scopes:        []string{"devices.manage"},
		AuditIdentity: "pat:" + testAuthorizationGrant,
	})
	if err != nil {
		t.Fatalf("attach in-scope PAT principal: %v", err)
	}
	authorized, err := gate.AuthorizeContext(ctx, testAuthorizationProcedure)
	if err != nil {
		t.Fatalf("authorize in-scope PAT: %v", err)
	}
	decision, ok := AuthorizationDecisionFromContext(authorized)
	if !ok || decision.AuditIdentity != "pat:"+testAuthorizationGrant {
		t.Fatalf("PAT authorization decision = (%#v, %t); want token audit identity", decision, ok)
	}
	if resolverCalls != 1 {
		t.Fatalf("in-scope PAT resolver calls = %d; want one", resolverCalls)
	}
}

func TestAuthorizationGate_ResolverFailureAndMissingPermissionAreStatic(t *testing.T) {
	ctx, err := ContextWithSessionClaims(t.Context(), Claims{
		Subject:        testAuthorizationSubject,
		SessionVersion: 1,
	})
	if err != nil {
		t.Fatalf("attach session claims: %v", err)
	}
	tests := map[string]struct {
		resolve effectiveAccessResolverFunc
		code    connect.Code
		message string
	}{
		"resolver failure": {
			resolve: func(context.Context, string) (authz.EffectiveAccess, error) {
				return authz.EffectiveAccess{}, errors.New("database details")
			},
			code:    connect.CodeUnavailable,
			message: "authorization unavailable",
		},
		"permission absent": {
			resolve: func(context.Context, string) (authz.EffectiveAccess, error) {
				return authz.EffectiveAccess{Permissions: map[authz.Permission]authz.Reach{}}, nil
			},
			code:    connect.CodePermissionDenied,
			message: "permission denied",
		},
		"zero reach": {
			resolve: func(context.Context, string) (authz.EffectiveAccess, error) {
				return authz.EffectiveAccess{
					Permissions: map[authz.Permission]authz.Reach{
						"devices.manage": {},
					},
				}, nil
			},
			code:    connect.CodeUnavailable,
			message: "authorization unavailable",
		},
		"contradictory global reach": {
			resolve: func(context.Context, string) (authz.EffectiveAccess, error) {
				return authz.EffectiveAccess{
					Permissions: map[authz.Permission]authz.Reach{
						"devices.manage": {Global: true, Self: true},
					},
				}, nil
			},
			code:    connect.CodeUnavailable,
			message: "authorization unavailable",
		},
		"malformed scoped reach": {
			resolve: func(context.Context, string) (authz.EffectiveAccess, error) {
				return authz.EffectiveAccess{
					Permissions: map[authz.Permission]authz.Reach{
						"devices.manage": {DeviceGroupIDs: []string{"not-a-ulid"}},
					},
				}, nil
			},
			code:    connect.CodeUnavailable,
			message: "authorization unavailable",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			gate := newTestAuthorizationGate(t, test.resolve)
			_, err := gate.AuthorizeContext(ctx, testAuthorizationProcedure)
			connectErr, ok := err.(*connect.Error)
			if !ok || connectErr.Code() != test.code || connectErr.Message() != test.message {
				t.Fatalf("authorization error = %v; want %v %q", err, test.code, test.message)
			}
		})
	}
}

func TestAuthorizationGate_GlobalOnlyPermissionRequiresGlobalReach(t *testing.T) {
	gate, err := newAuthorizationGate(
		effectiveAccessResolverFunc(func(context.Context, string) (authz.EffectiveAccess, error) {
			return authz.EffectiveAccess{
				Permissions: map[authz.Permission]authz.Reach{
					"roles.manage": {Self: true},
				},
			}, nil
		}),
		func(string) (ProcedureAuthorization, bool) {
			return ProcedureAuthorization{
				Class:      ProcedurePermissionGated,
				Permission: "roles.manage",
			}, true
		},
	)
	if err != nil {
		t.Fatalf("create global-only authorization gate: %v", err)
	}
	ctx, err := ContextWithSessionClaims(t.Context(), Claims{
		Subject:        testAuthorizationSubject,
		SessionVersion: 1,
	})
	if err != nil {
		t.Fatalf("attach session claims: %v", err)
	}
	if _, err := gate.AuthorizeContext(ctx, testAuthorizationProcedure); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("scoped global-only code = %v (%v); want Unavailable", connect.CodeOf(err), err)
	}
}

func TestNewInterceptorChain_RejectsNonAuthorizationFinalStage(t *testing.T) {
	noop := connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return next
	})
	var typedNil *AuthorizationGate
	for _, test := range []struct {
		name  string
		stage connect.Interceptor
	}{
		{name: "arbitrary", stage: noop},
		{name: "typed nil", stage: typedNil},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewInterceptorChain(noop, noop, noop, test.stage); !errors.Is(err, ErrInterceptorChainNotWired) {
				t.Fatalf("NewInterceptorChain error = %v; want ErrInterceptorChainNotWired", err)
			}
		})
	}
}

func newTestAuthorizationGate(
	t *testing.T,
	resolve effectiveAccessResolverFunc,
) *AuthorizationGate {
	t.Helper()
	gate, err := newAuthorizationGate(resolve, func(procedure string) (ProcedureAuthorization, bool) {
		if procedure != testAuthorizationProcedure {
			return ProcedureAuthorization{}, false
		}
		return ProcedureAuthorization{
			Class:      ProcedurePermissionGated,
			Permission: "devices.manage",
		}, true
	})
	if err != nil {
		t.Fatalf("create test authorization gate: %v", err)
	}
	return gate
}

type effectiveAccessResolverFunc func(context.Context, string) (authz.EffectiveAccess, error)

func (f effectiveAccessResolverFunc) ResolveEffectiveAccess(
	ctx context.Context,
	subject string,
) (authz.EffectiveAccess, error) {
	return f(ctx, subject)
}

type authorizationTestStream struct {
	procedure string
}

func (s authorizationTestStream) Spec() connect.Spec {
	return connect.Spec{Procedure: s.procedure}
}

func (authorizationTestStream) Peer() connect.Peer {
	return connect.Peer{}
}

func (authorizationTestStream) Receive(any) error {
	return nil
}

func (authorizationTestStream) RequestHeader() http.Header {
	return make(http.Header)
}

func (authorizationTestStream) Send(any) error {
	return nil
}

func (authorizationTestStream) ResponseHeader() http.Header {
	return make(http.Header)
}

func (authorizationTestStream) ResponseTrailer() http.Header {
	return make(http.Header)
}

type typedNilAuthorizationStream struct{}

func (*typedNilAuthorizationStream) Spec() connect.Spec {
	return connect.Spec{}
}

func (*typedNilAuthorizationStream) Peer() connect.Peer {
	return connect.Peer{}
}

func (*typedNilAuthorizationStream) Receive(any) error {
	return nil
}

func (*typedNilAuthorizationStream) RequestHeader() http.Header {
	return make(http.Header)
}

func (*typedNilAuthorizationStream) Send(any) error {
	return nil
}

func (*typedNilAuthorizationStream) ResponseHeader() http.Header {
	return make(http.Header)
}

func (*typedNilAuthorizationStream) ResponseTrailer() http.Header {
	return make(http.Header)
}
