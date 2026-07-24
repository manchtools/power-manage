package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/sdk/nilcheck"
	"github.com/manchtools/power-manage/sdk/validate"
	"github.com/manchtools/power-manage/server/internal/authz"
)

var (
	errAuthenticationRequired    = errors.New("authentication required")
	errPermissionDenied          = errors.New("permission denied")
	errAuthorizationUnavailable  = errors.New("authorization unavailable")
	errAuthenticatedPrincipal    = errors.New("authenticated principal is invalid: auth")
	errAuthorizationGateNotWired = errors.New("authorization gate is not wired: auth")
)

// EffectiveAccessResolver loads current additive access for one user subject.
type EffectiveAccessResolver interface {
	ResolveEffectiveAccess(context.Context, string) (authz.EffectiveAccess, error)
}

type procedureAuthorizationLookup func(string) (ProcedureAuthorization, bool)

// AuthorizationDecision is the handler-visible result of one permission gate.
type AuthorizationDecision struct {
	Subject            string
	AuditIdentity      string
	RequiredPermission authz.Permission
	EffectiveAccess    authz.EffectiveAccess
}

type authenticatedPrincipal struct {
	subject       string
	auditIdentity string
	patScopes     map[authz.Permission]struct{}
	isPAT         bool
}

type authenticatedPrincipalContextKey struct{}
type authorizationDecisionContextKey struct{}

// AuthorizationGate is both the server authorization interceptor and the
// defense-in-depth gate called directly by permission handlers.
type AuthorizationGate struct {
	resolver EffectiveAccessResolver
	lookup   procedureAuthorizationLookup
}

// NewAuthorizationGate wires authorization to the production RPC policy registry.
func NewAuthorizationGate(resolver EffectiveAccessResolver) (*AuthorizationGate, error) {
	if err := validateProcedureAuthorizations(procedureAuthorizations); err != nil {
		return nil, err
	}
	return newAuthorizationGate(resolver, classifyProcedureAuthorization)
}

func newAuthorizationGate(
	resolver EffectiveAccessResolver,
	lookup procedureAuthorizationLookup,
) (*AuthorizationGate, error) {
	if nilcheck.Interface(resolver) || lookup == nil {
		return nil, errAuthorizationGateNotWired
	}
	return &AuthorizationGate{resolver: resolver, lookup: lookup}, nil
}

// ValidateWiring rejects nil, typed-nil, and partially initialized gates.
func (g *AuthorizationGate) ValidateWiring() error {
	if g == nil || nilcheck.Interface(g.resolver) || g.lookup == nil {
		return errAuthorizationGateNotWired
	}
	return nil
}

// ContextWithSessionClaims attaches one verified session identity.
func ContextWithSessionClaims(ctx context.Context, claims Claims) (context.Context, error) {
	if nilcheck.Interface(ctx) ||
		!validAuthorizationSubject(claims.Subject) ||
		claims.SessionVersion <= 0 {
		return nil, errAuthenticatedPrincipal
	}
	return context.WithValue(ctx, authenticatedPrincipalContextKey{}, authenticatedPrincipal{
		subject: claims.Subject,
	}), nil
}

// ContextWithPATPrincipal attaches one verified, scope-limited PAT identity.
func ContextWithPATPrincipal(
	ctx context.Context,
	principal PATPrincipal,
) (context.Context, error) {
	if nilcheck.Interface(ctx) ||
		!validAuthorizationSubject(principal.Subject) ||
		validate.ULIDPathID(principal.TokenID) != nil ||
		principal.TokenID != strings.ToUpper(principal.TokenID) ||
		principal.AuditIdentity != "pat:"+principal.TokenID {
		return nil, errAuthenticatedPrincipal
	}
	scopes, err := canonicalPATScopes(principal.Scopes)
	if err != nil || !slices.Equal(scopes, principal.Scopes) {
		return nil, errAuthenticatedPrincipal
	}
	scopeSet := make(map[authz.Permission]struct{}, len(scopes))
	for _, scope := range scopes {
		scopeSet[authz.Permission(scope)] = struct{}{}
	}
	return context.WithValue(ctx, authenticatedPrincipalContextKey{}, authenticatedPrincipal{
		subject:       principal.Subject,
		auditIdentity: principal.AuditIdentity,
		patScopes:     scopeSet,
		isPAT:         true,
	}), nil
}

// AuthorizationDecisionFromContext returns an independent handler decision.
func AuthorizationDecisionFromContext(
	ctx context.Context,
) (AuthorizationDecision, bool) {
	if nilcheck.Interface(ctx) {
		return AuthorizationDecision{}, false
	}
	decision, ok := ctx.Value(authorizationDecisionContextKey{}).(AuthorizationDecision)
	if !ok {
		return AuthorizationDecision{}, false
	}
	decision.EffectiveAccess = cloneEffectiveAccess(decision.EffectiveAccess)
	return decision, true
}

// AuthorizeContext applies the same policy used by the interceptor and returns
// a context carrying the decision required by direct handler enforcement.
func (g *AuthorizationGate) AuthorizeContext(
	ctx context.Context,
	procedure string,
) (context.Context, error) {
	if g.ValidateWiring() != nil || nilcheck.Interface(ctx) {
		return nil, authorizationUnavailable()
	}
	policy, ok := g.lookup(procedure)
	if !ok {
		return nil, permissionDenied()
	}
	if err := validateProcedureAuthorization(procedure, policy); err != nil {
		return nil, authorizationUnavailable()
	}
	switch policy.Class {
	case ProcedurePublic, ProcedureAltAuth:
		return ctx, nil
	case ProcedurePermissionGated:
	default:
		return nil, authorizationUnavailable()
	}

	principal, ok := ctx.Value(authenticatedPrincipalContextKey{}).(authenticatedPrincipal)
	if !ok || !validAuthorizationSubject(principal.subject) {
		return nil, authenticationRequired()
	}
	if principal.isPAT {
		if _, ok := principal.patScopes[policy.Permission]; !ok {
			return nil, permissionDenied()
		}
	}
	effective, err := g.resolver.ResolveEffectiveAccess(ctx, principal.subject)
	if err != nil {
		return nil, authorizationUnavailable()
	}
	reach, ok := effective.Permissions[policy.Permission]
	if !ok {
		return nil, permissionDenied()
	}
	if !validReach(policy.Permission, reach) {
		return nil, authorizationUnavailable()
	}
	decision := AuthorizationDecision{
		Subject:            principal.subject,
		AuditIdentity:      principal.auditIdentity,
		RequiredPermission: policy.Permission,
		EffectiveAccess:    cloneEffectiveAccess(effective),
	}
	return context.WithValue(ctx, authorizationDecisionContextKey{}, decision), nil
}

// WrapUnary implements connect.Interceptor.
func (g *AuthorizationGate) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	if g.ValidateWiring() != nil || next == nil {
		return func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
			return nil, authorizationUnavailable()
		}
	}
	return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
		if nilcheck.Interface(request) {
			return nil, permissionDenied()
		}
		authorized, err := g.AuthorizeContext(ctx, request.Spec().Procedure)
		if err != nil {
			return nil, err
		}
		return next(authorized, request)
	}
}

// WrapStreamingClient implements connect.Interceptor.
func (g *AuthorizationGate) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	if g.ValidateWiring() != nil || next == nil {
		return func(_ context.Context, spec connect.Spec) connect.StreamingClientConn {
			return &rejectedStreamingClientConn{
				spec:          spec,
				requestHeader: make(http.Header),
			}
		}
	}
	return next
}

// WrapStreamingHandler implements connect.Interceptor.
func (g *AuthorizationGate) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	if g.ValidateWiring() != nil || next == nil {
		return func(context.Context, connect.StreamingHandlerConn) error {
			return authorizationUnavailable()
		}
	}
	return func(ctx context.Context, connection connect.StreamingHandlerConn) error {
		if nilcheck.Interface(connection) {
			return permissionDenied()
		}
		authorized, err := g.AuthorizeContext(ctx, connection.Spec().Procedure)
		if err != nil {
			return err
		}
		return next(authorized, connection)
	}
}

func validateProcedureAuthorizations(
	policies map[string]ProcedureAuthorization,
) error {
	if len(policies) == 0 {
		return fmt.Errorf("%w: registry is empty", ErrProcedureAuthorizationInvalid)
	}
	for procedure, policy := range policies {
		if err := validateProcedureAuthorization(procedure, policy); err != nil {
			return err
		}
	}
	return nil
}

func validateProcedureAuthorization(
	procedure string,
	policy ProcedureAuthorization,
) error {
	if strings.TrimSpace(procedure) == "" || procedure[0] != '/' {
		return fmt.Errorf("%w: invalid procedure %q", ErrProcedureAuthorizationInvalid, procedure)
	}
	switch policy.Class {
	case ProcedurePublic, ProcedureAltAuth:
		if policy.Permission != "" {
			return fmt.Errorf(
				"%w: non-permission procedure %q names %q",
				ErrProcedureAuthorizationInvalid,
				procedure,
				policy.Permission,
			)
		}
	case ProcedurePermissionGated:
		if _, ok := authz.Lookup(policy.Permission); !ok {
			return fmt.Errorf(
				"%w: procedure %q names unknown permission %q",
				ErrProcedureAuthorizationInvalid,
				procedure,
				policy.Permission,
			)
		}
	default:
		return fmt.Errorf(
			"%w: procedure %q has class %d",
			ErrProcedureAuthorizationInvalid,
			procedure,
			policy.Class,
		)
	}
	return nil
}

func validReach(permission authz.Permission, reach authz.Reach) bool {
	entry, ok := authz.Lookup(permission)
	if !ok {
		return false
	}
	if reach.Global {
		return !reach.Self &&
			len(reach.DeviceGroupIDs) == 0 &&
			len(reach.UserGroupIDs) == 0
	}
	if entry.Class == authz.GlobalOnly {
		return false
	}
	return (reach.Self ||
		len(reach.DeviceGroupIDs) > 0 ||
		len(reach.UserGroupIDs) > 0) &&
		validReachIDs(reach.DeviceGroupIDs) &&
		validReachIDs(reach.UserGroupIDs)
}

func validAuthorizationSubject(subject string) bool {
	return validate.ULIDPathID(subject) == nil && subject == strings.ToUpper(subject)
}

func validReachIDs(ids []string) bool {
	if !slices.IsSorted(ids) {
		return false
	}
	for index, id := range ids {
		if validate.ULIDPathID(id) != nil ||
			id != strings.ToUpper(id) ||
			index > 0 && id == ids[index-1] {
			return false
		}
	}
	return true
}

func cloneEffectiveAccess(access authz.EffectiveAccess) authz.EffectiveAccess {
	clone := authz.EffectiveAccess{
		Grants:      make([]authz.GrantAccess, len(access.Grants)),
		Permissions: make(map[authz.Permission]authz.Reach, len(access.Permissions)),
	}
	for index, grant := range access.Grants {
		clone.Grants[index] = authz.GrantAccess{
			GrantID:             grant.GrantID,
			ActivePermissions:   slices.Clone(grant.ActivePermissions),
			StrippedPermissions: slices.Clone(grant.StrippedPermissions),
		}
	}
	for permission, reach := range access.Permissions {
		clone.Permissions[permission] = authz.Reach{
			Global:         reach.Global,
			DeviceGroupIDs: slices.Clone(reach.DeviceGroupIDs),
			UserGroupIDs:   slices.Clone(reach.UserGroupIDs),
			Self:           reach.Self,
		}
	}
	return clone
}

func authenticationRequired() error {
	return connect.NewError(connect.CodeUnauthenticated, errAuthenticationRequired)
}

func permissionDenied() error {
	return connect.NewError(connect.CodePermissionDenied, errPermissionDenied)
}

func authorizationUnavailable() error {
	return connect.NewError(connect.CodeUnavailable, errAuthorizationUnavailable)
}
