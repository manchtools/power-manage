package auth

import (
	"context"
	"errors"
	"maps"
	"net/http"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/sdk/nilcheck"
	"github.com/manchtools/power-manage/server/internal/authz"
)

var (
	// ErrInterceptorChainNotWired classifies constructor and handler wiring failures.
	ErrInterceptorChainNotWired = errors.New("interceptor chain is not wired: auth")
	// ErrProcedureAuthorizationInvalid identifies an incomplete or contradictory
	// RPC policy registry.
	ErrProcedureAuthorizationInvalid = errors.New("procedure authorization is invalid: auth")
)

// ProcedureClass identifies the one authentication path an RPC uses.
type ProcedureClass uint8

const (
	ProcedurePublic ProcedureClass = iota + 1
	ProcedurePermissionGated
	ProcedureAltAuth
)

// ProcedureAuthorization is the complete authorization policy for one RPC.
type ProcedureAuthorization struct {
	Class      ProcedureClass
	Permission authz.Permission
}

var procedureAuthorizations = map[string]ProcedureAuthorization{
	powermanagev1connect.AgentServiceStreamProcedure:                   {Class: ProcedureAltAuth},
	powermanagev1connect.ControlServiceCompleteOidcSessionProcedure:    {Class: ProcedurePublic},
	powermanagev1connect.ControlServiceRefreshSessionProcedure:         {Class: ProcedurePublic},
	powermanagev1connect.ControlServiceStartOidcSessionProcedure:       {Class: ProcedurePublic},
	powermanagev1connect.InternalServiceStreamProcedure:                {Class: ProcedureAltAuth},
	powermanagev1connect.InternalServiceValidateTerminalTokenProcedure: {Class: ProcedureAltAuth},
	powermanagev1connect.PkiServiceEnrollAgentProcedure:                {Class: ProcedurePublic},
	powermanagev1connect.PkiServiceRenewAgentProcedure:                 {Class: ProcedurePublic},
	powermanagev1connect.PkiServiceRevokeAgentProcedure:                {Class: ProcedurePublic},
	powermanagev1connect.PkiServiceForceRenewAgentProcedure:            {Class: ProcedurePublic},
	powermanagev1connect.PkiServiceEnrollGatewayProcedure:              {Class: ProcedurePublic},
	powermanagev1connect.PkiServiceRenewGatewayProcedure:               {Class: ProcedurePublic},
	powermanagev1connect.PkiServiceRevokeGatewayProcedure:              {Class: ProcedurePublic},
	powermanagev1connect.PkiServiceConfirmAgentTrustStateProcedure:     {Class: ProcedurePublic},
	powermanagev1connect.PkiServiceConfirmGatewayTrustStateProcedure:   {Class: ProcedurePublic},
}

// ProcedureAuthorizations returns a copy of the complete RPC policy registry.
func ProcedureAuthorizations() map[string]ProcedureAuthorization {
	return maps.Clone(procedureAuthorizations)
}

// ProcedureClassifications returns a class-only view derived from the complete
// RPC policy registry.
func ProcedureClassifications() map[string]ProcedureClass {
	classifications := make(map[string]ProcedureClass, len(procedureAuthorizations))
	for procedure, policy := range procedureAuthorizations {
		classifications[procedure] = policy.Class
	}
	return classifications
}

// ClassifyProcedure resolves one RPC without defaulting unknown procedures.
func ClassifyProcedure(procedure string) (ProcedureClass, bool) {
	policy, ok := procedureAuthorizations[procedure]
	return policy.Class, ok
}

func classifyProcedureAuthorization(procedure string) (ProcedureAuthorization, bool) {
	policy, ok := procedureAuthorizations[procedure]
	return policy, ok
}

// InterceptorChain is the immutable validate → authenticate → rate-limit →
// authorize server chain.
type InterceptorChain struct {
	stages [4]connect.Interceptor
}

// NewInterceptorChain fixes the security-stage order at construction time.
func NewInterceptorChain(
	validate connect.Interceptor,
	authenticate connect.Interceptor,
	rateLimit connect.Interceptor,
	authorize connect.Interceptor,
) (*InterceptorChain, error) {
	chain := &InterceptorChain{
		stages: [4]connect.Interceptor{validate, authenticate, rateLimit, authorize},
	}
	if err := chain.ValidateWiring(); err != nil {
		return nil, err
	}
	return chain, nil
}

// ValidateWiring rejects nil and zero-value chains before handler exposure.
func (c *InterceptorChain) ValidateWiring() error {
	if c == nil {
		return ErrInterceptorChainNotWired
	}
	for _, stage := range c.stages {
		if nilcheck.Interface(stage) {
			return ErrInterceptorChainNotWired
		}
	}
	gate, ok := c.stages[len(c.stages)-1].(*AuthorizationGate)
	if !ok || gate.ValidateWiring() != nil {
		return ErrInterceptorChainNotWired
	}
	return nil
}

// WrapUnary implements connect.Interceptor.
func (c *InterceptorChain) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	if c.ValidateWiring() != nil || next == nil {
		return func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
			return nil, boundaryNotWiredError()
		}
	}
	for index := len(c.stages) - 1; index >= 0; index-- {
		next = c.stages[index].WrapUnary(next)
	}
	return next
}

// WrapStreamingClient implements connect.Interceptor.
func (c *InterceptorChain) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	if c.ValidateWiring() != nil || next == nil {
		return func(_ context.Context, spec connect.Spec) connect.StreamingClientConn {
			return &rejectedStreamingClientConn{
				spec:          spec,
				requestHeader: make(http.Header),
			}
		}
	}
	for index := len(c.stages) - 1; index >= 0; index-- {
		next = c.stages[index].WrapStreamingClient(next)
	}
	return next
}

type rejectedStreamingClientConn struct {
	spec          connect.Spec
	requestHeader http.Header
}

func (c *rejectedStreamingClientConn) Spec() connect.Spec {
	return c.spec
}

func (*rejectedStreamingClientConn) Peer() connect.Peer {
	return connect.Peer{}
}

func (*rejectedStreamingClientConn) Send(any) error {
	return boundaryNotWiredError()
}

func (c *rejectedStreamingClientConn) RequestHeader() http.Header {
	return c.requestHeader
}

func (*rejectedStreamingClientConn) CloseRequest() error {
	return boundaryNotWiredError()
}

func (*rejectedStreamingClientConn) Receive(any) error {
	return boundaryNotWiredError()
}

func (*rejectedStreamingClientConn) ResponseHeader() http.Header {
	return make(http.Header)
}

func (*rejectedStreamingClientConn) ResponseTrailer() http.Header {
	return make(http.Header)
}

func (*rejectedStreamingClientConn) CloseResponse() error {
	return boundaryNotWiredError()
}

// WrapStreamingHandler implements connect.Interceptor.
func (c *InterceptorChain) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	if c.ValidateWiring() != nil || next == nil {
		return func(context.Context, connect.StreamingHandlerConn) error {
			return boundaryNotWiredError()
		}
	}
	for index := len(c.stages) - 1; index >= 0; index-- {
		next = c.stages[index].WrapStreamingHandler(next)
	}
	return next
}

func boundaryNotWiredError() error {
	return connect.NewError(connect.CodeInternal, errors.New("authentication boundary is not wired"))
}
