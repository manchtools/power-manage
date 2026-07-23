package auth

import (
	"context"
	"errors"
	"maps"
	"net/http"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/sdk/nilcheck"
)

// ErrInterceptorChainNotWired classifies constructor and handler wiring failures.
var ErrInterceptorChainNotWired = errors.New("interceptor chain is not wired: auth")

// ProcedureClass identifies the one authentication path an RPC uses.
type ProcedureClass uint8

const (
	ProcedurePublic ProcedureClass = iota + 1
	ProcedurePermissionGated
	ProcedureAltAuth
)

var procedureClassifications = map[string]ProcedureClass{
	powermanagev1connect.AgentServiceStreamProcedure:                   ProcedureAltAuth,
	powermanagev1connect.ControlServiceCompleteOidcSessionProcedure:    ProcedurePublic,
	powermanagev1connect.ControlServiceRefreshSessionProcedure:         ProcedurePublic,
	powermanagev1connect.ControlServiceStartOidcSessionProcedure:       ProcedurePublic,
	powermanagev1connect.InternalServiceStreamProcedure:                ProcedureAltAuth,
	powermanagev1connect.InternalServiceValidateTerminalTokenProcedure: ProcedureAltAuth,
	powermanagev1connect.PkiServiceEnrollAgentProcedure:                ProcedurePublic,
	powermanagev1connect.PkiServiceRenewAgentProcedure:                 ProcedurePublic,
	powermanagev1connect.PkiServiceRevokeAgentProcedure:                ProcedurePublic,
	powermanagev1connect.PkiServiceForceRenewAgentProcedure:            ProcedurePublic,
	powermanagev1connect.PkiServiceEnrollGatewayProcedure:              ProcedurePublic,
	powermanagev1connect.PkiServiceRenewGatewayProcedure:               ProcedurePublic,
	powermanagev1connect.PkiServiceRevokeGatewayProcedure:              ProcedurePublic,
	powermanagev1connect.PkiServiceConfirmAgentTrustStateProcedure:     ProcedurePublic,
	powermanagev1connect.PkiServiceConfirmGatewayTrustStateProcedure:   ProcedurePublic,
}

// ProcedureClassifications returns a copy of the complete RPC registry.
func ProcedureClassifications() map[string]ProcedureClass {
	return maps.Clone(procedureClassifications)
}

// ClassifyProcedure resolves one RPC without defaulting unknown procedures.
func ClassifyProcedure(procedure string) (ProcedureClass, bool) {
	class, ok := procedureClassifications[procedure]
	return class, ok
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
