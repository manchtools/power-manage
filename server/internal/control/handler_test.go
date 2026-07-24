package control

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
	"github.com/manchtools/power-manage/server/internal/authz"
)

func TestNewHTTPHandler_RejectsMissingDependencies(t *testing.T) {
	noop := connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
			return next(ctx, request)
		}
	})
	chain, err := auth.NewInterceptorChain(noop, noop, noop, testAuthorizationGate(t))
	if err != nil {
		t.Fatalf("NewInterceptorChain: %v", err)
	}
	var typedNilService *testControlService
	tests := []struct {
		name        string
		service     powermanagev1connect.ControlServiceHandler
		chain       *auth.InterceptorChain
		wantErr     error
		wantMessage string
	}{
		{name: "nil service", service: nil, chain: chain, wantErr: ErrServiceNotWired, wantMessage: "service is not wired: control"},
		{name: "typed nil service", service: typedNilService, chain: chain, wantErr: ErrServiceNotWired, wantMessage: "service is not wired: control"},
		{name: "nil chain", service: testControlService{}, chain: nil, wantErr: auth.ErrInterceptorChainNotWired, wantMessage: "interceptor chain is not wired: auth: control interceptor chain"},
		{name: "zero chain", service: testControlService{}, chain: &auth.InterceptorChain{}, wantErr: auth.ErrInterceptorChainNotWired, wantMessage: "interceptor chain is not wired: auth: control interceptor chain"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := NewHTTPHandler(test.service, test.chain)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("NewHTTPHandler error = %v; want category %v", err, test.wantErr)
			}
			if err.Error() != test.wantMessage {
				t.Fatalf("NewHTTPHandler error = %q; want %q", err, test.wantMessage)
			}
		})
	}

	path, handler, err := NewHTTPHandler(testControlService{}, chain)
	if err != nil {
		t.Fatalf("NewHTTPHandler with complete dependencies: %v", err)
	}
	if path == "" || handler == nil {
		t.Fatalf("NewHTTPHandler = (%q, %v); want non-empty path and handler", path, handler)
	}
}

type testControlService struct {
	powermanagev1connect.UnimplementedControlServiceHandler
}

func testAuthorizationGate(t *testing.T) *auth.AuthorizationGate {
	t.Helper()
	gate, err := auth.NewAuthorizationGate(testEffectiveAccessResolver{})
	if err != nil {
		t.Fatalf("create test authorization gate: %v", err)
	}
	return gate
}

type testEffectiveAccessResolver struct{}

func (testEffectiveAccessResolver) ResolveEffectiveAccess(
	context.Context,
	string,
) (authz.EffectiveAccess, error) {
	return authz.EffectiveAccess{}, nil
}
