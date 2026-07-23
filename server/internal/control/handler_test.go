package control

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"

	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/server/internal/auth"
)

func TestNewHTTPHandler_RejectsMissingDependencies(t *testing.T) {
	noop := connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
			return next(ctx, request)
		}
	})
	chain, err := auth.NewInterceptorChain(noop, noop, noop, noop)
	if err != nil {
		t.Fatalf("NewInterceptorChain: %v", err)
	}
	var typedNilService *testControlService
	tests := []struct {
		name    string
		service any
		chain   *auth.InterceptorChain
		wantErr error
	}{
		{name: "nil service", service: nil, chain: chain, wantErr: ErrServiceNotWired},
		{name: "typed nil service", service: typedNilService, chain: chain, wantErr: ErrServiceNotWired},
		{name: "nil chain", service: testControlService{}, chain: nil, wantErr: auth.ErrInterceptorChainNotWired},
		{name: "zero chain", service: testControlService{}, chain: &auth.InterceptorChain{}, wantErr: auth.ErrInterceptorChainNotWired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := NewHTTPHandler(test.service, test.chain); !errors.Is(err, test.wantErr) {
				t.Fatalf("NewHTTPHandler error = %v; want category %v", err, test.wantErr)
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
