package auth

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/emptypb"

	_ "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/sdk/guardtest"
	"github.com/manchtools/power-manage/server/internal/authz"
)

func TestGuard_RPCClassificationCoversEveryProcedure(t *testing.T) {
	procedures := guardtest.Discover(t, "contract RPC procedures", 15, discoverContractProcedures)
	classifications := ProcedureClassifications()
	registered := slices.Sorted(maps.Keys(classifications))
	if !slices.Equal(registered, procedures) {
		t.Fatalf("RPC classifications = %v; descriptor procedures = %v", registered, procedures)
	}
	for _, procedure := range procedures {
		class := classifications[procedure]
		if class != ProcedurePublic && class != ProcedurePermissionGated && class != ProcedureAltAuth {
			t.Fatalf("%s class = %v; want public, permission-gated, or alt-auth", procedure, class)
		}
	}
}

func TestProcedureClassifications_DefensivelyCopied(t *testing.T) {
	first := ProcedureClassifications()
	if len(first) == 0 {
		t.Fatal("procedure classification registry is empty")
	}
	procedure := slices.Sorted(maps.Keys(first))[0]
	want := first[procedure]
	delete(first, procedure)
	first["/unregistered.Service/Method"] = ProcedurePublic

	second := ProcedureClassifications()
	if second[procedure] != want {
		t.Fatalf("mutating returned registry changed %s classification", procedure)
	}
	if _, exists := second["/unregistered.Service/Method"]; exists {
		t.Fatal("mutating returned registry added a production classification")
	}
	if got, ok := ClassifyProcedure(procedure); !ok || got != want {
		t.Fatalf("ClassifyProcedure(%q) = (%v, %v); want (%v, true)", procedure, got, ok, want)
	}
	for _, unknown := range []string{"", "/unregistered.Service/Method"} {
		if got, ok := ClassifyProcedure(unknown); ok {
			t.Fatalf("ClassifyProcedure(%q) = (%v, true); want fail-closed miss", unknown, got)
		}
	}
}

func TestInterceptorChain_EnforcesOrder(t *testing.T) {
	var calls []string
	chain, err := NewInterceptorChain(
		recordingStage("validate", nil, &calls),
		recordingStage("authenticate", nil, &calls),
		recordingStage("rate-limit", nil, &calls),
		recordingAuthorizationGate(t, nil, &calls),
	)
	if err != nil {
		t.Fatalf("NewInterceptorChain: %v", err)
	}
	handler := chain.WrapUnary(func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		calls = append(calls, "handler")
		return connect.NewResponse(&emptypb.Empty{}), nil
	})
	if _, err := handler(t.Context(), connect.NewRequest(&emptypb.Empty{})); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("synthetic request without a procedure code = %v (%v); want Unavailable", connect.CodeOf(err), err)
	}
	want := []string{"validate", "authenticate", "rate-limit", "authorize"}
	if !slices.Equal(calls, want) {
		t.Fatalf("interceptor order = %v; want %v", calls, want)
	}
}

func TestNewInterceptorChain_RejectsMissingStages(t *testing.T) {
	var calls []string
	complete := [4]connect.Interceptor{
		recordingStage("validate", nil, &calls),
		recordingStage("authenticate", nil, &calls),
		recordingStage("rate-limit", nil, &calls),
		recordingAuthorizationGate(t, nil, &calls),
	}
	var typedNilInterceptor *recordingInterceptor
	var typedNilGate *AuthorizationGate
	for index, name := range []string{"validate", "authenticate", "rate-limit", "authorize"} {
		typedNil := connect.Interceptor(typedNilInterceptor)
		if index == len(complete)-1 {
			typedNil = typedNilGate
		}
		for _, missing := range []struct {
			name  string
			stage connect.Interceptor
		}{
			{name: "nil", stage: nil},
			{name: "typed nil", stage: typedNil},
		} {
			t.Run(name+"/"+missing.name, func(t *testing.T) {
				stages := complete
				stages[index] = missing.stage
				if _, err := NewInterceptorChain(stages[0], stages[1], stages[2], stages[3]); !errors.Is(err, ErrInterceptorChainNotWired) {
					t.Fatalf("NewInterceptorChain error = %v; want category %v", err, ErrInterceptorChainNotWired)
				}
			})
		}
	}
}

func TestInterceptorChain_ShortCircuitsInOrder(t *testing.T) {
	stages := []string{"validate", "authenticate", "rate-limit", "authorize"}
	for stop := range stages {
		t.Run(stages[stop], func(t *testing.T) {
			var calls []string
			stopErr := errors.New("stop")
			interceptors := make([]connect.Interceptor, len(stages))
			for index, stage := range stages[:len(stages)-1] {
				var err error
				if index == stop {
					err = stopErr
				}
				interceptors[index] = recordingStage(stage, err, &calls)
			}
			var authorizationErr error
			if stop == len(stages)-1 {
				authorizationErr = stopErr
			}
			interceptors[len(stages)-1] = recordingAuthorizationGate(t, authorizationErr, &calls)
			chain, err := NewInterceptorChain(interceptors[0], interceptors[1], interceptors[2], interceptors[3])
			if err != nil {
				t.Fatalf("NewInterceptorChain: %v", err)
			}
			handler := chain.WrapUnary(func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
				calls = append(calls, "handler")
				return connect.NewResponse(&emptypb.Empty{}), nil
			})
			_, callErr := handler(t.Context(), connect.NewRequest(&emptypb.Empty{}))
			if stop == len(stages)-1 {
				if connect.CodeOf(callErr) != connect.CodePermissionDenied {
					t.Fatalf("authorization chain code = %v (%v); want PermissionDenied", connect.CodeOf(callErr), callErr)
				}
			} else if !errors.Is(callErr, stopErr) {
				t.Fatalf("chain error = %v; want %v", callErr, stopErr)
			}
			if want := stages[:stop+1]; !slices.Equal(calls, want) {
				t.Fatalf("calls before %s rejection = %v; want %v", stages[stop], calls, want)
			}
		})
	}
}

func TestInterceptorChain_EnforcesStreamingHandlerOrder(t *testing.T) {
	var calls []string
	chain, err := NewInterceptorChain(
		recordingStage("validate", nil, &calls),
		recordingStage("authenticate", nil, &calls),
		recordingStage("rate-limit", nil, &calls),
		recordingAuthorizationGate(t, nil, &calls),
	)
	if err != nil {
		t.Fatalf("NewInterceptorChain: %v", err)
	}
	handler := chain.WrapStreamingHandler(func(context.Context, connect.StreamingHandlerConn) error {
		calls = append(calls, "handler")
		return nil
	})
	if err := handler(t.Context(), authorizationTestStream{procedure: testAuthorizationProcedure}); err != nil {
		t.Fatalf("invoke streaming interceptor chain: %v", err)
	}
	want := []string{"validate", "authenticate", "rate-limit", "authorize", "handler"}
	if !slices.Equal(calls, want) {
		t.Fatalf("streaming interceptor order = %v; want %v", calls, want)
	}
}

func TestInterceptorChain_ShortCircuitsStreamingHandlerInOrder(t *testing.T) {
	stages := []string{"validate", "authenticate", "rate-limit", "authorize"}
	for stop := range stages {
		t.Run(stages[stop], func(t *testing.T) {
			var calls []string
			stopErr := errors.New("stop")
			interceptors := make([]connect.Interceptor, len(stages))
			for index, stage := range stages[:len(stages)-1] {
				var err error
				if index == stop {
					err = stopErr
				}
				interceptors[index] = recordingStage(stage, err, &calls)
			}
			var authorizationErr error
			if stop == len(stages)-1 {
				authorizationErr = stopErr
			}
			interceptors[len(stages)-1] = recordingAuthorizationGate(t, authorizationErr, &calls)
			chain, err := NewInterceptorChain(interceptors[0], interceptors[1], interceptors[2], interceptors[3])
			if err != nil {
				t.Fatalf("NewInterceptorChain: %v", err)
			}
			handler := chain.WrapStreamingHandler(func(context.Context, connect.StreamingHandlerConn) error {
				calls = append(calls, "handler")
				return nil
			})
			callErr := handler(t.Context(), authorizationTestStream{procedure: testAuthorizationProcedure})
			if stop == len(stages)-1 {
				if connect.CodeOf(callErr) != connect.CodePermissionDenied {
					t.Fatalf("streaming authorization code = %v (%v); want PermissionDenied", connect.CodeOf(callErr), callErr)
				}
			} else if !errors.Is(callErr, stopErr) {
				t.Fatalf("streaming chain error = %v; want %v", callErr, stopErr)
			}
			if want := stages[:stop+1]; !slices.Equal(calls, want) {
				t.Fatalf("streaming calls before %s rejection = %v; want %v", stages[stop], calls, want)
			}
		})
	}
}

func TestInterceptorChain_InvalidStreamingClientFailsClosed(t *testing.T) {
	var nilChain *InterceptorChain
	for _, test := range []struct {
		name  string
		chain *InterceptorChain
	}{
		{name: "nil", chain: nilChain},
		{name: "zero", chain: &InterceptorChain{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			nextCalled := false
			connection := test.chain.WrapStreamingClient(func(context.Context, connect.Spec) connect.StreamingClientConn {
				nextCalled = true
				return nil
			})(t.Context(), connect.Spec{})
			if connection == nil {
				t.Fatal("invalid chain returned a nil streaming client connection")
			}
			if nextCalled {
				t.Fatal("invalid chain called the next streaming client")
			}
			for _, operation := range []struct {
				name string
				call func() error
			}{
				{name: "Send", call: func() error { return connection.Send(&emptypb.Empty{}) }},
				{name: "Receive", call: func() error { return connection.Receive(&emptypb.Empty{}) }},
				{name: "CloseRequest", call: connection.CloseRequest},
				{name: "CloseResponse", call: connection.CloseResponse},
			} {
				t.Run(operation.name, func(t *testing.T) {
					err := operation.call()
					if connect.CodeOf(err) != connect.CodeInternal {
						t.Fatalf("%s error = %v; want CodeInternal", operation.name, err)
					}
				})
			}
		})
	}
}

func discoverContractProcedures() ([]string, error) {
	var procedures []string
	protoregistry.GlobalFiles.RangeFiles(func(file protoreflect.FileDescriptor) bool {
		if file.Package() != "powermanage.v1" {
			return true
		}
		services := file.Services()
		for serviceIndex := 0; serviceIndex < services.Len(); serviceIndex++ {
			service := services.Get(serviceIndex)
			methods := service.Methods()
			for methodIndex := 0; methodIndex < methods.Len(); methodIndex++ {
				method := methods.Get(methodIndex)
				procedures = append(procedures, "/"+string(service.FullName())+"/"+string(method.Name()))
			}
		}
		return true
	})
	slices.Sort(procedures)
	return procedures, nil
}

func recordingStage(name string, stageErr error, calls *[]string) connect.Interceptor {
	return &recordingInterceptor{name: name, err: stageErr, calls: calls}
}

func recordingAuthorizationGate(
	t *testing.T,
	stageErr error,
	calls *[]string,
) *AuthorizationGate {
	t.Helper()
	gate, err := newAuthorizationGate(
		effectiveAccessResolverFunc(func(context.Context, string) (authz.EffectiveAccess, error) {
			t.Fatal("public authorization policy called the effective-access resolver")
			return authz.EffectiveAccess{}, nil
		}),
		func(string) (ProcedureAuthorization, bool) {
			*calls = append(*calls, "authorize")
			return ProcedureAuthorization{Class: ProcedurePublic}, stageErr == nil
		},
	)
	if err != nil {
		t.Fatalf("create recording authorization gate: %v", err)
	}
	return gate
}

type recordingInterceptor struct {
	name  string
	err   error
	calls *[]string
}

func (r *recordingInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
		*r.calls = append(*r.calls, r.name)
		if r.err != nil {
			return nil, r.err
		}
		return next(ctx, request)
	}
}

func (r *recordingInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (r *recordingInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, connection connect.StreamingHandlerConn) error {
		*r.calls = append(*r.calls, r.name)
		if r.err != nil {
			return r.err
		}
		return next(ctx, connection)
	}
}
