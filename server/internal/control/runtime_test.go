package control_test

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/sign"
	"github.com/manchtools/power-manage/server/internal/control"
)

// TestNewRuntime_RequiresSecurityDependencies is AC-15/GUARD-006-6: nil and
// typed-nil verifier, binding resolver, or CRL signer must stop control boot.
func TestNewRuntime_RequiresSecurityDependencies(t *testing.T) {
	verifier := &verifierStub{}
	resolver := &resolverStub{}
	crlSigner := &crlSignerStub{}
	var typedNilVerifier *verifierStub
	var typedNilResolver *resolverStub
	var typedNilCRLSigner *crlSignerStub
	tests := []struct {
		name    string
		build   func() (*control.Runtime, error)
		wantErr string
	}{
		{name: "nil device signature verifier", build: func() (*control.Runtime, error) {
			return control.NewRuntime(nil, resolver, crlSigner)
		}, wantErr: "device signature verifier"},
		{name: "typed-nil device signature verifier", build: func() (*control.Runtime, error) {
			return control.NewRuntime(typedNilVerifier, resolver, crlSigner)
		}, wantErr: "device signature verifier"},
		{name: "nil binding resolver", build: func() (*control.Runtime, error) {
			return control.NewRuntime(verifier, nil, crlSigner)
		}, wantErr: "binding resolver"},
		{name: "typed-nil binding resolver", build: func() (*control.Runtime, error) {
			return control.NewRuntime(verifier, typedNilResolver, crlSigner)
		}, wantErr: "binding resolver"},
		{name: "nil CRL signer", build: func() (*control.Runtime, error) {
			return control.NewRuntime(verifier, resolver, nil)
		}, wantErr: "CRL signer"},
		{name: "typed-nil CRL signer", build: func() (*control.Runtime, error) {
			return control.NewRuntime(verifier, resolver, typedNilCRLSigner)
		}, wantErr: "CRL signer"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, err := test.build()
			if runtime != nil {
				t.Errorf("NewRuntime returned a runtime with %s", test.name)
			}
			assertErrorContains(t, err, test.wantErr)
		})
	}
}

// TestNewRuntime_AcceptsWiredSecurityDependencies proves construction checks
// wiring without invoking operational dependencies during boot.
func TestNewRuntime_AcceptsWiredSecurityDependencies(t *testing.T) {
	verifier := &verifierStub{}
	resolver := &resolverStub{}
	crlSigner := &crlSignerStub{}
	runtime, err := control.NewRuntime(verifier, resolver, crlSigner)
	if err != nil {
		t.Fatalf("NewRuntime rejected wired dependencies: %v", err)
	}
	if runtime == nil {
		t.Fatal("NewRuntime returned nil runtime")
	}
	if verifier.called || resolver.called || crlSigner.called {
		t.Fatal("NewRuntime invoked an operational dependency during wiring validation")
	}
}

type verifierStub struct{ called bool }

func (s *verifierStub) VerifyResult([]byte, *powermanagev1.DeviceSigned, sign.ResultVerifyOptions) ([]byte, error) {
	s.called = true
	return nil, nil
}

type resolverStub struct{ called bool }

func (s *resolverStub) ResolveDeviceGateway(context.Context, string, string) (bool, error) {
	s.called = true
	return true, nil
}

type crlSignerStub struct{ called bool }

func (s *crlSignerStub) SignAgentRevocationList(*x509.RevocationList) ([]byte, error) {
	s.called = true
	return nil, nil
}

func (s *crlSignerStub) SignGatewayRevocationList(*x509.RevocationList) ([]byte, error) {
	s.called = true
	return nil, nil
}

func assertErrorContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("got nil error; want rejection containing %q", want)
	}
	if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
		t.Fatalf("error = %q; want substring %q", err, want)
	}
}
