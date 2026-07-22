// Package control provides control's fail-closed composition root.
package control

import (
	"context"
	"crypto/x509"
	"fmt"
	"reflect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/sign"
)

// DeviceSignatureVerifier verifies a result against stored certificate DER.
type DeviceSignatureVerifier interface {
	VerifyResult([]byte, *powermanagev1.DeviceSigned, sign.ResultVerifyOptions) ([]byte, error)
}

// BindingResolver authorizes a claimed device/gateway association.
type BindingResolver interface {
	ResolveDeviceGateway(context.Context, string, string) (bool, error)
}

// CRLSigner signs the separate agent and gateway revocation lists.
type CRLSigner interface {
	SignAgentRevocationList(*x509.RevocationList) ([]byte, error)
	SignGatewayRevocationList(*x509.RevocationList) ([]byte, error)
}

// Runtime is a control process whose mandatory security gates are wired.
type Runtime struct {
	verifier  DeviceSignatureVerifier
	resolver  BindingResolver
	crlSigner CRLSigner
}

// NewRuntime refuses to construct control when any mandatory gate is absent.
func NewRuntime(verifier DeviceSignatureVerifier, resolver BindingResolver, crlSigner CRLSigner) (*Runtime, error) {
	if interfaceNil(verifier) {
		return nil, fmt.Errorf("device signature verifier is not wired")
	}
	if interfaceNil(resolver) {
		return nil, fmt.Errorf("device/gateway binding resolver is not wired")
	}
	if interfaceNil(crlSigner) {
		return nil, fmt.Errorf("CRL signer is not wired")
	}
	return &Runtime{verifier: verifier, resolver: resolver, crlSigner: crlSigner}, nil
}

func interfaceNil(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
