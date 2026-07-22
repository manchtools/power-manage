// Package signing owns the agent's command-verification and result-signing
// chokepoints for SPEC-006. It holds no CA private key.
package signing

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/sign"
)

// Profile holds the command public key and the device's enrolled private key.
type Profile struct {
	commandKey crypto.PublicKey
	deviceKey  crypto.Signer
}

// NewProfile validates both agent signing roles before boot. The command key
// must be public-only; command private-key custody belongs exclusively to
// control.
func NewProfile(commandKey crypto.PublicKey, deviceKey crypto.Signer) (*Profile, error) {
	if _, private := commandKey.(crypto.Signer); private {
		return nil, fmt.Errorf("command verification key must be public; its private key stays on control")
	}
	if err := sign.ValidateSigningKey(commandKey); err != nil {
		return nil, fmt.Errorf("validate command verification key: %w", err)
	}
	if err := sign.ValidateSigningKey(deviceKey); err != nil {
		return nil, fmt.Errorf("validate device signing key: %w", err)
	}
	commandPublicKey, err := x509.MarshalPKIXPublicKey(commandKey)
	if err != nil {
		return nil, fmt.Errorf("marshal command verification key: %w", err)
	}
	devicePublicKey, err := x509.MarshalPKIXPublicKey(deviceKey.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal device signing key: %w", err)
	}
	if bytes.Equal(commandPublicKey, devicePublicKey) {
		return nil, fmt.Errorf("command and device signing keys must differ")
	}
	return &Profile{commandKey: commandKey, deviceKey: deviceKey}, nil
}

// VerifyCommand is the agent's sole command-verification chokepoint.
func (p *Profile) VerifyCommand(command *powermanagev1.SignedCommand, options sign.VerifyOptions) ([]byte, error) {
	if p == nil || p.commandKey == nil {
		return nil, fmt.Errorf("command verifier is not wired")
	}
	return sign.VerifyCommand(p.commandKey, command, options)
}

// SignResult is the agent's sole result-signing chokepoint.
func (p *Profile) SignResult(envelope *powermanagev1.DeviceSigned) error {
	if p == nil || p.deviceKey == nil {
		return fmt.Errorf("device result signer is not wired")
	}
	return sign.SignResult(p.deviceKey, envelope)
}
