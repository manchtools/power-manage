// Package pki holds control's signing authorities and DER-backed verification
// seams for SPEC-006. Private CA and command keys never leave this package.
package pki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"sync"
	"time"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/sign"
	"github.com/manchtools/power-manage/server/internal/store"
)

type certificateAuthority struct {
	certificate *x509.Certificate
	signer      crypto.Signer
	publicKey   []byte
}

var reservedCRLExtensions = []asn1.ObjectIdentifier{
	{2, 5, 29, 20}, // cRLNumber is sourced from RevocationList.Number.
	{2, 5, 29, 35}, // authorityKeyIdentifier is sourced from the CA certificate.
}

// Authorities is control's opaque, purpose-separated signing-key custody set.
// Its methods expose signing operations, never the private keys themselves.
type Authorities struct {
	mu             sync.RWMutex
	agentCA        certificateAuthority
	gatewayCA      certificateAuthority
	commandSigner  crypto.Signer
	agentIssuers   map[[32]byte]certificateAuthority
	gatewayIssuers map[[32]byte]certificateAuthority
}

// NewAuthorities validates all three control-only authorities before boot.
func NewAuthorities(
	agentCertificateDER []byte,
	agentSigner crypto.Signer,
	gatewayCertificateDER []byte,
	gatewaySigner crypto.Signer,
	commandSigner crypto.Signer,
) (*Authorities, error) {
	agentCA, err := newCertificateAuthority("agent", agentCertificateDER, agentSigner)
	if err != nil {
		return nil, err
	}
	gatewayCA, err := newCertificateAuthority("gateway", gatewayCertificateDER, gatewaySigner)
	if err != nil {
		return nil, err
	}
	if err := sign.ValidateSigningKey(commandSigner); err != nil {
		return nil, fmt.Errorf("validate command signing key: %w", err)
	}
	commandPublicKey, err := marshalPublicKey(commandSigner.Public())
	if err != nil {
		return nil, fmt.Errorf("marshal command public key: %w", err)
	}
	if bytes.Equal(agentCA.publicKey, gatewayCA.publicKey) {
		return nil, fmt.Errorf("agent and gateway CA keys are reused")
	}
	if bytes.Equal(commandPublicKey, agentCA.publicKey) {
		return nil, fmt.Errorf("command key reuses agent CA key")
	}
	if bytes.Equal(commandPublicKey, gatewayCA.publicKey) {
		return nil, fmt.Errorf("command key reuses gateway CA key")
	}
	authorities := &Authorities{
		agentCA:        agentCA,
		gatewayCA:      gatewayCA,
		commandSigner:  commandSigner,
		agentIssuers:   make(map[[32]byte]certificateAuthority),
		gatewayIssuers: make(map[[32]byte]certificateAuthority),
	}
	authorities.agentIssuers[authorityFingerprint(agentCA.certificate.Raw)] = agentCA
	authorities.gatewayIssuers[authorityFingerprint(gatewayCA.certificate.Raw)] = gatewayCA
	return authorities, nil
}

// SignCommand is control's sole command-signing chokepoint.
func (a *Authorities) SignCommand(command *powermanagev1.SignedCommand) error {
	if a == nil || a.commandSigner == nil {
		return fmt.Errorf("command signer is not wired")
	}
	return sign.SignCommand(a.commandSigner, command)
}

// SignAgentRevocationList signs an agent CRL with the current agent CA.
func (a *Authorities) SignAgentRevocationList(template *x509.RevocationList) ([]byte, error) {
	authority, ok := a.currentAuthority(store.CertificateClassAgent)
	if !ok {
		return nil, fmt.Errorf("agent CRL signer is not wired")
	}
	return authority.signRevocationList("agent", template)
}

// SignGatewayRevocationList signs a gateway CRL with the current gateway CA.
func (a *Authorities) SignGatewayRevocationList(template *x509.RevocationList) ([]byte, error) {
	authority, ok := a.currentAuthority(store.CertificateClassGateway)
	if !ok {
		return nil, fmt.Errorf("gateway CRL signer is not wired")
	}
	return authority.signRevocationList("gateway", template)
}

func (a *Authorities) signRevocationListForIssuer(
	class store.CertificateClass,
	issuer [sha256.Size]byte,
	template *x509.RevocationList,
) ([]byte, error) {
	authority, ok := a.authorityForIssuer(class, issuer)
	if !ok {
		return nil, fmt.Errorf("%s CRL issuer is not wired", class)
	}
	return authority.signRevocationList(string(class), template)
}

func authorityFingerprint(der []byte) [32]byte {
	return sha256.Sum256(der)
}

func (a *Authorities) currentAuthority(class store.CertificateClass) (certificateAuthority, bool) {
	if a == nil {
		return certificateAuthority{}, false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	switch class {
	case store.CertificateClassAgent:
		return a.agentCA, a.agentCA.certificate != nil && a.agentCA.signer != nil
	case store.CertificateClassGateway:
		return a.gatewayCA, a.gatewayCA.certificate != nil && a.gatewayCA.signer != nil
	default:
		return certificateAuthority{}, false
	}
}

func (a *Authorities) authorityForIssuer(class store.CertificateClass, fingerprint [32]byte) (certificateAuthority, bool) {
	if a == nil {
		return certificateAuthority{}, false
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	var authority certificateAuthority
	var ok bool
	switch class {
	case store.CertificateClassAgent:
		authority, ok = a.agentIssuers[fingerprint]
	case store.CertificateClassGateway:
		authority, ok = a.gatewayIssuers[fingerprint]
	}
	return authority, ok
}

func (a *Authorities) installAuthority(class store.CertificateClass, certificateDER []byte, signer crypto.Signer) error {
	if a == nil {
		return fmt.Errorf("authorities are not wired")
	}
	authority, err := newCertificateAuthority(string(class), certificateDER, signer)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch class {
	case store.CertificateClassAgent:
		a.agentIssuers[authorityFingerprint(certificateDER)] = authority
	case store.CertificateClassGateway:
		a.gatewayIssuers[authorityFingerprint(certificateDER)] = authority
	default:
		return fmt.Errorf("invalid certificate class")
	}
	return nil
}

func (a *Authorities) selectAuthority(class store.CertificateClass, fingerprint [32]byte) error {
	if a == nil {
		return fmt.Errorf("authorities are not wired")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	switch class {
	case store.CertificateClassAgent:
		authority, ok := a.agentIssuers[fingerprint]
		if !ok {
			return fmt.Errorf("agent issuer is not installed")
		}
		a.agentCA = authority
	case store.CertificateClassGateway:
		authority, ok := a.gatewayIssuers[fingerprint]
		if !ok {
			return fmt.Errorf("gateway issuer is not installed")
		}
		a.gatewayCA = authority
	default:
		return fmt.Errorf("invalid certificate class")
	}
	return nil
}

func (a *Authorities) removeAuthority(class store.CertificateClass, fingerprint [32]byte) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if class == store.CertificateClassAgent {
		delete(a.agentIssuers, fingerprint)
	} else if class == store.CertificateClassGateway {
		delete(a.gatewayIssuers, fingerprint)
	}
}

func newCertificateAuthority(role string, certificateDER []byte, signer crypto.Signer) (certificateAuthority, error) {
	certificate, err := parseExactCertificate(certificateDER)
	if err != nil {
		return certificateAuthority{}, fmt.Errorf("parse %s CA certificate: %w", role, err)
	}
	now := time.Now()
	if now.Before(certificate.NotBefore) || now.After(certificate.NotAfter) {
		return certificateAuthority{}, fmt.Errorf("%s CA certificate is not currently valid", role)
	}
	if !certificate.BasicConstraintsValid || !certificate.IsCA {
		return certificateAuthority{}, fmt.Errorf("%s CA certificate is not a CA", role)
	}
	if certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return certificateAuthority{}, fmt.Errorf("%s CA certificate lacks certificate-signing key usage", role)
	}
	if certificate.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return certificateAuthority{}, fmt.Errorf("%s CA certificate lacks CRL-signing key usage", role)
	}
	if len(certificate.SubjectKeyId) == 0 {
		return certificateAuthority{}, fmt.Errorf("%s CA certificate lacks subject key ID", role)
	}
	if err := sign.ValidateSigningKey(certificate.PublicKey); err != nil {
		return certificateAuthority{}, fmt.Errorf("validate %s CA certificate key: %w", role, err)
	}
	if err := sign.ValidateSigningKey(signer); err != nil {
		return certificateAuthority{}, fmt.Errorf("validate %s CA signer: %w", role, err)
	}
	certificatePublicKey, err := marshalPublicKey(certificate.PublicKey)
	if err != nil {
		return certificateAuthority{}, fmt.Errorf("marshal %s CA certificate public key: %w", role, err)
	}
	signerPublicKey, err := marshalPublicKey(signer.Public())
	if err != nil {
		return certificateAuthority{}, fmt.Errorf("marshal %s CA signer public key: %w", role, err)
	}
	if !bytes.Equal(certificatePublicKey, signerPublicKey) {
		return certificateAuthority{}, fmt.Errorf("%s CA signer does not match certificate", role)
	}
	return certificateAuthority{
		certificate: certificate,
		signer:      signer,
		publicKey:   certificatePublicKey,
	}, nil
}

func (a certificateAuthority) signRevocationList(role string, template *x509.RevocationList) ([]byte, error) {
	if template == nil {
		return nil, fmt.Errorf("%s CRL template is nil", role)
	}
	for _, extension := range template.ExtraExtensions {
		for _, reserved := range reservedCRLExtensions {
			if extension.Id.Equal(reserved) {
				return nil, fmt.Errorf("%s CRL template contains reserved CRL extension %s", role, extension.Id.String())
			}
		}
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, a.certificate, a.signer)
	if err != nil {
		return nil, fmt.Errorf("sign %s revocation list: %w", role, err)
	}
	return der, nil
}

// DERResultVerifier is control's stateless device-result verification seam.
// It parses the stored certificate DER on every call; no projected or cached
// public key can become a second authority.
type DERResultVerifier struct{}

// VerifyResult verifies a result with the key derived from exact certificate
// DER and returns only the payload bytes accepted by the shared verifier.
func (DERResultVerifier) VerifyResult(
	certificateDER []byte,
	envelope *powermanagev1.DeviceSigned,
	options sign.ResultVerifyOptions,
) ([]byte, error) {
	certificate, err := parseExactCertificate(certificateDER)
	if err != nil {
		return nil, fmt.Errorf("parse stored certificate DER: %w", err)
	}
	return sign.VerifyResult(certificate.PublicKey, envelope, options)
}

func parseExactCertificate(der []byte) (*x509.Certificate, error) {
	ownedDER := append([]byte(nil), der...)
	certificate, err := x509.ParseCertificate(ownedDER)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(certificate.Raw, ownedDER) {
		return nil, fmt.Errorf("certificate DER contains trailing data")
	}
	return certificate, nil
}

func marshalPublicKey(key crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return der, nil
}
