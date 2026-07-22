// Package enroll implements the agent's local-key CSR enrollment flow and
// authorization-neutral local relay for SPEC-006 M4.
package enroll

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/contract/seal"
	"github.com/manchtools/power-manage/contract/sign"
)

const (
	maxRegistrationTokenBytes = 512
	agentCertificateLifetime  = 365 * 24 * time.Hour
)

// CredentialBundle is the verified public identity plus the two private keys
// generated locally for it. Private fields never cross the enrollment RPC.
type CredentialBundle struct {
	DeviceID                       string
	CertificateDER                 []byte
	CertificateAuthorityDER        []byte
	GatewayCertificateAuthorityDER []byte
	PrivateKey                     crypto.Signer
	SealingPrivateKey              *ecdh.PrivateKey
}

// CredentialStore owns first publication, strict loading, and atomic renewal
// replacement for the agent's single local identity.
type CredentialStore interface {
	Create(context.Context, CredentialBundle) error
	Load(context.Context) (CredentialBundle, error)
	Replace(context.Context, CredentialBundle) error
}

// Client generates local keys, submits their public proof, validates TOFU/pin
// continuity, and creates the first credential bundle.
type Client struct {
	remote                   powermanagev1connect.PkiServiceClient
	store                    CredentialStore
	now                      func() time.Time
	renewalMu                sync.Mutex
	pendingRenewalSealingKey *ecdh.PrivateKey
}

// NewClient validates the remote and local credential-custody dependencies.
func NewClient(remote powermanagev1connect.PkiServiceClient, store CredentialStore) (*Client, error) {
	if isNilEnrollmentDependency(remote) {
		return nil, errors.New("enroll: nil PkiService client")
	}
	if isNilEnrollmentDependency(store) {
		return nil, errors.New("enroll: nil credential store")
	}
	return &Client{remote: remote, store: store, now: time.Now}, nil
}

// Enroll performs one fresh enrollment. Existing credentials are refused by
// the store; reset is the only supported path to another identity.
func (c *Client) Enroll(ctx context.Context, token, caFingerprint string) (string, error) {
	if c == nil || isNilEnrollmentDependency(c.remote) || isNilEnrollmentDependency(c.store) || c.now == nil {
		return "", errors.New("enroll: client is not wired")
	}
	if ctx == nil {
		return "", errors.New("enroll: nil context")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if token == "" || len(token) > maxRegistrationTokenBytes {
		return "", errors.New("enroll: registration token is invalid")
	}
	pin, err := parseCAFingerprint(caFingerprint)
	if err != nil {
		return "", err
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("enroll: generate mTLS private key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, privateKey)
	if err != nil {
		return "", fmt.Errorf("enroll: create certificate signing request: %w", err)
	}
	sealingPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("enroll: generate sealing private key: %w", err)
	}
	response, err := c.remote.EnrollAgent(ctx, connect.NewRequest(&powermanagev1.EnrollAgentRequest{
		RegistrationToken:            token,
		CertificateSigningRequestDer: csrDER,
		SealingPublicKey:             sealingPrivateKey.PublicKey().Bytes(),
	}))
	if err != nil {
		return "", fmt.Errorf("enroll: PkiService enrollment: %w", err)
	}
	if response == nil || response.Msg == nil {
		return "", errors.New("enroll: PkiService returned an empty response")
	}
	deviceID, err := validateEnrollmentResponse(
		response.Msg.GetCertificateDer(),
		response.Msg.GetCertificateAuthorityDer(),
		privateKey.Public(),
		pin,
		c.now(),
	)
	if err != nil {
		return "", err
	}
	if err := validateGatewayTrustAnchor(
		response.Msg.GetGatewayCertificateAuthorityDer(),
		response.Msg.GetCertificateAuthorityDer(),
		c.now(),
		true,
	); err != nil {
		return "", err
	}
	bundle := CredentialBundle{
		DeviceID:                       deviceID,
		CertificateDER:                 bytes.Clone(response.Msg.GetCertificateDer()),
		CertificateAuthorityDER:        bytes.Clone(response.Msg.GetCertificateAuthorityDer()),
		GatewayCertificateAuthorityDER: bytes.Clone(response.Msg.GetGatewayCertificateAuthorityDer()),
		PrivateKey:                     privateKey,
		SealingPrivateKey:              sealingPrivateKey,
	}
	if err := c.store.Create(ctx, bundle); err != nil {
		return "", fmt.Errorf("enroll: store credentials: %w", err)
	}
	return deviceID, nil
}

// Renew proves possession of the enrolled mTLS key, rotates the sealing key,
// verifies identity and CA continuity, and atomically replaces credentials.
func (c *Client) Renew(ctx context.Context) error {
	if c == nil || isNilEnrollmentDependency(c.remote) || isNilEnrollmentDependency(c.store) || c.now == nil {
		return errors.New("enroll: client is not wired")
	}
	if ctx == nil {
		return errors.New("enroll: nil context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.renewalMu.Lock()
	defer c.renewalMu.Unlock()
	current, err := c.store.Load(ctx)
	if err != nil {
		return fmt.Errorf("enroll: load credentials for renewal: %w", err)
	}
	if err := validateStoredCredentialBundle(current); err != nil {
		return fmt.Errorf("enroll: validate credentials for renewal: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, current.PrivateKey)
	if err != nil {
		return fmt.Errorf("enroll: create renewal certificate signing request: %w", err)
	}
	sealingPrivateKey := c.pendingRenewalSealingKey
	if sealingPrivateKey == nil {
		sealingPrivateKey, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("enroll: generate renewed sealing private key: %w", err)
		}
		c.pendingRenewalSealingKey = sealingPrivateKey
	}
	response, err := c.remote.RenewAgent(ctx, connect.NewRequest(&powermanagev1.RenewAgentRequest{
		CertificateDer:               bytes.Clone(current.CertificateDER),
		CertificateSigningRequestDer: csrDER,
		SealingPublicKey:             sealingPrivateKey.PublicKey().Bytes(),
	}))
	if err != nil {
		return fmt.Errorf("enroll: PkiService renewal: %w", err)
	}
	if response == nil || response.Msg == nil {
		return errors.New("enroll: PkiService returned an empty renewal response")
	}
	deviceID, err := validateEnrollmentResponse(
		response.Msg.GetCertificateDer(),
		response.Msg.GetCertificateAuthorityDer(),
		current.PrivateKey.Public(),
		nil,
		c.now(),
	)
	if err != nil {
		return fmt.Errorf("enroll: validate renewal response: %w", err)
	}
	if deviceID != current.DeviceID {
		return errors.New("enroll: renewed certificate device ID mismatch")
	}
	if !bytes.Equal(response.Msg.GetCertificateAuthorityDer(), current.CertificateAuthorityDER) {
		return errors.New("enroll: renewed certificate authority differs from enrolled authority")
	}
	if err := validateGatewayTrustAnchor(
		response.Msg.GetGatewayCertificateAuthorityDer(),
		response.Msg.GetCertificateAuthorityDer(),
		c.now(),
		true,
	); err != nil {
		return fmt.Errorf("enroll: validate renewal gateway certificate authority: %w", err)
	}
	if !bytes.Equal(response.Msg.GetGatewayCertificateAuthorityDer(), current.GatewayCertificateAuthorityDER) {
		return errors.New("enroll: renewed gateway certificate authority differs from enrolled authority")
	}
	replacement := CredentialBundle{
		DeviceID:                       current.DeviceID,
		CertificateDER:                 bytes.Clone(response.Msg.GetCertificateDer()),
		CertificateAuthorityDER:        bytes.Clone(response.Msg.GetCertificateAuthorityDer()),
		GatewayCertificateAuthorityDER: bytes.Clone(response.Msg.GetGatewayCertificateAuthorityDer()),
		PrivateKey:                     current.PrivateKey,
		SealingPrivateKey:              sealingPrivateKey,
	}
	if err := c.store.Replace(ctx, replacement); err != nil {
		return fmt.Errorf("enroll: replace renewed credentials: %w", err)
	}
	c.pendingRenewalSealingKey = nil
	return nil
}

func validateEnrollmentResponse(
	certificateDER []byte,
	certificateAuthorityDER []byte,
	expectedPublicKey crypto.PublicKey,
	pin []byte,
	now time.Time,
) (string, error) {
	certificateAuthority, err := parseExactCertificate(certificateAuthorityDER)
	if err != nil {
		return "", fmt.Errorf("enroll: parse certificate authority: %w", err)
	}
	if !certificateAuthority.IsCA || !certificateAuthority.BasicConstraintsValid || certificateAuthority.KeyUsage&x509.KeyUsageCertSign == 0 {
		return "", errors.New("enroll: certificate authority has an invalid profile")
	}
	if err := sign.ValidateSigningKey(certificateAuthority.PublicKey); err != nil {
		return "", fmt.Errorf("enroll: validate certificate authority key: %w", err)
	}
	if now.Before(certificateAuthority.NotBefore) || now.After(certificateAuthority.NotAfter) {
		return "", errors.New("enroll: certificate authority is not currently valid")
	}
	fingerprint := sha256.Sum256(certificateAuthority.Raw)
	if len(pin) != 0 && subtle.ConstantTimeCompare(fingerprint[:], pin) != 1 {
		return "", errors.New("enroll: certificate authority fingerprint mismatch")
	}
	certificate, err := parseExactCertificate(certificateDER)
	if err != nil {
		return "", fmt.Errorf("enroll: parse issued certificate: %w", err)
	}
	if !publicKeysEqual(certificate.PublicKey, expectedPublicKey) {
		return "", errors.New("enroll: issued certificate public key mismatch")
	}
	class, deviceID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil {
		return "", fmt.Errorf("enroll: parse issued certificate identity: %w", err)
	}
	if class != identity.AgentClass {
		return "", fmt.Errorf("enroll: issued certificate class %q is not agent", class)
	}
	if certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		certificate.NotAfter.Sub(certificate.NotBefore) != agentCertificateLifetime {
		return "", errors.New("enroll: issued certificate has an invalid agent profile")
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificateAuthority)
	if _, err := certificate.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return "", fmt.Errorf("enroll: verify issued certificate: %w", err)
	}
	return deviceID, nil
}

func parseCAFingerprint(value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	encoded := value
	if strings.HasPrefix(strings.ToLower(encoded), "sha256:") {
		encoded = encoded[len("sha256:"):]
	}
	if len(encoded) != sha256.Size*2 {
		return nil, errors.New("enroll: CA fingerprint must contain 64 hexadecimal characters")
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, errors.New("enroll: CA fingerprint is not hexadecimal")
	}
	return decoded, nil
}

func parseExactCertificate(der []byte) (*x509.Certificate, error) {
	ownedDER := bytes.Clone(der)
	certificate, err := x509.ParseCertificate(ownedDER)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(certificate.Raw, ownedDER) {
		return nil, errors.New("certificate DER contains trailing data")
	}
	return certificate, nil
}

func publicKeysEqual(first, second crypto.PublicKey) bool {
	firstDER, err := x509.MarshalPKIXPublicKey(first)
	if err != nil {
		return false
	}
	secondDER, err := x509.MarshalPKIXPublicKey(second)
	return err == nil && bytes.Equal(firstDER, secondDER)
}

func isNilEnrollmentDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func validateCredentialBundle(bundle CredentialBundle, now time.Time) error {
	if isNilEnrollmentDependency(bundle.PrivateKey) || bundle.SealingPrivateKey == nil {
		return errors.New("enroll: credential bundle has a nil private key")
	}
	if err := sign.ValidateSigningKey(bundle.PrivateKey); err != nil {
		return fmt.Errorf("enroll: validate credential private key: %w", err)
	}
	deviceID, err := validateEnrollmentResponse(
		bundle.CertificateDER,
		bundle.CertificateAuthorityDER,
		bundle.PrivateKey.Public(),
		nil,
		now,
	)
	if err != nil {
		return err
	}
	if deviceID != bundle.DeviceID {
		return errors.New("enroll: credential bundle device ID mismatch")
	}
	if err := validateGatewayTrustAnchor(bundle.GatewayCertificateAuthorityDER, bundle.CertificateAuthorityDER, now, true); err != nil {
		return err
	}
	if err := seal.ValidateX25519PublicKey(bundle.SealingPrivateKey.PublicKey().Bytes()); err != nil {
		return fmt.Errorf("enroll: validate sealing private key: %w", err)
	}
	return nil
}

func validateStoredCredentialBundle(bundle CredentialBundle) error {
	if isNilEnrollmentDependency(bundle.PrivateKey) || bundle.SealingPrivateKey == nil {
		return errors.New("enroll: credential bundle has a nil private key")
	}
	if err := sign.ValidateSigningKey(bundle.PrivateKey); err != nil {
		return fmt.Errorf("enroll: validate credential private key: %w", err)
	}
	certificateAuthority, err := parseExactCertificate(bundle.CertificateAuthorityDER)
	if err != nil {
		return fmt.Errorf("enroll: parse stored certificate authority: %w", err)
	}
	if !certificateAuthority.IsCA || !certificateAuthority.BasicConstraintsValid || certificateAuthority.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("enroll: stored certificate authority has an invalid profile")
	}
	if err := sign.ValidateSigningKey(certificateAuthority.PublicKey); err != nil {
		return fmt.Errorf("enroll: validate stored certificate authority key: %w", err)
	}
	if err := validateGatewayTrustAnchor(bundle.GatewayCertificateAuthorityDER, bundle.CertificateAuthorityDER, time.Time{}, false); err != nil {
		return err
	}
	certificate, err := parseExactCertificate(bundle.CertificateDER)
	if err != nil {
		return fmt.Errorf("enroll: parse stored certificate: %w", err)
	}
	if !publicKeysEqual(certificate.PublicKey, bundle.PrivateKey.Public()) {
		return errors.New("enroll: stored certificate public key mismatch")
	}
	class, deviceID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil {
		return fmt.Errorf("enroll: parse stored certificate identity: %w", err)
	}
	if class != identity.AgentClass || deviceID != bundle.DeviceID {
		return errors.New("enroll: stored certificate identity mismatch")
	}
	if certificate.IsCA || !certificate.BasicConstraintsValid || certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 ||
		len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		certificate.NotAfter.Sub(certificate.NotBefore) != agentCertificateLifetime {
		return errors.New("enroll: stored certificate has an invalid agent profile")
	}
	if err := certificate.CheckSignatureFrom(certificateAuthority); err != nil {
		return fmt.Errorf("enroll: verify stored certificate authority: %w", err)
	}
	if err := seal.ValidateX25519PublicKey(bundle.SealingPrivateKey.PublicKey().Bytes()); err != nil {
		return fmt.Errorf("enroll: validate stored sealing private key: %w", err)
	}
	return nil
}

func validateGatewayTrustAnchor(gatewayDER, agentDER []byte, now time.Time, requireCurrent bool) error {
	gatewayCA, err := parseExactCertificate(gatewayDER)
	if err != nil {
		return fmt.Errorf("enroll: parse gateway certificate authority: %w", err)
	}
	if !gatewayCA.IsCA || !gatewayCA.BasicConstraintsValid || gatewayCA.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("enroll: gateway certificate authority has an invalid profile")
	}
	if err := sign.ValidateSigningKey(gatewayCA.PublicKey); err != nil {
		return fmt.Errorf("enroll: validate gateway certificate authority key: %w", err)
	}
	if requireCurrent && (now.Before(gatewayCA.NotBefore) || now.After(gatewayCA.NotAfter)) {
		return errors.New("enroll: gateway certificate authority is not currently valid")
	}
	agentCA, err := parseExactCertificate(agentDER)
	if err != nil {
		return fmt.Errorf("enroll: parse agent certificate authority for gateway separation: %w", err)
	}
	if bytes.Equal(gatewayCA.Raw, agentCA.Raw) || publicKeysEqual(gatewayCA.PublicKey, agentCA.PublicKey) {
		return errors.New("enroll: agent and gateway certificate authorities are not distinct")
	}
	return nil
}
