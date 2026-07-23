package enroll

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/sdk/fsafe"
)

const DefaultCredentialPath = "/var/lib/power-manage/identity.pem"

const maxCredentialBundleBytes int64 = 256 * 1024

const continuityPEMType = "POWER MANAGE CA CONTINUITY"

var credentialPEMTypes = [...]string{
	"POWER MANAGE AGENT CERTIFICATE",
	"POWER MANAGE AGENT PRIVATE KEY",
	"POWER MANAGE AGENT CA CERTIFICATE",
	"POWER MANAGE GATEWAY CA CERTIFICATE",
	"POWER MANAGE SEALING PRIVATE KEY",
}

type storedCredentialContinuity struct {
	AgentTrustBundle                *StoredTrustBundle        `json:"agent_trust_bundle"`
	GatewayTrustBundle              *StoredTrustBundle        `json:"gateway_trust_bundle"`
	PendingAgentTrustConfirmation   *PendingTrustConfirmation `json:"pending_agent_trust_confirmation,omitempty"`
	PendingGatewayTrustConfirmation *PendingTrustConfirmation `json:"pending_gateway_trust_confirmation,omitempty"`
}

type createCredentialFile func(string, []byte, os.FileMode) error
type readCredentialFile func(string, int64, os.FileMode) ([]byte, error)
type replaceCredentialFile func(string, []byte, os.FileMode) error

// FileCredentialStore owns one atomic, root-only PEM credential bundle.
type FileCredentialStore struct {
	path    string
	create  createCredentialFile
	read    readCredentialFile
	replace replaceCredentialFile
	now     func() time.Time
}

// NewFileCredentialStore builds the production credential-custody boundary.
func NewFileCredentialStore(path string) (*FileCredentialStore, error) {
	return newFileCredentialStore(path, fsafe.WriteFileNew)
}

func newFileCredentialStore(path string, create createCredentialFile) (*FileCredentialStore, error) {
	if path == "" || !filepath.IsAbs(path) {
		return nil, errors.New("enroll: credential path must be absolute")
	}
	if create == nil {
		return nil, errors.New("enroll: nil credential file creator")
	}
	return &FileCredentialStore{
		path: filepath.Clean(path), create: create,
		read: fsafe.ReadRootFile, replace: fsafe.WriteFileAtomic, now: time.Now,
	}, nil
}

// Create validates and atomically publishes the first credential bundle.
func (s *FileCredentialStore) Create(ctx context.Context, bundle CredentialBundle) error {
	if s == nil || s.path == "" || s.create == nil || s.now == nil {
		return errors.New("enroll: credential store is not wired")
	}
	if ctx == nil {
		return errors.New("enroll: nil credential-store context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCredentialBundle(bundle, s.now()); err != nil {
		return fmt.Errorf("enroll: validate credential bundle: %w", err)
	}
	encoded, err := encodeCredentialBundle(bundle)
	if err != nil {
		return err
	}
	if err := s.create(s.path, encoded, 0o600); err != nil {
		return fmt.Errorf("enroll: create credential bundle: %w", err)
	}
	return nil
}

// Load reads one exact, bounded, root-only credential bundle. Expired agent
// certificates remain loadable so an overdue agent can renew immediately.
func (s *FileCredentialStore) Load(ctx context.Context) (CredentialBundle, error) {
	if s == nil || s.path == "" || s.read == nil || s.now == nil {
		return CredentialBundle{}, errors.New("enroll: credential store is not wired for loading")
	}
	if ctx == nil {
		return CredentialBundle{}, errors.New("enroll: nil credential-store context")
	}
	if err := ctx.Err(); err != nil {
		return CredentialBundle{}, err
	}
	encoded, err := s.read(s.path, maxCredentialBundleBytes, 0o600)
	if err != nil {
		return CredentialBundle{}, fmt.Errorf("enroll: read credential bundle: %w", err)
	}
	bundle, err := decodeStoredCredentialBundle(encoded)
	if err != nil {
		return CredentialBundle{}, err
	}
	if err := validateStoredCredentialBundle(bundle, s.now()); err != nil {
		return CredentialBundle{}, fmt.Errorf("enroll: validate stored credential bundle: %w", err)
	}
	return bundle, nil
}

// Replace validates and atomically publishes one renewed credential bundle.
func (s *FileCredentialStore) Replace(ctx context.Context, bundle CredentialBundle) error {
	if s == nil || s.path == "" || s.replace == nil || s.now == nil {
		return errors.New("enroll: credential store is not wired for replacement")
	}
	if ctx == nil {
		return errors.New("enroll: nil credential-store context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateCredentialBundle(bundle, s.now()); err != nil {
		return fmt.Errorf("enroll: validate renewed credential bundle: %w", err)
	}
	encoded, err := encodeCredentialBundle(bundle)
	if err != nil {
		return err
	}
	if err := s.replace(s.path, encoded, 0o600); err != nil {
		return fmt.Errorf("enroll: replace credential bundle: %w", err)
	}
	return nil
}

func decodeStoredCredentialBundle(encoded []byte) (CredentialBundle, error) {
	remaining := bytes.Clone(encoded)
	blocks := make([]*pem.Block, 0, len(credentialPEMTypes))
	for _, expectedType := range credentialPEMTypes {
		prefix := []byte("-----BEGIN " + expectedType + "-----\n")
		if !bytes.HasPrefix(remaining, prefix) {
			return CredentialBundle{}, fmt.Errorf("enroll: credential bundle must contain exact ordered %s block", expectedType)
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != expectedType || len(block.Headers) != 0 || len(block.Bytes) == 0 {
			return CredentialBundle{}, fmt.Errorf("enroll: credential bundle has an invalid %s block", expectedType)
		}
		blocks = append(blocks, block)
		remaining = rest
	}
	var continuity storedCredentialContinuity
	var agentTrustBundle, gatewayTrustBundle StoredTrustBundle
	if len(remaining) != 0 {
		prefix := []byte("-----BEGIN " + continuityPEMType + "-----\n")
		if !bytes.HasPrefix(remaining, prefix) {
			return CredentialBundle{}, errors.New("enroll: credential bundle contains duplicate, unknown, or trailing data")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != continuityPEMType || len(block.Headers) != 0 || len(block.Bytes) == 0 || len(rest) != 0 {
			return CredentialBundle{}, errors.New("enroll: credential bundle has an invalid CA continuity block")
		}
		decoder := json.NewDecoder(bytes.NewReader(block.Bytes))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&continuity); err != nil {
			return CredentialBundle{}, fmt.Errorf("enroll: decode stored CA continuity: %w", err)
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			return CredentialBundle{}, errors.New("enroll: stored CA continuity contains trailing JSON data")
		}
		if continuity.AgentTrustBundle == nil || continuity.GatewayTrustBundle == nil {
			return CredentialBundle{}, errors.New("enroll: stored CA continuity requires non-null agent and gateway trust bundles")
		}
		agentTrustBundle = *continuity.AgentTrustBundle
		gatewayTrustBundle = *continuity.GatewayTrustBundle
		agentAbsent := agentTrustBundle.Generation == 0 && len(agentTrustBundle.RootCertificateDER) == 0
		gatewayAbsent := gatewayTrustBundle.Generation == 0 && len(gatewayTrustBundle.RootCertificateDER) == 0
		if agentAbsent && gatewayAbsent {
			return CredentialBundle{}, errors.New("enroll: stored CA continuity cannot encode legacy-empty trust state")
		}
	}
	certificate, err := parseExactCertificate(blocks[0].Bytes)
	if err != nil {
		return CredentialBundle{}, fmt.Errorf("enroll: parse stored agent certificate: %w", err)
	}
	class, deviceID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil || class != identity.AgentClass {
		return CredentialBundle{}, errors.New("enroll: stored agent certificate identity is invalid")
	}
	privateKeyValue, err := x509.ParsePKCS8PrivateKey(blocks[1].Bytes)
	if err != nil {
		return CredentialBundle{}, fmt.Errorf("enroll: parse stored mTLS private key: %w", err)
	}
	privateKey, ok := privateKeyValue.(crypto.Signer)
	if !ok || isNilEnrollmentDependency(privateKey) {
		return CredentialBundle{}, errors.New("enroll: stored mTLS private key is not a signer")
	}
	if !publicKeysEqual(certificate.PublicKey, privateKey.Public()) {
		return CredentialBundle{}, errors.New("enroll: stored certificate public key mismatch")
	}
	if _, err := parseExactCertificate(blocks[2].Bytes); err != nil {
		return CredentialBundle{}, fmt.Errorf("enroll: parse stored agent CA certificate: %w", err)
	}
	if _, err := parseExactCertificate(blocks[3].Bytes); err != nil {
		return CredentialBundle{}, fmt.Errorf("enroll: parse stored gateway CA certificate: %w", err)
	}
	sealingKeyValue, err := x509.ParsePKCS8PrivateKey(blocks[4].Bytes)
	if err != nil {
		return CredentialBundle{}, fmt.Errorf("enroll: parse stored sealing private key: %w", err)
	}
	sealingPrivateKey, ok := sealingKeyValue.(*ecdh.PrivateKey)
	if !ok || sealingPrivateKey == nil {
		return CredentialBundle{}, errors.New("enroll: stored sealing private key is not X25519")
	}
	return CredentialBundle{
		DeviceID:                        deviceID,
		CertificateDER:                  bytes.Clone(blocks[0].Bytes),
		PrivateKey:                      privateKey,
		CertificateAuthorityDER:         bytes.Clone(blocks[2].Bytes),
		GatewayCertificateAuthorityDER:  bytes.Clone(blocks[3].Bytes),
		SealingPrivateKey:               sealingPrivateKey,
		AgentTrustBundle:                agentTrustBundle,
		GatewayTrustBundle:              gatewayTrustBundle,
		PendingAgentTrustConfirmation:   continuity.PendingAgentTrustConfirmation,
		PendingGatewayTrustConfirmation: continuity.PendingGatewayTrustConfirmation,
	}, nil
}

func encodeCredentialBundle(bundle CredentialBundle) ([]byte, error) {
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(bundle.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("enroll: marshal mTLS private key: %w", err)
	}
	sealingPrivateKeyDER, err := x509.MarshalPKCS8PrivateKey(bundle.SealingPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("enroll: marshal sealing private key: %w", err)
	}
	blocks := []*pem.Block{
		{Type: credentialPEMTypes[0], Bytes: bundle.CertificateDER},
		{Type: credentialPEMTypes[1], Bytes: privateKeyDER},
		{Type: credentialPEMTypes[2], Bytes: bundle.CertificateAuthorityDER},
		{Type: credentialPEMTypes[3], Bytes: bundle.GatewayCertificateAuthorityDER},
		{Type: credentialPEMTypes[4], Bytes: sealingPrivateKeyDER},
	}
	if bundle.AgentTrustBundle.Generation != 0 || bundle.GatewayTrustBundle.Generation != 0 ||
		bundle.PendingAgentTrustConfirmation != nil || bundle.PendingGatewayTrustConfirmation != nil {
		continuityDER, err := json.Marshal(storedCredentialContinuity{
			AgentTrustBundle: &bundle.AgentTrustBundle, GatewayTrustBundle: &bundle.GatewayTrustBundle,
			PendingAgentTrustConfirmation:   bundle.PendingAgentTrustConfirmation,
			PendingGatewayTrustConfirmation: bundle.PendingGatewayTrustConfirmation,
		})
		if err != nil {
			return nil, fmt.Errorf("enroll: encode CA continuity: %w", err)
		}
		blocks = append(blocks, &pem.Block{Type: continuityPEMType, Bytes: continuityDER})
	}
	var encoded []byte
	for _, block := range blocks {
		encoded = append(encoded, pem.EncodeToMemory(block)...)
	}
	return encoded, nil
}
