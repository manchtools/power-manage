package enroll

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/manchtools/power-manage/contract/identity"
)

func TestAgentCredentialStore_PreservesDistinctGatewayTrustAnchor(t *testing.T) {
	bundle := newStoredCredentialBundleFixture(t)
	encoded, err := encodeCredentialBundle(bundle)
	if err != nil {
		t.Fatalf("encode credential bundle: %v", err)
	}
	store, err := newFileCredentialStore("/var/lib/power-manage/identity.pem", func(string, []byte, os.FileMode) error { return nil })
	if err != nil {
		t.Fatalf("newFileCredentialStore: %v", err)
	}
	store.read = func(path string, maxBytes int64, mode os.FileMode) ([]byte, error) {
		if path != "/var/lib/power-manage/identity.pem" || maxBytes != maxCredentialBundleBytes || mode != 0o600 {
			t.Fatalf("credential read = (%q, %d, %04o); want production bounded root-only read", path, maxBytes, mode)
		}
		return bytes.Clone(encoded), nil
	}
	store.now = func() time.Time { return bundleCertificate(t, bundle).NotAfter.Add(time.Hour) }

	loaded, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.DeviceID != bundle.DeviceID || !bytes.Equal(loaded.CertificateDER, bundle.CertificateDER) ||
		!bytes.Equal(loaded.CertificateAuthorityDER, bundle.CertificateAuthorityDER) ||
		!bytes.Equal(loaded.GatewayCertificateAuthorityDER, bundle.GatewayCertificateAuthorityDER) ||
		!publicKeysMatch(t, loaded.PrivateKey.Public(), bundle.PrivateKey.Public()) ||
		!bytes.Equal(loaded.SealingPrivateKey.Bytes(), bundle.SealingPrivateKey.Bytes()) {
		t.Fatal("loaded credential bundle differs from exact stored identity")
	}
}

func TestFileCredentialStore_LoadRejectsNonCanonicalOrInvalidPEM(t *testing.T) {
	bundle := newStoredCredentialBundleFixture(t)
	encoded, err := encodeCredentialBundle(bundle)
	if err != nil {
		t.Fatalf("encode credential bundle: %v", err)
	}
	blocks := decodeCredentialPEM(t, encoded)
	otherEncoded, err := encodeCredentialBundle(newStoredCredentialBundleFixture(t))
	if err != nil {
		t.Fatalf("encode alternate credential bundle: %v", err)
	}
	otherBlocks := decodeCredentialPEM(t, otherEncoded)
	encodeBlocks := func(items ...*pem.Block) []byte {
		var result []byte
		for _, block := range items {
			result = append(result, pem.EncodeToMemory(block)...)
		}
		return result
	}
	withContinuity := func(payload string) []byte {
		return append(bytes.Clone(encoded), pem.EncodeToMemory(&pem.Block{
			Type: continuityPEMType, Bytes: []byte(payload),
		})...)
	}
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "missing block", data: encodeBlocks(blocks[:4]...), want: "exact ordered POWER MANAGE SEALING PRIVATE KEY"},
		{name: "duplicate block", data: encodeBlocks(blocks[0], blocks[1], blocks[2], blocks[3], blocks[3], blocks[4]), want: "exact ordered POWER MANAGE SEALING PRIVATE KEY"},
		{name: "unknown block", data: encodeBlocks(blocks[0], blocks[1], &pem.Block{Type: "UNKNOWN", Bytes: []byte{1}}, blocks[3], blocks[4]), want: "exact ordered POWER MANAGE AGENT CA CERTIFICATE"},
		{name: "trailing bytes", data: append(bytes.Clone(encoded), []byte("trailing")...), want: "duplicate, unknown, or trailing data"},
		{name: "leading bytes", data: append([]byte("leading\n"), encoded...), want: "exact ordered POWER MANAGE AGENT CERTIFICATE"},
		{name: "PEM headers", data: encodeBlocks(blocks[0], &pem.Block{Type: blocks[1].Type, Headers: map[string]string{"X": "Y"}, Bytes: blocks[1].Bytes}, blocks[2], blocks[3], blocks[4]), want: "invalid POWER MANAGE AGENT PRIVATE KEY"},
		{name: "malformed signing key", data: encodeBlocks(blocks[0], &pem.Block{Type: blocks[1].Type, Bytes: []byte("bad")}, blocks[2], blocks[3], blocks[4]), want: "parse stored mTLS private key"},
		{name: "malformed certificate", data: encodeBlocks(&pem.Block{Type: blocks[0].Type, Bytes: []byte("bad")}, blocks[1], blocks[2], blocks[3], blocks[4]), want: "parse stored agent certificate"},
		{name: "certificate and signing key mismatch", data: encodeBlocks(blocks[0], otherBlocks[1], blocks[2], blocks[3], blocks[4]), want: "stored certificate public key mismatch"},
		{name: "certificate and CA mismatch", data: encodeBlocks(blocks[0], blocks[1], otherBlocks[2], blocks[3], blocks[4]), want: "verify stored certificate authority"},
		{name: "malformed gateway CA", data: encodeBlocks(blocks[0], blocks[1], blocks[2], &pem.Block{Type: blocks[3].Type, Bytes: []byte("bad")}, blocks[4]), want: "parse stored gateway CA certificate"},
		{name: "wrong sealing key type", data: encodeBlocks(blocks[0], blocks[1], blocks[2], blocks[3], &pem.Block{Type: blocks[4].Type, Bytes: blocks[1].Bytes}), want: "stored sealing private key is not X25519"},
		{name: "null continuity", data: withContinuity(`null`), want: "stored CA continuity requires non-null agent and gateway trust bundles"},
		{name: "missing continuity fields", data: withContinuity(`{}`), want: "stored CA continuity requires non-null agent and gateway trust bundles"},
		{name: "missing agent trust bundle", data: withContinuity(`{"gateway_trust_bundle":{}}`), want: "stored CA continuity requires non-null agent and gateway trust bundles"},
		{name: "missing gateway trust bundle", data: withContinuity(`{"agent_trust_bundle":{}}`), want: "stored CA continuity requires non-null agent and gateway trust bundles"},
		{name: "null agent trust bundle", data: withContinuity(`{"agent_trust_bundle":null,"gateway_trust_bundle":{}}`), want: "stored CA continuity requires non-null agent and gateway trust bundles"},
		{name: "null gateway trust bundle", data: withContinuity(`{"agent_trust_bundle":{},"gateway_trust_bundle":null}`), want: "stored CA continuity requires non-null agent and gateway trust bundles"},
		{name: "empty continuity state", data: withContinuity(`{"agent_trust_bundle":{},"gateway_trust_bundle":{}}`), want: "stored CA continuity cannot encode legacy-empty trust state"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, err := newFileCredentialStore("/var/lib/power-manage/identity.pem", func(string, []byte, os.FileMode) error { return nil })
			if err != nil {
				t.Fatalf("newFileCredentialStore: %v", err)
			}
			store.read = func(string, int64, os.FileMode) ([]byte, error) { return bytes.Clone(test.data), nil }
			if _, err := store.Load(context.Background()); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load error = %v; want category %q", err, test.want)
			}
		})
	}
}

func TestFileCredentialStore_ReplaceValidatesBeforeAtomicMode0600Write(t *testing.T) {
	bundle := newStoredCredentialBundleFixture(t)
	var writes int
	store, err := newFileCredentialStore("/var/lib/power-manage/identity.pem", func(string, []byte, os.FileMode) error { return nil })
	if err != nil {
		t.Fatalf("newFileCredentialStore: %v", err)
	}
	store.replace = func(path string, data []byte, mode os.FileMode) error {
		writes++
		if path != "/var/lib/power-manage/identity.pem" || mode != 0o600 || len(data) == 0 {
			t.Fatalf("credential replace = (%q, %d bytes, %04o); want atomic production write", path, len(data), mode)
		}
		return nil
	}
	if err := store.Replace(context.Background(), bundle); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	invalid := bundle
	invalid.PrivateKey = nil
	if err := store.Replace(context.Background(), invalid); err == nil || !strings.Contains(err.Error(), "credential bundle has a nil private key") {
		t.Fatalf("Replace error = %v; want nil-private-key rejection", err)
	}
	if writes != 1 {
		t.Fatalf("atomic writes = %d; want only the valid replacement", writes)
	}

	boom := errors.New("write failed")
	store.replace = func(string, []byte, os.FileMode) error { return boom }
	if err := store.Replace(context.Background(), bundle); !errors.Is(err, boom) {
		t.Fatalf("Replace error = %v; want atomic writer failure", err)
	}
}

func newStoredCredentialBundleFixture(t *testing.T) CredentialBundle {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate credential signing key: %v", err)
	}
	sealingPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate credential sealing key: %v", err)
	}
	ca, caSigner := newClientTestCA(t)
	gatewayCA, _ := newClientTestCA(t)
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(-time.Hour).Add(agentCertificateLifetime),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if err := identity.StampCertificateIdentity(template, identity.AgentClass, enrolledClientDeviceID); err != nil {
		t.Fatalf("stamp stored credential identity: %v", err)
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, ca, privateKey.Public(), caSigner)
	if err != nil {
		t.Fatalf("create stored credential certificate: %v", err)
	}
	return CredentialBundle{
		DeviceID:                       enrolledClientDeviceID,
		CertificateDER:                 certificateDER,
		CertificateAuthorityDER:        bytes.Clone(ca.Raw),
		GatewayCertificateAuthorityDER: bytes.Clone(gatewayCA.Raw),
		PrivateKey:                     privateKey,
		SealingPrivateKey:              sealingPrivateKey,
	}
}

func bundleCertificate(t *testing.T, bundle CredentialBundle) *x509.Certificate {
	t.Helper()
	certificate, err := x509.ParseCertificate(bundle.CertificateDER)
	if err != nil {
		t.Fatalf("parse bundle certificate: %v", err)
	}
	return certificate
}
