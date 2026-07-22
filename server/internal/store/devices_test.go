package store

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/manchtools/power-manage/contract/identity"
)

const (
	testEnrolledDeviceID  = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	testEnrollmentTokenID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
)

// TestDeviceProjection_RebuildsEnrollmentState pins the sole durable binding
// among issued certificate DER, its derived fingerprint, and the registered
// X25519 public key.
func TestDeviceProjection_RebuildsEnrollmentState(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production event store: %v", err)
	}
	certificateDER := newDeviceCertificateFixture(t, identity.AgentClass, testEnrolledDeviceID)
	sealingKey := bytes.Repeat([]byte{0x42}, 32)
	event, err := AgentEnrolledEvent(
		testEnrolledDeviceID,
		certificateDER,
		sealingKey,
		testEnrollmentTokenID,
		"owner@example.com",
	)
	if err != nil {
		t.Fatalf("create agent enrollment event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(context.Background(), event, 0); err != nil {
		t.Fatalf("append agent enrollment event: %v", err)
	}

	got, err := eventStore.Device(context.Background(), testEnrolledDeviceID)
	if err != nil {
		t.Fatalf("read device projection: %v", err)
	}
	wantFingerprint := sha256.Sum256(certificateDER)
	if !bytes.Equal(got.CertificateDER, certificateDER) || got.CertificateFingerprint != wantFingerprint {
		t.Fatalf("device certificate binding = (%x, %x); want exact DER and SHA-256 %x", got.CertificateDER, got.CertificateFingerprint, wantFingerprint)
	}
	if !bytes.Equal(got.SealingPublicKey, sealingKey) || got.RegistrationTokenID != testEnrollmentTokenID || got.Owner != "owner@example.com" || got.ProjectionVersion != 1 {
		t.Fatalf("device projection = %+v; want complete enrollment state", got)
	}

	if _, err := pool.Exec(context.Background(), `
		UPDATE devices
		SET projection_version = 9,
		    certificate_der = $2,
		    certificate_fingerprint = $3,
		    sealing_public_key = $4,
		    registration_token_id = '01ARZ3NDEKTSV4RRFFQ69G5FAX',
		    owner = 'corrupt'
		WHERE device_id = $1`,
		testEnrolledDeviceID,
		newDeviceCertificateFixture(t, identity.AgentClass, "01ARZ3NDEKTSV4RRFFQ69G5FAX"),
		bytes.Repeat([]byte{0x11}, 32),
		bytes.Repeat([]byte{0x24}, 32),
	); err != nil {
		t.Fatalf("corrupt device projection fixture: %v", err)
	}
	if err := eventStore.RebuildAll(context.Background(), DeviceRebuildTarget); err != nil {
		t.Fatalf("rebuild device projection: %v", err)
	}
	rebuilt, err := eventStore.Device(context.Background(), testEnrolledDeviceID)
	if err != nil {
		t.Fatalf("read rebuilt device projection: %v", err)
	}
	if !bytes.Equal(rebuilt.CertificateDER, certificateDER) || rebuilt.CertificateFingerprint != wantFingerprint ||
		!bytes.Equal(rebuilt.SealingPublicKey, sealingKey) || rebuilt.RegistrationTokenID != testEnrollmentTokenID ||
		rebuilt.Owner != "owner@example.com" || rebuilt.ProjectionVersion != 1 {
		t.Fatalf("rebuilt device projection = %+v; want event-derived enrollment state", rebuilt)
	}
}

// TestDeviceProjection_RejectsInvalidEnrollmentEvents proves corrupt trust
// material cannot partially persist as either an event or projection row.
func TestDeviceProjection_RejectsInvalidEnrollmentEvents(t *testing.T) {
	validCertificate := newDeviceCertificateFixture(t, identity.AgentClass, testEnrolledDeviceID)
	wrongClass := newDeviceCertificateFixture(t, identity.GatewayClass, testEnrolledDeviceID)
	tests := []struct {
		name        string
		deviceID    string
		certificate []byte
		sealingKey  []byte
		tokenID     string
		owner       string
		want        string
	}{
		{name: "invalid device ID", deviceID: "not-ulid", certificate: validCertificate, sealingKey: bytes.Repeat([]byte{1}, 32), tokenID: testEnrollmentTokenID, want: "store: invalid device ID"},
		{name: "malformed certificate", deviceID: testEnrolledDeviceID, certificate: []byte("bad"), sealingKey: bytes.Repeat([]byte{1}, 32), tokenID: testEnrollmentTokenID, want: "store: parse certificate DER"},
		{name: "trailing certificate data", deviceID: testEnrolledDeviceID, certificate: append(append([]byte(nil), validCertificate...), 0), sealingKey: bytes.Repeat([]byte{1}, 32), tokenID: testEnrollmentTokenID, want: "store: parse certificate DER"},
		{name: "wrong certificate class", deviceID: testEnrolledDeviceID, certificate: wrongClass, sealingKey: bytes.Repeat([]byte{1}, 32), tokenID: testEnrollmentTokenID, want: `store: certificate class "gateway" is not agent`},
		{name: "certificate identity mismatch", deviceID: "01ARZ3NDEKTSV4RRFFQ69G5FAX", certificate: validCertificate, sealingKey: bytes.Repeat([]byte{1}, 32), tokenID: testEnrollmentTokenID, want: "store: certificate identity is mismatched with device ID"},
		{name: "short sealing key", deviceID: testEnrolledDeviceID, certificate: validCertificate, sealingKey: bytes.Repeat([]byte{1}, 31), tokenID: testEnrollmentTokenID, want: "seal: invalid X25519 public key"},
		{name: "zero sealing key", deviceID: testEnrolledDeviceID, certificate: validCertificate, sealingKey: make([]byte, 32), tokenID: testEnrollmentTokenID, want: "seal: X25519 public key is low-order"},
		{name: "invalid token ID", deviceID: testEnrolledDeviceID, certificate: validCertificate, sealingKey: bytes.Repeat([]byte{1}, 32), tokenID: "bad", want: "store: invalid registration token ID"},
		{name: "oversized owner", deviceID: testEnrolledDeviceID, certificate: validCertificate, sealingKey: bytes.Repeat([]byte{1}, 32), tokenID: testEnrollmentTokenID, owner: strings.Repeat("x", 257), want: "store: invalid device owner"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pool := testPostgres(t)
			eventStore, err := NewProduction(pool)
			if err != nil {
				t.Fatalf("create production event store: %v", err)
			}
			event, err := AgentEnrolledEvent(test.deviceID, test.certificate, test.sealingKey, test.tokenID, test.owner)
			if err == nil {
				err = eventStore.AppendEventWithVersion(context.Background(), event, 0)
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid enrollment error = %v; want category %q", err, test.want)
			}
			var eventCount, deviceCount int
			if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM events`).Scan(&eventCount); err != nil {
				t.Fatalf("count events: %v", err)
			}
			if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM devices`).Scan(&deviceCount); err != nil {
				t.Fatalf("count devices: %v", err)
			}
			if eventCount != 0 || deviceCount != 0 {
				t.Fatalf("invalid enrollment persisted events=%d devices=%d; want zero", eventCount, deviceCount)
			}
		})
	}
}

func newDeviceCertificateFixture(t *testing.T, class identity.Class, deviceID string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device certificate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		NotBefore:             time.Date(2026, time.July, 22, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, time.July, 22, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if err := identity.StampCertificateIdentity(template, class, deviceID); err != nil {
		t.Fatalf("stamp device certificate identity: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create device certificate: %v", err)
	}
	return der
}
