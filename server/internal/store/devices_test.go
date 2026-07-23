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

func TestDeviceProjection_RenewsAndRebuildsExactState(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production event store: %v", err)
	}
	key := newDeviceSigningKeyFixture(t)
	currentDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, testEnrolledDeviceID, key, 7)
	renewedDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, testEnrolledDeviceID, key, 8)
	firstSealingKey := bytes.Repeat([]byte{0x42}, 32)
	renewedSealingKey := bytes.Repeat([]byte{0x43}, 32)
	enrollment, err := AgentEnrolledEvent(testEnrolledDeviceID, currentDER, firstSealingKey, testEnrollmentTokenID, "owner@example.com")
	if err != nil {
		t.Fatalf("create enrollment event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(context.Background(), enrollment, 0); err != nil {
		t.Fatalf("append enrollment event: %v", err)
	}

	err = eventStore.WithDeviceLifecycleLock(context.Background(), testEnrolledDeviceID, func(lifecycle *DeviceLifecycle) error {
		current, err := lifecycle.Device(context.Background())
		if err != nil {
			return err
		}
		renewal, err := AgentCertificateRenewedEvent(testEnrolledDeviceID, renewedDER, renewedSealingKey, current.CertificateDER)
		if err != nil {
			return err
		}
		return lifecycle.AppendEvent(context.Background(), renewal, current.ProjectionVersion)
	})
	if err != nil {
		t.Fatalf("append locked renewal: %v", err)
	}

	assertRenewedDeviceProjection(t, eventStore, renewedDER, currentDER, renewedSealingKey)
	currentFingerprint := sha256.Sum256(currentDER)
	if _, err := pool.Exec(context.Background(), `
		UPDATE devices
		SET projection_version = 9,
		    certificate_der = $1,
		    certificate_fingerprint = $2,
		    sealing_public_key = $3,
		    previous_certificate_der = $4,
		    registration_token_id = '01ARZ3NDEKTSV4RRFFQ69G5FAX',
		    owner = 'corrupt'
		WHERE device_id = $5`, currentDER, currentFingerprint[:], firstSealingKey, renewedDER, testEnrolledDeviceID); err != nil {
		t.Fatalf("corrupt renewed projection fixture: %v", err)
	}
	if err := eventStore.RebuildAll(context.Background(), DeviceRebuildTarget); err != nil {
		t.Fatalf("rebuild renewed device projection: %v", err)
	}
	assertRenewedDeviceProjection(t, eventStore, renewedDER, currentDER, renewedSealingKey)
}

func TestAgentCertificateRenewedEvent_RejectsInvalidTransitionMaterial(t *testing.T) {
	key := newDeviceSigningKeyFixture(t)
	currentDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, testEnrolledDeviceID, key, 7)
	renewedDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, testEnrolledDeviceID, key, 8)
	differentKeyDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, testEnrolledDeviceID, newDeviceSigningKeyFixture(t), 9)
	differentIdentityDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, "01ARZ3NDEKTSV4RRFFQ69G5FAX", key, 10)
	gatewayDER := newDeviceCertificateWithKeyFixture(t, identity.GatewayClass, testEnrolledDeviceID, key, 11)
	tests := []struct {
		name       string
		deviceID   string
		renewed    []byte
		sealingKey []byte
		superseded []byte
		want       string
	}{
		{name: "same certificate", deviceID: testEnrolledDeviceID, renewed: currentDER, sealingKey: bytes.Repeat([]byte{1}, 32), superseded: currentDER, want: "renewed certificate equals"},
		{name: "different signing key", deviceID: testEnrolledDeviceID, renewed: differentKeyDER, sealingKey: bytes.Repeat([]byte{1}, 32), superseded: currentDER, want: "public key differs"},
		{name: "different identity", deviceID: testEnrolledDeviceID, renewed: differentIdentityDER, sealingKey: bytes.Repeat([]byte{1}, 32), superseded: currentDER, want: "identity is mismatched"},
		{name: "gateway class", deviceID: testEnrolledDeviceID, renewed: gatewayDER, sealingKey: bytes.Repeat([]byte{1}, 32), superseded: currentDER, want: `class "gateway" is not agent`},
		{name: "low-order sealing key", deviceID: testEnrolledDeviceID, renewed: renewedDER, sealingKey: make([]byte, 32), superseded: currentDER, want: "low-order"},
		{name: "malformed superseded certificate", deviceID: testEnrolledDeviceID, renewed: renewedDER, sealingKey: bytes.Repeat([]byte{1}, 32), superseded: []byte("bad"), want: "invalid superseded certificate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := AgentCertificateRenewedEvent(test.deviceID, test.renewed, test.sealingKey, test.superseded); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("AgentCertificateRenewedEvent error = %v; want category %q", err, test.want)
			}
		})
	}
}

func TestDeviceProjection_RejectsWrongRenewalPredecessorWithoutPersistingEvent(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production event store: %v", err)
	}
	key := newDeviceSigningKeyFixture(t)
	currentDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, testEnrolledDeviceID, key, 7)
	renewedDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, testEnrolledDeviceID, key, 8)
	wrongPredecessorDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, testEnrolledDeviceID, key, 6)
	sealingKey := bytes.Repeat([]byte{0x42}, 32)
	enrollment, err := AgentEnrolledEvent(testEnrolledDeviceID, currentDER, sealingKey, testEnrollmentTokenID, "owner@example.com")
	if err != nil {
		t.Fatalf("create enrollment event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(context.Background(), enrollment, 0); err != nil {
		t.Fatalf("append enrollment event: %v", err)
	}
	renewal, err := AgentCertificateRenewedEvent(testEnrolledDeviceID, renewedDER, bytes.Repeat([]byte{0x43}, 32), wrongPredecessorDER)
	if err != nil {
		t.Fatalf("create wrong-predecessor renewal event: %v", err)
	}
	err = eventStore.WithDeviceLifecycleLock(context.Background(), testEnrolledDeviceID, func(lifecycle *DeviceLifecycle) error {
		return lifecycle.AppendEvent(context.Background(), renewal, 1)
	})
	if err == nil || !strings.Contains(err.Error(), "conflicts with the current device projection") {
		t.Fatalf("wrong-predecessor renewal error = %v; want projection conflict", err)
	}
	var events int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM events WHERE stream_type = 'device' AND stream_id = $1`, testEnrolledDeviceID).Scan(&events); err != nil {
		t.Fatalf("count device events: %v", err)
	}
	device, err := eventStore.Device(context.Background(), testEnrolledDeviceID)
	if err != nil {
		t.Fatalf("read preserved device projection: %v", err)
	}
	wantFingerprint := sha256.Sum256(currentDER)
	if events != 1 || device.ProjectionVersion != 1 || device.CertificateFingerprint != wantFingerprint || !bytes.Equal(device.CertificateDER, currentDER) {
		t.Fatalf("wrong-predecessor state = events %d, device %+v; want exact enrollment", events, device)
	}
}

func TestDeviceLifecycleLock_SerializesSameDeviceOnly(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production event store: %v", err)
	}
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- eventStore.WithDeviceLifecycleLock(context.Background(), testEnrolledDeviceID, func(*DeviceLifecycle) error {
			close(firstEntered)
			<-releaseFirst
			return nil
		})
	}()
	<-firstEntered

	sameEntered := make(chan struct{})
	sameDone := make(chan error, 1)
	go func() {
		sameDone <- eventStore.WithDeviceLifecycleLock(context.Background(), testEnrolledDeviceID, func(*DeviceLifecycle) error {
			close(sameEntered)
			return nil
		})
	}()
	differentID := "01ARZ3NDEKTSV4RRFFQ69G5FAX"
	differentEntered := make(chan struct{})
	differentDone := make(chan error, 1)
	go func() {
		differentDone <- eventStore.WithDeviceLifecycleLock(context.Background(), differentID, func(*DeviceLifecycle) error {
			close(differentEntered)
			return nil
		})
	}()

	select {
	case <-sameEntered:
		t.Fatal("same-device lifecycle callback entered while lock was held")
	case <-differentEntered:
		// Different identities must not share a lifecycle lock.
	case <-time.After(5 * time.Second):
		t.Fatal("different-device lifecycle callback remained blocked")
	}
	if err := <-differentDone; err != nil {
		t.Fatalf("different-device lifecycle lock: %v", err)
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("first lifecycle lock: %v", err)
	}
	select {
	case <-sameEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("same-device lifecycle callback did not enter after release")
	}
	if err := <-sameDone; err != nil {
		t.Fatalf("same-device lifecycle lock: %v", err)
	}
}

func assertRenewedDeviceProjection(t *testing.T, eventStore *Store, certificateDER, previousCertificateDER, sealingKey []byte) {
	t.Helper()
	device, err := eventStore.Device(context.Background(), testEnrolledDeviceID)
	if err != nil {
		t.Fatalf("read renewed device: %v", err)
	}
	wantFingerprint := sha256.Sum256(certificateDER)
	if device.ProjectionVersion != 2 || device.CertificateFingerprint != wantFingerprint ||
		!bytes.Equal(device.CertificateDER, certificateDER) ||
		!bytes.Equal(device.PreviousCertificateDER, previousCertificateDER) ||
		!bytes.Equal(device.SealingPublicKey, sealingKey) ||
		device.RegistrationTokenID != testEnrollmentTokenID || device.Owner != "owner@example.com" {
		t.Fatalf("renewed device projection = %+v; want exact version-two state", device)
	}
}

func newDeviceCertificateFixture(t *testing.T, class identity.Class, deviceID string) []byte {
	t.Helper()
	return newDeviceCertificateWithKeyFixture(t, class, deviceID, newDeviceSigningKeyFixture(t), 7)
}

func newDeviceSigningKeyFixture(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate device certificate key: %v", err)
	}
	return key
}

func newDeviceCertificateWithKeyFixture(t *testing.T, class identity.Class, deviceID string, key *ecdsa.PrivateKey, serial int64) []byte {
	t.Helper()
	publicDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("marshal device fixture public key: %v", err)
	}
	keyID := sha256.Sum256(publicDER)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		NotBefore:             time.Date(2026, time.July, 22, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2027, time.July, 22, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SubjectKeyId:          bytes.Clone(keyID[:20]),
		AuthorityKeyId:        bytes.Clone(keyID[:20]),
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
