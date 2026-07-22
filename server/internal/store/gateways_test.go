package store

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manchtools/power-manage/contract/identity"
)

const testEnrolledGatewayID = "01J00000000000000000000004"

func TestGatewayProjectors_RejectPartiallyMatchingCorruptIdempotencyState(t *testing.T) {
	t.Run("enrollment", func(t *testing.T) {
		pool := testPostgres(t)
		eventStore, err := NewProduction(pool)
		if err != nil {
			t.Fatalf("create production event store: %v", err)
		}
		key := newDeviceSigningKeyFixture(t)
		dnsNames := []string{"gateway.internal.example"}
		certificateDER := newGatewayCertificateFixture(t, key, testEnrolledGatewayID, dnsNames, 21)
		event, err := GatewayEnrolledEvent(testEnrolledGatewayID, certificateDER, testGatewayRegistrationTokenID, "owner@example.com", dnsNames)
		if err != nil {
			t.Fatalf("create gateway enrollment event: %v", err)
		}
		if err := eventStore.AppendEventWithVersion(context.Background(), event, 0); err != nil {
			t.Fatalf("append gateway enrollment event: %v", err)
		}
		corruptPrevious := newGatewayCertificateFixture(t, key, testEnrolledGatewayID, dnsNames, 20)
		if _, err := pool.Exec(context.Background(), `UPDATE gateways SET previous_certificate_der = $2 WHERE gateway_id = $1`, testEnrolledGatewayID, corruptPrevious); err != nil {
			t.Fatalf("corrupt gateway enrollment projection: %v", err)
		}

		projectErr := replayGatewayProjector(t, pool, event, 1, projectGatewayEnrollment)
		if projectErr == nil || !strings.Contains(projectErr.Error(), "conflicts with the current projection") || allCRLWorkCount(t, pool) != 0 {
			t.Fatalf("corrupt enrollment replay = %v with %d CRL work items; want conflict and no work", projectErr, allCRLWorkCount(t, pool))
		}
		assertGatewayProjectionBytes(t, pool, 1, certificateDER, corruptPrevious, sha256.Sum256(certificateDER))
	})

	t.Run("renewal", func(t *testing.T) {
		pool := testPostgres(t)
		eventStore, err := NewProduction(pool)
		if err != nil {
			t.Fatalf("create production event store: %v", err)
		}
		key := newDeviceSigningKeyFixture(t)
		dnsNames := []string{"gateway.internal.example"}
		firstDER := newGatewayCertificateFixture(t, key, testEnrolledGatewayID, dnsNames, 31)
		secondDER := newGatewayCertificateFixture(t, key, testEnrolledGatewayID, dnsNames, 32)
		appendGatewayEnrollmentEvent(t, eventStore, firstDER, dnsNames)
		event, err := GatewayCertificateRenewedEvent(testEnrolledGatewayID, secondDER, firstDER)
		if err != nil {
			t.Fatalf("create gateway renewal event: %v", err)
		}
		appendGatewayLifecycleEvent(t, eventStore, event, 1)
		clearGatewayCRLProjections(t, pool)
		corruptFingerprint := sha256.Sum256([]byte("constraint-valid renewal corruption"))
		if _, err := pool.Exec(context.Background(), `UPDATE gateways SET certificate_fingerprint = $2 WHERE gateway_id = $1`, testEnrolledGatewayID, corruptFingerprint[:]); err != nil {
			t.Fatalf("corrupt gateway renewal projection: %v", err)
		}

		projectErr := replayGatewayProjector(t, pool, event, 2, projectGatewayRenewal)
		if projectErr == nil || !strings.Contains(projectErr.Error(), "conflicts with the current projection") || allCRLWorkCount(t, pool) != 0 {
			t.Fatalf("corrupt renewal replay = %v with %d CRL work items; want conflict and no work", projectErr, allCRLWorkCount(t, pool))
		}
		assertGatewayProjectionBytes(t, pool, 2, secondDER, firstDER, corruptFingerprint)
	})

	t.Run("revocation", func(t *testing.T) {
		pool := testPostgres(t)
		eventStore, err := NewProduction(pool)
		if err != nil {
			t.Fatalf("create production event store: %v", err)
		}
		key := newDeviceSigningKeyFixture(t)
		dnsNames := []string{"gateway.internal.example"}
		certificateDER := newGatewayCertificateFixture(t, key, testEnrolledGatewayID, dnsNames, 41)
		appendGatewayEnrollmentEvent(t, eventStore, certificateDER, dnsNames)
		event, err := GatewayCertificateRevokedEvent(testEnrolledGatewayID, certificateDER)
		if err != nil {
			t.Fatalf("create gateway revocation event: %v", err)
		}
		appendGatewayLifecycleEvent(t, eventStore, event, 1)
		clearGatewayCRLProjections(t, pool)
		corruptFingerprint := sha256.Sum256([]byte("constraint-valid revocation corruption"))
		if _, err := pool.Exec(context.Background(), `UPDATE gateways SET certificate_fingerprint = $2 WHERE gateway_id = $1`, testEnrolledGatewayID, corruptFingerprint[:]); err != nil {
			t.Fatalf("corrupt gateway revocation projection: %v", err)
		}

		projectErr := replayGatewayProjector(t, pool, event, 2, projectGatewayRevocation)
		if projectErr == nil || !strings.Contains(projectErr.Error(), "conflicts with the current projection") || allCRLWorkCount(t, pool) != 0 {
			t.Fatalf("corrupt revocation replay = %v with %d CRL work items; want conflict and no work", projectErr, allCRLWorkCount(t, pool))
		}
		assertGatewayProjectionBytes(t, pool, 2, certificateDER, nil, corruptFingerprint)
	})
}

func TestGatewayEvents_RejectUnexpectedEKUAndNonDNSSANs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*x509.Certificate)
	}{
		{name: "unknown extended key usage", mutate: func(certificate *x509.Certificate) {
			certificate.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 55555, 1}}
		}},
		{name: "email SAN", mutate: func(certificate *x509.Certificate) {
			certificate.EmailAddresses = []string{"gateway@attacker.invalid"}
		}},
		{name: "IP SAN", mutate: func(certificate *x509.Certificate) {
			certificate.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dnsNames := []string{"gateway.internal.example"}
			certificateDER := newGatewayCertificateFixtureWithMutation(
				t,
				newDeviceSigningKeyFixture(t),
				testEnrolledGatewayID,
				dnsNames,
				51,
				test.mutate,
			)
			if _, err := GatewayEnrolledEvent(testEnrolledGatewayID, certificateDER, testGatewayRegistrationTokenID, "owner@example.com", dnsNames); err == nil || !strings.Contains(err.Error(), "profile") {
				t.Fatalf("GatewayEnrolledEvent error = %v; want gateway profile rejection", err)
			}
		})
	}
}

func TestGatewayEvents_RejectUnsupportedRawSANGeneralNames(t *testing.T) {
	for _, kind := range []string{"otherName", "directoryName", "registeredID"} {
		t.Run(kind, func(t *testing.T) {
			dnsNames := []string{"gateway.internal.example"}
			certificateDER := newGatewayCertificateFixtureWithMutation(
				t,
				newDeviceSigningKeyFixture(t),
				testEnrolledGatewayID,
				dnsNames,
				52,
				func(certificate *x509.Certificate) {
					certificate.ExtraExtensions = []pkix.Extension{unsupportedGatewaySANExtension(t, dnsNames[0], kind)}
				},
			)
			assertUnsupportedGatewaySANFixture(t, certificateDER, dnsNames[0], kind)
			_, err := GatewayEnrolledEvent(testEnrolledGatewayID, certificateDER, testGatewayRegistrationTokenID, "owner@example.com", dnsNames)
			want := "store: gateway certificate profile is invalid: identity: certificate subjectAltName contains an unsupported GeneralName"
			if err == nil || err.Error() != want {
				t.Fatalf("GatewayEnrolledEvent error = %v; want %q", err, want)
			}
		})
	}
}

func TestGatewayProjection_RebuildsExactLifecycleState(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production event store: %v", err)
	}

	agentDER := newDeviceCertificateFixture(t, identity.AgentClass, testEnrolledDeviceID)
	appendEnrollmentFixture(t, eventStore, agentDER)
	agentRevoke, err := AgentCertificateRevokedEvent(testEnrolledDeviceID, agentDER)
	if err != nil {
		t.Fatalf("create agent revocation fixture: %v", err)
	}
	appendLifecycleEventFixture(t, eventStore, agentRevoke, 1)

	gatewayKey := newDeviceSigningKeyFixture(t)
	dnsNames := []string{"gateway-1.internal.example", "gateway-1.backup.internal.example"}
	firstDER := newGatewayCertificateFixture(t, gatewayKey, testEnrolledGatewayID, dnsNames, 11)
	secondDER := newGatewayCertificateFixture(t, gatewayKey, testEnrolledGatewayID, dnsNames, 12)
	enrolled, err := GatewayEnrolledEvent(
		testEnrolledGatewayID,
		firstDER,
		testGatewayRegistrationTokenID,
		"gateway-owner@example.com",
		dnsNames,
	)
	if err != nil {
		t.Fatalf("create gateway enrollment event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(context.Background(), enrolled, 0); err != nil {
		t.Fatalf("append gateway enrollment event: %v", err)
	}
	renewed, err := GatewayCertificateRenewedEvent(testEnrolledGatewayID, secondDER, firstDER)
	if err != nil {
		t.Fatalf("create gateway renewal event: %v", err)
	}
	appendGatewayLifecycleEvent(t, eventStore, renewed, 1)
	revoked, err := GatewayCertificateRevokedEvent(testEnrolledGatewayID, secondDER)
	if err != nil {
		t.Fatalf("create gateway revocation event: %v", err)
	}
	appendGatewayLifecycleEvent(t, eventStore, revoked, 2)

	assertGatewayProjection(t, eventStore, Gateway{
		GatewayID:              testEnrolledGatewayID,
		CertificateDER:         secondDER,
		CertificateFingerprint: sha256.Sum256(secondDER),
		PreviousCertificateDER: firstDER,
		RegistrationTokenID:    testGatewayRegistrationTokenID,
		Owner:                  "gateway-owner@example.com",
		DNSNames:               dnsNames,
		LifecycleState:         GatewayLifecycleRevoked,
		ProjectionVersion:      3,
	})
	assertGatewayRevocations(t, eventStore, []revocationExpectation{
		{der: firstDER, reason: reasonCodeSuperseded},
		{der: secondDER, reason: reasonCodeUnspecified},
	})
	agentRevocations, err := eventStore.CertificateRevocations(context.Background(), CertificateClassAgent)
	if err != nil {
		t.Fatalf("read agent revocation fixture: %v", err)
	}
	if len(agentRevocations) != 1 || !bytes.Equal(agentRevocations[0].CertificateDER, agentDER) {
		t.Fatalf("agent revocations before gateway rebuild = %+v; want exact fixture", agentRevocations)
	}
	workBefore := allCRLWorkCount(t, pool)

	corruptDNSNames := []string{"corrupt.internal.example"}
	corruptDER := newGatewayCertificateFixture(t, gatewayKey, testEnrolledGatewayID, corruptDNSNames, 13)
	corruptFingerprint := sha256.Sum256(corruptDER)
	if _, err := pool.Exec(context.Background(), `
		UPDATE gateways
		SET certificate_der = $2,
		    certificate_fingerprint = $3,
		    previous_certificate_der = NULL,
		    owner = 'corrupt',
		    dns_names = $4,
		    lifecycle_state = 'active',
		    projection_version = 99
		WHERE gateway_id = $1`,
		testEnrolledGatewayID,
		corruptDER,
		corruptFingerprint[:],
		corruptDNSNames,
	); err != nil {
		t.Fatalf("corrupt gateway projection: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `DELETE FROM certificate_revocations WHERE certificate_class = 'gateway'`); err != nil {
		t.Fatalf("delete gateway revocation projections: %v", err)
	}
	if err := eventStore.RebuildAll(context.Background(), GatewayRebuildTarget); err != nil {
		t.Fatalf("rebuild gateway projections: %v", err)
	}

	assertGatewayProjection(t, eventStore, Gateway{
		GatewayID:              testEnrolledGatewayID,
		CertificateDER:         secondDER,
		CertificateFingerprint: sha256.Sum256(secondDER),
		PreviousCertificateDER: firstDER,
		RegistrationTokenID:    testGatewayRegistrationTokenID,
		Owner:                  "gateway-owner@example.com",
		DNSNames:               dnsNames,
		LifecycleState:         GatewayLifecycleRevoked,
		ProjectionVersion:      3,
	})
	assertGatewayRevocations(t, eventStore, []revocationExpectation{
		{der: firstDER, reason: reasonCodeSuperseded},
		{der: secondDER, reason: reasonCodeUnspecified},
	})
	agentRevocations, err = eventStore.CertificateRevocations(context.Background(), CertificateClassAgent)
	if err != nil {
		t.Fatalf("read agent revocations after gateway rebuild: %v", err)
	}
	if len(agentRevocations) != 1 || !bytes.Equal(agentRevocations[0].CertificateDER, agentDER) {
		t.Fatalf("gateway rebuild disturbed agent revocations: %+v", agentRevocations)
	}
	if workAfter := allCRLWorkCount(t, pool); workAfter != workBefore {
		t.Fatalf("CRL work count after gateway rebuild = %d; want unchanged %d", workAfter, workBefore)
	}
}

func appendGatewayLifecycleEvent(t *testing.T, eventStore *Store, event Event, expectedVersion int64) {
	t.Helper()
	if err := eventStore.WithDeviceLifecycleLock(context.Background(), testEnrolledGatewayID, func(lifecycle *DeviceLifecycle) error {
		return lifecycle.AppendGatewayEvent(context.Background(), event, expectedVersion)
	}); err != nil {
		t.Fatalf("append gateway lifecycle event: %v", err)
	}
}

func appendGatewayEnrollmentEvent(t *testing.T, eventStore *Store, certificateDER []byte, dnsNames []string) {
	t.Helper()
	event, err := GatewayEnrolledEvent(
		testEnrolledGatewayID,
		certificateDER,
		testGatewayRegistrationTokenID,
		"owner@example.com",
		dnsNames,
	)
	if err != nil {
		t.Fatalf("create gateway enrollment event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(context.Background(), event, 0); err != nil {
		t.Fatalf("append gateway enrollment event: %v", err)
	}
}

func replayGatewayProjector(
	t *testing.T,
	pool *pgxpool.Pool,
	event Event,
	streamVersion int64,
	projector Projector,
) error {
	t.Helper()
	var createdAt time.Time
	if err := pool.QueryRow(
		context.Background(),
		`SELECT created_at FROM events WHERE stream_type = $1 AND stream_id = $2 AND stream_version = $3`,
		event.StreamType,
		event.StreamID,
		streamVersion,
	).Scan(&createdAt); err != nil {
		t.Fatalf("read persisted gateway event time: %v", err)
	}
	persisted := PersistedEvent{Event: event, StreamVersion: streamVersion, CreatedAt: createdAt}
	tx, err := pool.Begin(context.Background())
	if err != nil {
		t.Fatalf("begin gateway projector replay: %v", err)
	}
	projectErr := projector(context.Background(), projectionTx{DBTX: tx, sourceEvent: &persisted}, persisted)
	if projectErr != nil {
		if err := rollbackTx(context.Background(), tx); err != nil {
			t.Fatalf("roll back rejected gateway projector replay: %v", err)
		}
		return projectErr
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit accepted gateway projector replay: %v", err)
	}
	return nil
}

func clearGatewayCRLProjections(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `DELETE FROM work_items WHERE work_kind = $1`, PublishGatewayCRLWorkKind); err != nil {
		t.Fatalf("clear gateway CRL work: %v", err)
	}
	if _, err := pool.Exec(context.Background(), `DELETE FROM certificate_revocations WHERE certificate_class = 'gateway'`); err != nil {
		t.Fatalf("clear gateway certificate revocations: %v", err)
	}
}

func assertGatewayProjectionBytes(
	t *testing.T,
	pool *pgxpool.Pool,
	wantVersion int64,
	wantCertificateDER []byte,
	wantPreviousDER []byte,
	wantFingerprint [sha256.Size]byte,
) {
	t.Helper()
	var version int64
	var certificateDER, previousDER, fingerprint []byte
	if err := pool.QueryRow(
		context.Background(),
		`SELECT projection_version, certificate_der, previous_certificate_der, certificate_fingerprint FROM gateways WHERE gateway_id = $1`,
		testEnrolledGatewayID,
	).Scan(&version, &certificateDER, &previousDER, &fingerprint); err != nil {
		t.Fatalf("read raw gateway projection: %v", err)
	}
	if version != wantVersion || !bytes.Equal(certificateDER, wantCertificateDER) ||
		!bytes.Equal(previousDER, wantPreviousDER) || !bytes.Equal(fingerprint, wantFingerprint[:]) {
		t.Fatalf("raw gateway projection = version %d cert %x previous %x fingerprint %x; want preserved corrupt state", version, certificateDER, previousDER, fingerprint)
	}
}

func assertGatewayProjection(t *testing.T, eventStore *Store, want Gateway) {
	t.Helper()
	got, err := eventStore.Gateway(context.Background(), want.GatewayID)
	if err != nil {
		t.Fatalf("read gateway projection: %v", err)
	}
	if got.GatewayID != want.GatewayID || got.CertificateFingerprint != want.CertificateFingerprint ||
		!bytes.Equal(got.CertificateDER, want.CertificateDER) || !bytes.Equal(got.PreviousCertificateDER, want.PreviousCertificateDER) ||
		got.RegistrationTokenID != want.RegistrationTokenID || got.Owner != want.Owner || !slices.Equal(got.DNSNames, want.DNSNames) ||
		got.LifecycleState != want.LifecycleState || got.ProjectionVersion != want.ProjectionVersion {
		t.Fatalf("gateway projection = %+v; want %+v", got, want)
	}
}

func assertGatewayRevocations(t *testing.T, eventStore *Store, want []revocationExpectation) {
	t.Helper()
	revocations, err := eventStore.CertificateRevocations(context.Background(), CertificateClassGateway)
	if err != nil {
		t.Fatalf("read gateway revocations: %v", err)
	}
	if len(revocations) != len(want) {
		t.Fatalf("gateway revocation count = %d; want %d", len(revocations), len(want))
	}
	for index := range want {
		if !bytes.Equal(revocations[index].CertificateDER, want[index].der) || revocations[index].ReasonCode != want[index].reason {
			t.Fatalf("gateway revocation %d = %+v; want reason %d exact DER", index, revocations[index], want[index].reason)
		}
	}
}

func allCRLWorkCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM work_items WHERE work_kind IN ('publish-agent-crl', 'publish-gateway-crl')`).Scan(&count); err != nil {
		t.Fatalf("count CRL work: %v", err)
	}
	return count
}

func newGatewayCertificateFixture(t *testing.T, key *ecdsa.PrivateKey, gatewayID string, dnsNames []string, serial int64) []byte {
	t.Helper()
	return newGatewayCertificateFixtureWithMutation(t, key, gatewayID, dnsNames, serial, nil)
}

func newGatewayCertificateFixtureWithMutation(
	t *testing.T,
	key *ecdsa.PrivateKey,
	gatewayID string,
	dnsNames []string,
	serial int64,
	mutate func(*x509.Certificate),
) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		NotBefore:             time.Date(2026, time.July, 22, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2026, time.September, 5, 0, 0, 0, 0, time.UTC),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              slices.Clone(dnsNames),
	}
	if err := identity.StampCertificateIdentity(template, identity.GatewayClass, gatewayID); err != nil {
		t.Fatalf("stamp gateway certificate identity: %v", err)
	}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create gateway certificate: %v", err)
	}
	return der
}

func unsupportedGatewaySANExtension(t *testing.T, dnsName, unsupportedKind string) pkix.Extension {
	t.Helper()
	unsupported := unsupportedGatewayGeneralName(t, unsupportedKind)
	value, err := asn1.Marshal([]asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte(dnsName)},
		{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(identity.GatewaySPIFFEURI)},
		unsupported,
	})
	if err != nil {
		t.Fatalf("marshal unsupported gateway SAN extension: %v", err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: value}
}

func unsupportedGatewayGeneralName(t *testing.T, kind string) asn1.RawValue {
	t.Helper()
	switch kind {
	case "otherName":
		utf8DER, err := asn1.Marshal("unsupported")
		if err != nil {
			t.Fatalf("marshal otherName value: %v", err)
		}
		otherNameDER, err := asn1.Marshal(struct {
			TypeID asn1.ObjectIdentifier
			Value  asn1.RawValue
		}{
			TypeID: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 4},
			Value: asn1.RawValue{
				Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: utf8DER,
			},
		})
		if err != nil {
			t.Fatalf("marshal otherName: %v", err)
		}
		var sequence asn1.RawValue
		if rest, err := asn1.Unmarshal(otherNameDER, &sequence); err != nil || len(rest) != 0 {
			t.Fatalf("parse otherName sequence = %x, %v", rest, err)
		}
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sequence.Bytes}
	case "directoryName":
		directoryDER, err := asn1.Marshal(pkix.Name{CommonName: "unsupported"}.ToRDNSequence())
		if err != nil {
			t.Fatalf("marshal directoryName: %v", err)
		}
		var sequence asn1.RawValue
		if rest, err := asn1.Unmarshal(directoryDER, &sequence); err != nil || len(rest) != 0 {
			t.Fatalf("parse directoryName sequence = %x, %v", rest, err)
		}
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: sequence.Bytes}
	case "registeredID":
		identifierDER, err := asn1.Marshal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 5})
		if err != nil {
			t.Fatalf("marshal registeredID: %v", err)
		}
		var identifier asn1.RawValue
		if rest, err := asn1.Unmarshal(identifierDER, &identifier); err != nil || len(rest) != 0 {
			t.Fatalf("parse registeredID = %x, %v", rest, err)
		}
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 8, Bytes: identifier.Bytes}
	default:
		t.Fatalf("unknown unsupported GeneralName fixture %q", kind)
		return asn1.RawValue{}
	}
}

func assertUnsupportedGatewaySANFixture(t *testing.T, certificateDER []byte, dnsName, unsupportedKind string) {
	t.Helper()
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("parse unsupported SAN gateway fixture: %v", err)
	}
	class, gatewayID, err := identity.ParseCertificateIdentity(certificate)
	if err != nil || class != identity.GatewayClass || gatewayID != testEnrolledGatewayID ||
		!slices.Equal(certificate.DNSNames, []string{dnsName}) || len(certificate.EmailAddresses) != 0 || len(certificate.IPAddresses) != 0 {
		t.Fatalf("unsupported %s SAN fixture parsed as identity (%q, %q), DNS %v, email %v, IP %v: %v", unsupportedKind, class, gatewayID, certificate.DNSNames, certificate.EmailAddresses, certificate.IPAddresses, err)
	}
	found := false
	for _, extension := range certificate.Extensions {
		if !extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		var names []asn1.RawValue
		if rest, err := asn1.Unmarshal(extension.Value, &names); err != nil || len(rest) != 0 {
			t.Fatalf("parse unsupported SAN extension = %x, %v", rest, err)
		}
		for _, name := range names {
			if name.Class == asn1.ClassContextSpecific && name.Tag == map[string]int{"otherName": 0, "directoryName": 4, "registeredID": 8}[unsupportedKind] {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("unsupported %s GeneralName is absent from raw SAN extension", unsupportedKind)
	}
}
