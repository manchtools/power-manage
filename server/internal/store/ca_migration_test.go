package store

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/manchtools/power-manage/contract/identity"
)

func TestCAMigrationReport_PaginatesAndClassifiesFromStoredCertificateDER(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production event store: %v", err)
	}
	now := time.Date(2026, time.July, 23, 13, 0, 0, 0, time.UTC)
	current := newMigrationReportCA(t, "current report issuer", now)
	successor := newMigrationReportCA(t, "successor report issuer", now)
	currentFingerprint := sha256.Sum256(current.certificate.Raw)
	successorFingerprint := sha256.Sum256(successor.certificate.Raw)
	rows := []struct {
		id        string
		authority migrationReportCA
		confirmed bool
		revoked   bool
	}{
		{id: "01J00000000000000000000101", authority: current},
		{id: "01J00000000000000000000102", authority: successor},
		{id: "01J00000000000000000000103", authority: successor, confirmed: true},
		{id: "01J00000000000000000000104", authority: current, revoked: true},
	}
	for index, row := range rows {
		certificateDER, key := seedMigrationReportAgent(t, eventStore, row.id, row.authority, now, int64(100+index))
		if row.confirmed {
			if err := eventStore.RecordLeafTrustConfirmation(context.Background(), LeafTrustConfirmation{
				CertificateClass: CertificateClassAgent, ReporterID: row.id,
				ReporterCertificateDER: certificateDER, Generation: 9,
				IssuerFingerprint: successorFingerprint,
			}); err != nil {
				t.Fatalf("record successor confirmation for %s: %v", row.id, err)
			}
		}
		if row.revoked {
			event, err := AgentCertificateRevokedEvent(row.id, certificateDER)
			if err != nil {
				t.Fatalf("build report revocation event: %v", err)
			}
			appendMigrationLifecycleEvent(t, eventStore, row.id, event)
		}
		_ = key
	}

	// A tempting projection shortcut is deliberately corrupted. The report
	// must parse each stored certificate's RawIssuer/AKI and remain correct.
	wrong := sha256.Sum256([]byte("projection-only wrong issuer"))
	if _, err := pool.Exec(context.Background(), `
		UPDATE devices SET certificate_fingerprint = $2 WHERE device_id = $1`,
		rows[1].id, wrong[:],
	); err != nil {
		t.Fatalf("corrupt report-only issuer projection: %v", err)
	}

	query := CAMigrationReportQuery{
		CertificateClass: CertificateClassAgent, Generation: 9,
		CurrentIssuerFingerprint:   currentFingerprint,
		SuccessorIssuerFingerprint: successorFingerprint,
		CurrentRootDER:             bytes.Clone(current.certificate.Raw),
		SuccessorRootDER:           bytes.Clone(successor.certificate.Raw),
		Limit:                      2,
	}
	first, err := eventStore.CAMigrationReport(context.Background(), query)
	if err != nil {
		t.Fatalf("first CA migration report page: %v", err)
	}
	if got := migrationEntryIDs(first.Entries); !slices.Equal(got, []string{rows[0].id, rows[1].id}) || first.NextCursor == "" {
		t.Fatalf("first report page = (%v, cursor %q); want first two and a cursor", got, first.NextCursor)
	}
	if first.Entries[0].Status != CAMigrationStatusCurrentIssued || first.Entries[1].Status != CAMigrationStatusSuccessorIssued {
		t.Fatalf("first report classifications = %v; want current-issued then successor-issued despite corrupt projection", first.Entries)
	}
	seedMigrationReportAgent(t, eventStore, "01J00000000000000000000100", current, now, 99)
	query.Cursor = first.NextCursor
	second, err := eventStore.CAMigrationReport(context.Background(), query)
	if err != nil {
		t.Fatalf("second CA migration report page: %v", err)
	}
	if got := migrationEntryIDs(second.Entries); !slices.Equal(got, []string{rows[2].id, rows[3].id}) || second.NextCursor != "" {
		t.Fatalf("second report page = (%v, cursor %q); want final two and terminal cursor", got, second.NextCursor)
	}
	if second.Entries[0].Status != CAMigrationStatusSuccessorConfirmed || second.Entries[1].Status != CAMigrationStatusRevoked {
		t.Fatalf("second report classifications = %v; want successor-confirmed then revoked", second.Entries)
	}

	invalid := []struct {
		query   CAMigrationReportQuery
		wantErr string
	}{
		{query: CAMigrationReportQuery{}, wantErr: "certificate class"},
		{query: CAMigrationReportQuery{CertificateClass: CertificateClassAgent, Generation: 9, CurrentIssuerFingerprint: currentFingerprint, SuccessorIssuerFingerprint: successorFingerprint, CurrentRootDER: current.certificate.Raw, SuccessorRootDER: successor.certificate.Raw, Limit: 0}, wantErr: "limit"},
		{query: CAMigrationReportQuery{CertificateClass: CertificateClassAgent, Generation: 9, CurrentIssuerFingerprint: currentFingerprint, SuccessorIssuerFingerprint: successorFingerprint, CurrentRootDER: current.certificate.Raw, SuccessorRootDER: successor.certificate.Raw, Limit: MaxCAMigrationReportPageSize + 1}, wantErr: "limit"},
		{query: CAMigrationReportQuery{CertificateClass: CertificateClassAgent, Generation: 9, CurrentIssuerFingerprint: currentFingerprint, SuccessorIssuerFingerprint: currentFingerprint, CurrentRootDER: current.certificate.Raw, SuccessorRootDER: current.certificate.Raw, Limit: 1}, wantErr: "fingerprints must differ"},
		{query: CAMigrationReportQuery{CertificateClass: CertificateClassAgent, Generation: 9, CurrentIssuerFingerprint: currentFingerprint, SuccessorIssuerFingerprint: successorFingerprint, CurrentRootDER: current.certificate.Raw, SuccessorRootDER: successor.certificate.Raw, Cursor: "not-a-cursor", Limit: 1}, wantErr: "cursor"},
		{query: CAMigrationReportQuery{CertificateClass: CertificateClassAgent, Generation: 9, CurrentIssuerFingerprint: currentFingerprint, SuccessorIssuerFingerprint: successorFingerprint, SuccessorRootDER: successor.certificate.Raw, Limit: 1}, wantErr: "current root"},
		{query: CAMigrationReportQuery{CertificateClass: CertificateClassAgent, Generation: 9, CurrentIssuerFingerprint: currentFingerprint, SuccessorIssuerFingerprint: successorFingerprint, CurrentRootDER: current.certificate.Raw, SuccessorRootDER: []byte("not DER"), Limit: 1}, wantErr: "successor root"},
		{query: CAMigrationReportQuery{CertificateClass: CertificateClassAgent, Generation: 9, CurrentIssuerFingerprint: currentFingerprint, SuccessorIssuerFingerprint: successorFingerprint, CurrentRootDER: append(bytes.Clone(current.certificate.Raw), 0), SuccessorRootDER: successor.certificate.Raw, Limit: 1}, wantErr: "current root"},
		{query: CAMigrationReportQuery{CertificateClass: CertificateClassAgent, Generation: 9, CurrentIssuerFingerprint: sha256.Sum256([]byte("wrong current root")), SuccessorIssuerFingerprint: successorFingerprint, CurrentRootDER: current.certificate.Raw, SuccessorRootDER: successor.certificate.Raw, Limit: 1}, wantErr: "current fingerprint"},
		{query: CAMigrationReportQuery{CertificateClass: CertificateClassAgent, Generation: 9, CurrentIssuerFingerprint: currentFingerprint, SuccessorIssuerFingerprint: sha256.Sum256([]byte("wrong successor root")), CurrentRootDER: current.certificate.Raw, SuccessorRootDER: successor.certificate.Raw, Limit: 1}, wantErr: "successor fingerprint"},
	}
	for index, invalidCase := range invalid {
		page, err := eventStore.CAMigrationReport(context.Background(), invalidCase.query)
		if err == nil || len(page.Entries) != 0 {
			t.Fatalf("invalid report query %d = (%+v, %v); want empty rejection", index, page, err)
		}
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(invalidCase.wantErr)) {
			t.Fatalf("invalid report query %d error = %q; want %q", index, err, invalidCase.wantErr)
		}
	}

	for _, class := range []CertificateClass{CertificateClassAgent, CertificateClassGateway} {
		t.Run(string(class)+" cryptographically verifies issuer classification", func(t *testing.T) {
			classStore, err := NewProduction(testPostgres(t))
			if err != nil {
				t.Fatalf("create isolated %s report store: %v", class, err)
			}
			assertCryptographicMigrationClassification(t, classStore, class, now)
		})
	}
}

func assertCryptographicMigrationClassification(t *testing.T, eventStore *Store, class CertificateClass, now time.Time) {
	t.Helper()
	current := newMigrationReportCA(t, string(class)+" current issuer", now)
	successor := newMigrationReportCA(t, string(class)+" successor issuer", now)
	attacker := newMigrationReportCA(t, string(class)+" attacker signer", now)
	currentFingerprint := sha256.Sum256(current.certificate.Raw)
	successorFingerprint := sha256.Sum256(successor.certificate.Raw)
	base := "01J000000000000000000002"
	ids := []string{base + "01", base + "02", base + "03"}
	seedMigrationReportLeaf(t, eventStore, class, ids[0], current, current, now, 201)
	seedMigrationReportLeaf(t, eventStore, class, ids[1], successor, successor, now, 202)
	// The hostile leaf's RawIssuer and AKI are copied from successor because
	// successor is the certificate parent, but its signature is made by the
	// attacker's key. Field matching alone would misclassify it as migrated.
	seedMigrationReportLeaf(t, eventStore, class, ids[2], successor, attacker, now, 203)
	query := CAMigrationReportQuery{
		CertificateClass: class, Generation: 12,
		CurrentIssuerFingerprint: currentFingerprint, SuccessorIssuerFingerprint: successorFingerprint,
		CurrentRootDER: bytes.Clone(current.certificate.Raw), SuccessorRootDER: bytes.Clone(successor.certificate.Raw),
		Limit: 2,
	}
	page, err := eventStore.CAMigrationReport(context.Background(), query)
	if err != nil {
		t.Fatalf("cryptographic migration report: %v", err)
	}
	if got := migrationEntryIDs(page.Entries); !slices.Equal(got, ids[:2]) || page.NextCursor == "" {
		t.Fatalf("cryptographic report first page = (%v,%q); want first two and cursor", got, page.NextCursor)
	}
	if page.Entries[0].Status != CAMigrationStatusCurrentIssued ||
		page.Entries[1].Status != CAMigrationStatusSuccessorIssued {
		t.Fatalf("cryptographic first-page classifications = %+v", page.Entries)
	}
	query.Cursor = page.NextCursor
	last, err := eventStore.CAMigrationReport(context.Background(), query)
	if err != nil || !slices.Equal(migrationEntryIDs(last.Entries), ids[2:]) || last.NextCursor != "" ||
		last.Entries[0].Status != CAMigrationStatusInvalidIssuerSignature {
		t.Fatalf("cryptographic final page = (%+v,%v); hostile issuer/SKI lookalike must not count as successor-issued", last, err)
	}
}

func seedMigrationReportLeaf(
	t *testing.T,
	eventStore *Store,
	class CertificateClass,
	id string,
	issuerFields migrationReportCA,
	signingAuthority migrationReportCA,
	now time.Time,
	serial int64,
) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate migration report leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(365 * 24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	identityClass := identity.AgentClass
	if class == CertificateClassAgent {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		identityClass = identity.GatewayClass
		template.NotAfter = template.NotBefore.Add(gatewayCertificateLifetime)
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		template.DNSNames = []string{"report-gateway.internal.example"}
	}
	if err := identity.StampCertificateIdentity(template, identityClass, id); err != nil {
		t.Fatalf("stamp report identity: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuerFields.certificate, key.Public(), issuerFields.signer)
	if err != nil {
		t.Fatalf("create migration report leaf: %v", err)
	}
	if signingAuthority.certificate != issuerFields.certificate {
		der = bytes.Clone(der)
		der[len(der)-1] ^= 0xff
	}
	if class == CertificateClassAgent {
		sealing, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate report sealing key: %v", err)
		}
		event, err := AgentEnrolledEvent(id, der, sealing.PublicKey().Bytes(), "01J00000000000000000000211", "owner@example.com")
		if err != nil {
			t.Fatalf("build report agent event: %v", err)
		}
		appendMigrationLifecycleEvent(t, eventStore, id, event)
		return
	}
	event, err := GatewayEnrolledEvent(id, der, "01J00000000000000000000212", "owner@example.com", template.DNSNames)
	if err != nil {
		t.Fatalf("build report gateway event: %v", err)
	}
	if err := eventStore.WithDeviceLifecycleLock(context.Background(), id, func(lifecycle *DeviceLifecycle) error {
		return lifecycle.AppendGatewayEvent(context.Background(), event, 0)
	}); err != nil {
		t.Fatalf("append report gateway event: %v", err)
	}
}

type migrationReportCA struct {
	certificate *x509.Certificate
	signer      *ecdsa.PrivateKey
}

func newMigrationReportCA(t *testing.T, name string, now time.Time) migrationReportCA {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate migration report CA: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatalf("marshal migration report CA key: %v", err)
	}
	keyID := sha256.Sum256(publicDER)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: bytes.Clone(keyID[:20]), AuthorityKeyId: bytes.Clone(keyID[:20]),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatalf("create migration report CA: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse migration report CA: %v", err)
	}
	return migrationReportCA{certificate: certificate, signer: signer}
}

func seedMigrationReportAgent(
	t *testing.T,
	eventStore *Store,
	deviceID string,
	authority migrationReportCA,
	now time.Time,
	serial int64,
) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate migration report leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(-time.Minute).Add(365 * 24 * time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if err := identity.StampCertificateIdentity(template, identity.AgentClass, deviceID); err != nil {
		t.Fatalf("stamp migration report leaf: %v", err)
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, authority.certificate, key.Public(), authority.signer)
	if err != nil {
		t.Fatalf("create migration report leaf: %v", err)
	}
	sealing, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate migration report sealing key: %v", err)
	}
	event, err := AgentEnrolledEvent(
		deviceID, certificateDER, sealing.PublicKey().Bytes(),
		"01J00000000000000000000111", "owner@example.com",
	)
	if err != nil {
		t.Fatalf("build migration report enrollment event: %v", err)
	}
	appendMigrationLifecycleEvent(t, eventStore, deviceID, event)
	return certificateDER, key
}

func appendMigrationLifecycleEvent(t *testing.T, eventStore *Store, deviceID string, event Event) {
	t.Helper()
	if err := eventStore.WithDeviceLifecycleLock(context.Background(), deviceID, func(lifecycle *DeviceLifecycle) error {
		current, err := lifecycle.Device(context.Background())
		expectedVersion := int64(0)
		if err == nil {
			expectedVersion = current.ProjectionVersion
		} else if !IsNotFound(err) {
			return err
		}
		return lifecycle.AppendEvent(context.Background(), event, expectedVersion)
	}); err != nil {
		t.Fatalf("append migration report lifecycle event: %v", err)
	}
}

func migrationEntryIDs(entries []CAMigrationReportEntry) []string {
	result := make([]string, len(entries))
	for index := range entries {
		result[index] = entries[index].ReporterID
	}
	return result
}
