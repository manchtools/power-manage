package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/manchtools/power-manage/contract/identity"
)

func TestCRLState_CompareAndSwapIsMonotonicUnderConcurrency(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production event store: %v", err)
	}
	issuedAt := time.Date(2026, time.July, 22, 15, 0, 0, 0, time.UTC)
	if stored, err := eventStore.CompareAndSwapCRL(context.Background(), CertificateClassAgent, 0, []byte{1}, issuedAt, CRLSource{}); stored || err == nil || err.Error() != "store: invalid CRL compare-and-swap input: revocation-list DER is invalid" {
		t.Fatalf("malformed CRL write = (%v, %v); want exact rejection", stored, err)
	}
	firstDER := signedStoreCRLFixture(t, 1, issuedAt)
	secondDER := signedStoreCRLFixture(t, 1, issuedAt)
	type compareAndSwapResult struct {
		stored bool
		err    error
	}
	results := make(chan compareAndSwapResult, 2)
	for _, der := range [][]byte{firstDER, secondDER} {
		der := der
		go func() {
			stored, err := eventStore.CompareAndSwapCRL(context.Background(), CertificateClassAgent, 0, der, issuedAt, CRLSource{})
			results <- compareAndSwapResult{stored: stored, err: err}
		}()
	}
	stored := 0
	for range 2 {
		var result compareAndSwapResult
		select {
		case result = <-results:
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent CRL compare-and-swap did not complete")
		}
		if result.err != nil {
			t.Fatalf("compare and swap CRL: %v", result.err)
		}
		if result.stored {
			stored++
		}
	}
	if stored != 1 {
		t.Fatalf("successful concurrent CRL writes = %d; want one", stored)
	}
	state, err := eventStore.LatestCRL(context.Background(), CertificateClassAgent)
	if err != nil {
		t.Fatalf("read latest CRL: %v", err)
	}
	if state.Sequence != 1 || (!bytes.Equal(state.DER, firstDER) && !bytes.Equal(state.DER, secondDER)) {
		t.Fatalf("latest CRL = %+v; want one sequence-one publication", state)
	}
	if stored, err := eventStore.CompareAndSwapCRL(context.Background(), CertificateClassAgent, 1, []byte{3}, issuedAt.Add(time.Second), CRLSource{}); stored || err == nil || err.Error() != "store: invalid CRL compare-and-swap input" {
		t.Fatalf("source-less sequence-two write = (%v, %v); want exact rejection", stored, err)
	}
	key := newDeviceSigningKeyFixture(t)
	certificateDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, testEnrolledDeviceID, key, 7)
	appendEnrollmentFixture(t, eventStore, certificateDER)
	source := CRLSource{StreamType: deviceStreamType, StreamID: testEnrolledDeviceID, StreamVersion: 1}
	thirdDER := signedStoreCRLFixture(t, 2, issuedAt.Add(time.Second))
	if stored, err := eventStore.CompareAndSwapCRL(context.Background(), CertificateClassAgent, 1, thirdDER, issuedAt.Add(time.Second), source); err != nil || !stored {
		t.Fatalf("store sequence two = (%v, %v); want success", stored, err)
	}
	state, err = eventStore.LatestCRL(context.Background(), CertificateClassAgent)
	if err != nil {
		t.Fatalf("read second CRL: %v", err)
	}
	if state.Sequence != 2 || state.Source != source || !bytes.Equal(state.DER, thirdDER) {
		t.Fatalf("latest CRL = %+v; want sequence two", state)
	}
	receiptSequence, found, err := eventStore.CRLWorkReceipt(context.Background(), CertificateClassAgent, source)
	if err != nil || !found || receiptSequence != 2 {
		t.Fatalf("CRL work receipt = (%d, %v, %v); want sequence two", receiptSequence, found, err)
	}
	missing := CRLSource{StreamType: deviceStreamType, StreamID: testEnrolledDeviceID, StreamVersion: 2}
	if receiptSequence, found, err := eventStore.CRLWorkReceipt(context.Background(), CertificateClassAgent, missing); err != nil || found || receiptSequence != 0 {
		t.Fatalf("missing CRL work receipt = (%d, %v, %v); want absent", receiptSequence, found, err)
	}
	if _, err := pool.Exec(context.Background(), `UPDATE crl_state SET crl_der = $1 WHERE certificate_class = 'agent'`, []byte{1}); err != nil {
		t.Fatalf("corrupt durable CRL fixture: %v", err)
	}
	if _, err := eventStore.LatestCRL(context.Background(), CertificateClassAgent); err == nil || !strings.Contains(err.Error(), "revocation-list DER is invalid") {
		t.Fatalf("malformed durable CRL error = %v; want exact material rejection", err)
	}
}

func TestCRLStateSchema_RejectsIncompletePublicationSource(t *testing.T) {
	pool := testPostgres(t)
	issuedAt := time.Date(2026, time.July, 22, 15, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		query string
		args  []any
	}{
		{
			name:  "missing DER",
			query: `UPDATE crl_state SET sequence = 1, crl_der = NULL, issued_at = $1 WHERE certificate_class = 'agent'`,
			args:  []any{issuedAt},
		},
		{
			name: "partial source tuple",
			query: `UPDATE crl_state SET sequence = 1, crl_der = $1, issued_at = $2,
				source_stream_type = 'device' WHERE certificate_class = 'agent'`,
			args: []any{[]byte{1}, issuedAt},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := pool.Exec(context.Background(), test.query, test.args...)
			var postgresError *pgconn.PgError
			if err == nil || !errors.As(err, &postgresError) || postgresError.Code != "23514" {
				t.Fatalf("invalid CRL state error = %v; want SQLSTATE 23514", err)
			}
		})
	}
}

func TestDeviceProjection_RevocationAndForceRenewRebuildExactState(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production event store: %v", err)
	}
	key := newDeviceSigningKeyFixture(t)
	firstDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, testEnrolledDeviceID, key, 7)
	secondDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, testEnrolledDeviceID, key, 8)
	appendEnrollmentFixture(t, eventStore, firstDER)

	forceRenew, err := AgentCertificateForceRenewalRequiredEvent(testEnrolledDeviceID, firstDER)
	if err != nil {
		t.Fatalf("create force-renew event: %v", err)
	}
	appendLifecycleEventFixture(t, eventStore, forceRenew, 1)
	assertDeviceLifecycleState(t, eventStore, DeviceLifecycleForceRenewal, 2)
	assertAgentRevocations(t, eventStore, []revocationExpectation{{der: firstDER, reason: reasonCodeSuperseded}})

	renewal, err := AgentCertificateRenewedEvent(
		testEnrolledDeviceID,
		secondDER,
		bytes.Repeat([]byte{0x43}, 32),
		firstDER,
	)
	if err != nil {
		t.Fatalf("create renewal event: %v", err)
	}
	appendLifecycleEventFixture(t, eventStore, renewal, 2)
	assertDeviceLifecycleState(t, eventStore, DeviceLifecycleActive, 3)

	revoke, err := AgentCertificateRevokedEvent(testEnrolledDeviceID, secondDER)
	if err != nil {
		t.Fatalf("create standalone revoke event: %v", err)
	}
	appendLifecycleEventFixture(t, eventStore, revoke, 3)
	assertDeviceLifecycleState(t, eventStore, DeviceLifecycleRevoked, 4)
	assertAgentRevocations(t, eventStore, []revocationExpectation{
		{der: firstDER, reason: reasonCodeSuperseded},
		{der: secondDER, reason: reasonCodeUnspecified},
	})

	if _, err := pool.Exec(
		context.Background(),
		`UPDATE devices SET lifecycle_state = 'active', projection_version = 99 WHERE device_id = $1`,
		testEnrolledDeviceID,
	); err != nil {
		t.Fatalf("corrupt device lifecycle projection: %v", err)
	}
	if _, err := pool.Exec(
		context.Background(),
		`DELETE FROM certificate_revocations WHERE certificate_class = 'agent'`,
	); err != nil {
		t.Fatalf("clear agent revocation projections: %v", err)
	}
	if err := eventStore.RebuildAll(context.Background(), DeviceRebuildTarget); err != nil {
		t.Fatalf("rebuild device revocations: %v", err)
	}
	assertDeviceLifecycleState(t, eventStore, DeviceLifecycleRevoked, 4)
	assertAgentRevocations(t, eventStore, []revocationExpectation{
		{der: firstDER, reason: reasonCodeSuperseded},
		{der: secondDER, reason: reasonCodeUnspecified},
	})
}

func TestDeviceRebuild_PreservesGatewayRevocations(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production event store: %v", err)
	}
	agentKey := newDeviceSigningKeyFixture(t)
	agentDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, testEnrolledDeviceID, agentKey, 7)
	appendEnrollmentFixture(t, eventStore, agentDER)

	gatewayKey := newDeviceSigningKeyFixture(t)
	gatewayDER := newDeviceCertificateWithKeyFixture(t, identity.GatewayClass, testEnrolledDeviceID, gatewayKey, 8)
	gatewayCertificate, err := x509.ParseCertificate(gatewayDER)
	if err != nil {
		t.Fatalf("parse gateway certificate fixture: %v", err)
	}
	gatewayFingerprint := sha256.Sum256(gatewayDER)
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO certificate_revocations (
			certificate_class, certificate_fingerprint, certificate_der,
			serial_number, revoked_at, reason_code,
			source_stream_type, source_stream_id, source_stream_version
		) VALUES ('gateway', $1, $2, $3, $4, 0, 'device', $5, 1)`,
		gatewayFingerprint[:], gatewayDER, gatewayCertificate.SerialNumber.Bytes(),
		time.Now().UTC(), testEnrolledDeviceID,
	); err != nil {
		t.Fatalf("insert gateway revocation fixture: %v", err)
	}

	if err := eventStore.RebuildAll(context.Background(), DeviceRebuildTarget); err != nil {
		t.Fatalf("rebuild device projections: %v", err)
	}
	gatewayRevocations, err := eventStore.CertificateRevocations(context.Background(), CertificateClassGateway)
	if err != nil {
		t.Fatalf("read gateway revocations after device rebuild: %v", err)
	}
	if len(gatewayRevocations) != 1 || !bytes.Equal(gatewayRevocations[0].CertificateDER, gatewayDER) {
		t.Fatalf("gateway revocations after device rebuild = %+v; want exact preserved row", gatewayRevocations)
	}
}

func TestDeviceProjection_RevocationRejectsWrongPredecessorWithoutWrites(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production event store: %v", err)
	}
	key := newDeviceSigningKeyFixture(t)
	currentDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, testEnrolledDeviceID, key, 7)
	wrongDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, testEnrolledDeviceID, key, 8)
	appendEnrollmentFixture(t, eventStore, currentDER)

	event, err := AgentCertificateRevokedEvent(testEnrolledDeviceID, wrongDER)
	if err != nil {
		t.Fatalf("create wrong-predecessor revoke event: %v", err)
	}
	if err := eventStore.WithDeviceLifecycleLock(context.Background(), testEnrolledDeviceID, func(lifecycle *DeviceLifecycle) error {
		return lifecycle.AppendEvent(context.Background(), event, 1)
	}); err == nil || !strings.Contains(err.Error(), "agent certificate lifecycle event conflicts with the current device projection") {
		t.Fatalf("wrong-predecessor revoke error = %v; want exact projection conflict", err)
	}
	assertDeviceLifecycleState(t, eventStore, DeviceLifecycleActive, 1)
	assertAgentRevocations(t, eventStore, nil)
	if got := crlWorkCount(t, pool); got != 0 {
		t.Fatalf("CRL work count = %d; want zero", got)
	}
}

func TestDeviceProjection_RenewalSupersessionEnqueuesCRLWorkAtomically(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production event store: %v", err)
	}
	key := newDeviceSigningKeyFixture(t)
	currentDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, testEnrolledDeviceID, key, 7)
	renewedDER := newDeviceCertificateWithKeyFixture(t, identity.AgentClass, testEnrolledDeviceID, key, 8)
	appendEnrollmentFixture(t, eventStore, currentDER)
	renewal, err := AgentCertificateRenewedEvent(testEnrolledDeviceID, renewedDER, bytes.Repeat([]byte{0x43}, 32), currentDER)
	if err != nil {
		t.Fatalf("create renewal event: %v", err)
	}
	appendLifecycleEventFixture(t, eventStore, renewal, 1)

	assertAgentRevocations(t, eventStore, []revocationExpectation{{der: currentDER, reason: reasonCodeSuperseded}})
	if got := crlWorkCount(t, pool); got != 1 {
		t.Fatalf("CRL work count = %d; want one", got)
	}
}

type revocationExpectation struct {
	der    []byte
	reason int
}

func appendEnrollmentFixture(t *testing.T, eventStore *Store, certificateDER []byte) {
	t.Helper()
	event, err := AgentEnrolledEvent(
		testEnrolledDeviceID,
		certificateDER,
		bytes.Repeat([]byte{0x42}, 32),
		testEnrollmentTokenID,
		"owner@example.com",
	)
	if err != nil {
		t.Fatalf("create enrollment event: %v", err)
	}
	if err := eventStore.AppendEventWithVersion(context.Background(), event, 0); err != nil {
		t.Fatalf("append enrollment event: %v", err)
	}
}

func appendLifecycleEventFixture(t *testing.T, eventStore *Store, event Event, expectedVersion int64) {
	t.Helper()
	if err := eventStore.WithDeviceLifecycleLock(context.Background(), testEnrolledDeviceID, func(lifecycle *DeviceLifecycle) error {
		return lifecycle.AppendEvent(context.Background(), event, expectedVersion)
	}); err != nil {
		t.Fatalf("append lifecycle event: %v", err)
	}
}

func assertDeviceLifecycleState(t *testing.T, eventStore *Store, want DeviceLifecycleState, version int64) {
	t.Helper()
	device, err := eventStore.Device(context.Background(), testEnrolledDeviceID)
	if err != nil {
		t.Fatalf("read device: %v", err)
	}
	if device.LifecycleState != want || device.ProjectionVersion != version {
		t.Fatalf("device lifecycle = (%q, %d); want (%q, %d)", device.LifecycleState, device.ProjectionVersion, want, version)
	}
}

func assertAgentRevocations(t *testing.T, eventStore *Store, want []revocationExpectation) {
	t.Helper()
	revocations, err := eventStore.CertificateRevocations(context.Background(), CertificateClassAgent)
	if err != nil {
		t.Fatalf("read certificate revocations: %v", err)
	}
	if len(revocations) != len(want) {
		t.Fatalf("revocation count = %d; want %d", len(revocations), len(want))
	}
	for index := range want {
		if !bytes.Equal(revocations[index].CertificateDER, want[index].der) || revocations[index].ReasonCode != want[index].reason {
			t.Fatalf("revocation %d = %+v; want DER %x reason %d", index, revocations[index], want[index].der, want[index].reason)
		}
	}
}

func crlWorkCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM work_items WHERE work_kind = 'publish-agent-crl'`).Scan(&count); err != nil {
		t.Fatalf("count CRL work: %v", err)
	}
	return count
}

func signedStoreCRLFixture(t *testing.T, sequence int64, issuedAt time.Time) []byte {
	t.Helper()
	signer := newDeviceSigningKeyFixture(t)
	authorityTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(100), NotBefore: issuedAt.Add(-time.Hour), NotAfter: issuedAt.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3, 4},
	}
	authorityDER, err := x509.CreateCertificate(rand.Reader, authorityTemplate, authorityTemplate, signer.Public(), signer)
	if err != nil {
		t.Fatalf("create CRL authority fixture: %v", err)
	}
	authority, err := x509.ParseCertificate(authorityDER)
	if err != nil {
		t.Fatalf("parse CRL authority fixture: %v", err)
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(sequence), ThisUpdate: issuedAt, NextUpdate: issuedAt.Add(time.Hour),
	}, authority, signer)
	if err != nil {
		t.Fatalf("create CRL fixture: %v", err)
	}
	return der
}
