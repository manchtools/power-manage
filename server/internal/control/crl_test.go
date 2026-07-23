package control

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/manchtools/power-manage/server/internal/store"
)

func TestCRLDistributor_SendsCurrentOnConnectAndEveryNewerChange(t *testing.T) {
	issuedAt := time.Date(2026, time.July, 22, 15, 0, 0, 0, time.UTC)
	ca, signer := crlDistributorCA(t)
	current := store.SignedCRL{
		Class: store.CertificateClassAgent, Sequence: 1,
		DER: signedCRLFixture(t, ca, signer, 1, issuedAt), IssuedAt: issuedAt,
	}
	source := &crlStateSourceStub{states: map[store.CertificateClass]store.SignedCRL{
		store.CertificateClassAgent: current,
	}}
	distributor, err := NewCRLDistributor(source)
	if err != nil {
		t.Fatalf("create CRL distributor: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	updates, err := distributor.Subscribe(ctx, store.CertificateClassAgent)
	if err != nil {
		t.Fatalf("subscribe to CRL updates: %v", err)
	}
	assertDistributedCRL(t, updates, 1)

	next := store.SignedCRL{
		Class: store.CertificateClassAgent, Sequence: 2,
		DER: signedCRLFixture(t, ca, signer, 2, issuedAt.Add(time.Second)), IssuedAt: issuedAt.Add(time.Second),
	}
	source.states[store.CertificateClassAgent] = next
	if err := distributor.Publish(context.Background(), next); err != nil {
		t.Fatalf("publish next CRL: %v", err)
	}
	assertDistributedCRL(t, updates, 2)
	cancel()
	select {
	case _, open := <-updates:
		if open {
			t.Fatal("CRL subscription remained open after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("CRL subscription did not close after cancellation")
	}
}

func TestCRLDistributor_RejectsMalformedOrNonMonotonicPublication(t *testing.T) {
	issuedAt := time.Date(2026, time.July, 22, 15, 0, 0, 0, time.UTC)
	ca, signer := crlDistributorCA(t)
	current := store.SignedCRL{
		Class: store.CertificateClassAgent, Sequence: 2,
		DER: signedCRLFixture(t, ca, signer, 2, issuedAt), IssuedAt: issuedAt,
	}
	source := &crlStateSourceStub{states: map[store.CertificateClass]store.SignedCRL{
		store.CertificateClassAgent: current,
	}}
	distributor, err := NewCRLDistributor(source)
	if err != nil {
		t.Fatalf("create CRL distributor: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates, err := distributor.Subscribe(ctx, store.CertificateClassAgent)
	if err != nil {
		t.Fatalf("subscribe to CRL updates: %v", err)
	}
	assertDistributedCRL(t, updates, 2)

	tests := []struct {
		name         string
		state        store.SignedCRL
		want         string
		useAsDurable bool
	}{
		{name: "malformed DER", state: store.SignedCRL{Class: store.CertificateClassAgent, Sequence: 3, DER: []byte("bad"), IssuedAt: issuedAt.Add(time.Second)}, want: "control: signed CRL DER is invalid"},
		{name: "stale sequence", state: store.SignedCRL{Class: store.CertificateClassAgent, Sequence: 1, DER: signedCRLFixture(t, ca, signer, 1, issuedAt.Add(-time.Second)), IssuedAt: issuedAt.Add(-time.Second)}, want: "control: CRL sequence 1 is not newer than 2", useAsDurable: true},
		{name: "number mismatch", state: store.SignedCRL{Class: store.CertificateClassAgent, Sequence: 3, DER: signedCRLFixture(t, ca, signer, 4, issuedAt.Add(time.Second)), IssuedAt: issuedAt.Add(time.Second)}, want: "control: signed CRL number does not match durable sequence"},
		{name: "issued-at mismatch", state: store.SignedCRL{Class: store.CertificateClassAgent, Sequence: 3, DER: signedCRLFixture(t, ca, signer, 3, issuedAt.Add(time.Second)), IssuedAt: issuedAt.Add(2 * time.Second)}, want: "control: signed CRL issued-at does not match durable state"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.useAsDurable {
				source.states[store.CertificateClassAgent] = test.state
				defer func() { source.states[store.CertificateClassAgent] = current }()
			}
			if err := distributor.Publish(context.Background(), test.state); err == nil || err.Error() != test.want {
				t.Fatalf("invalid CRL publication error = %v; want %q", err, test.want)
			}
		})
	}
	fork := current
	fork.DER = signedCRLFixture(t, ca, signer, current.Sequence, current.IssuedAt)
	source.states[store.CertificateClassAgent] = fork
	forkContext, cancelFork := context.WithCancel(context.Background())
	defer cancelFork()
	forkUpdates, err := distributor.Subscribe(forkContext, store.CertificateClassAgent)
	if forkUpdates != nil || err == nil || err.Error() != "control: durable CRL changed without advancing its sequence" {
		t.Fatalf("same-sequence durable fork = (%v, %v); want exact rejection", forkUpdates, err)
	}
	source.states[store.CertificateClassAgent] = current
	select {
	case update := <-updates:
		t.Fatalf("rejected publication reached subscriber: %+v", update)
	default:
	}
}

func TestCRLDistributor_SlowSubscriberRetainsNewestWithoutBlockingPublish(t *testing.T) {
	issuedAt := time.Date(2026, time.July, 22, 15, 0, 0, 0, time.UTC)
	ca, signer := crlDistributorCA(t)
	source := &crlStateSourceStub{states: map[store.CertificateClass]store.SignedCRL{}}
	source.states[store.CertificateClassAgent] = store.SignedCRL{
		Class: store.CertificateClassAgent, Sequence: 1,
		DER: signedCRLFixture(t, ca, signer, 1, issuedAt), IssuedAt: issuedAt,
	}
	distributor, err := NewCRLDistributor(source)
	if err != nil {
		t.Fatalf("create CRL distributor: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates, err := distributor.Subscribe(ctx, store.CertificateClassAgent)
	if err != nil {
		t.Fatalf("subscribe to CRL updates: %v", err)
	}

	for sequence := int64(2); sequence <= 3; sequence++ {
		state := store.SignedCRL{
			Class: store.CertificateClassAgent, Sequence: sequence,
			DER:      signedCRLFixture(t, ca, signer, sequence, issuedAt.Add(time.Duration(sequence)*time.Second)),
			IssuedAt: issuedAt.Add(time.Duration(sequence) * time.Second),
		}
		source.states[store.CertificateClassAgent] = state
		if err := distributor.Publish(context.Background(), state); err != nil {
			t.Fatalf("publish CRL sequence %d: %v", sequence, err)
		}
	}
	assertDistributedCRL(t, updates, 3)
	select {
	case update := <-updates:
		t.Fatalf("slow subscriber retained stale extra update: %+v", update)
	default:
	}
}

func TestCRLDistributor_ExactRedeliveryIsIdempotent(t *testing.T) {
	issuedAt := time.Date(2026, time.July, 22, 15, 0, 0, 0, time.UTC)
	ca, signer := crlDistributorCA(t)
	current := store.SignedCRL{
		Class: store.CertificateClassAgent, Sequence: 1,
		DER: signedCRLFixture(t, ca, signer, 1, issuedAt), IssuedAt: issuedAt,
	}
	distributor, err := NewCRLDistributor(&crlStateSourceStub{states: map[store.CertificateClass]store.SignedCRL{
		store.CertificateClassAgent: current,
	}})
	if err != nil {
		t.Fatalf("create CRL distributor: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates, err := distributor.Subscribe(ctx, store.CertificateClassAgent)
	if err != nil {
		t.Fatalf("subscribe to CRL updates: %v", err)
	}
	assertDistributedCRL(t, updates, 1)
	if err := distributor.Publish(context.Background(), current); err != nil {
		t.Fatalf("redeliver exact durable CRL: %v", err)
	}
	select {
	case update := <-updates:
		t.Fatalf("exact CRL redelivery reached subscriber: %+v", update)
	default:
	}
}

func TestCRLDistributor_LegacySourceRejectsIssuerScopedLookup(t *testing.T) {
	issuedAt := time.Date(2026, time.July, 22, 15, 0, 0, 0, time.UTC)
	ca, signer := crlDistributorCA(t)
	current := store.SignedCRL{
		Class: store.CertificateClassAgent, Sequence: 1,
		DER: signedCRLFixture(t, ca, signer, 1, issuedAt), IssuedAt: issuedAt,
	}
	distributor, err := NewCRLDistributor(&crlStateSourceStub{states: map[store.CertificateClass]store.SignedCRL{
		store.CertificateClassAgent: current,
	}})
	if err != nil {
		t.Fatalf("create legacy CRL distributor: %v", err)
	}
	scoped := current
	scoped.IssuerFingerprint = sha256.Sum256(ca.Raw)
	if err := distributor.Publish(context.Background(), scoped); err == nil || err.Error() != "control: read durable CRL before publication: control: legacy CRL source cannot resolve an issuer-scoped publication" {
		t.Fatalf("issuer-scoped publication through legacy source error = %v; want fail-closed adapter rejection", err)
	}
}

type crlStateSourceStub struct {
	states map[store.CertificateClass]store.SignedCRL
}

func (s *crlStateSourceStub) LatestCRL(_ context.Context, class store.CertificateClass) (store.SignedCRL, error) {
	return s.states[class], nil
}

func assertDistributedCRL(t *testing.T, updates <-chan store.SignedCRL, sequence int64) {
	t.Helper()
	select {
	case update := <-updates:
		if update.Sequence != sequence {
			t.Fatalf("distributed CRL sequence = %d; want %d", update.Sequence, sequence)
		}
	case <-time.After(time.Second):
		t.Fatalf("CRL sequence %d was not distributed", sequence)
	}
}

func crlDistributorCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CRL distributor CA key: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatalf("marshal CRL distributor CA key: %v", err)
	}
	keyID := sha256.Sum256(publicDER)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CRL distributor CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: keyID[:20],
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatalf("create CRL distributor CA: %v", err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CRL distributor CA: %v", err)
	}
	return certificate, signer
}

func signedCRLFixture(
	t *testing.T,
	ca *x509.Certificate,
	signer *ecdsa.PrivateKey,
	sequence int64,
	issuedAt time.Time,
) []byte {
	t.Helper()
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(sequence), ThisUpdate: issuedAt, NextUpdate: issuedAt.Add(7 * 24 * time.Hour),
	}, ca, signer)
	if err != nil {
		t.Fatalf("create signed CRL fixture: %v", err)
	}
	return der
}
