package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/manchtools/power-manage/server/internal/store"
)

func TestCRLIssuer_MigrationPublishesIssuerScopedLists(t *testing.T) {
	for _, class := range []store.CertificateClass{store.CertificateClassAgent, store.CertificateClassGateway} {
		t.Run(string(class), func(t *testing.T) {
			fixture := newRotationManagerFixture(t)
			current, successor := fixture.current(class), fixture.successor(class)
			consumer := fixture.seedOppositeConsumer(t, class, "01J00000000000000000000083")
			oldLeaf := fixture.seedLeaf(t, class, "01J00000000000000000000081")
			oldLeaf.certificateDER = replaceRotationLeafSerial(t, oldLeaf.certificateDER, current, oldLeaf.signer, 777)
			fixture.replaceSeededLeafDER(t, oldLeaf)
			fixture.revokeLeaf(t, oldLeaf)

			fixture.beginTrust(t, class, successor)
			trust := fixture.snapshot(t, class)
			fixture.confirmRootConsumer(t, trust, consumer)
			if err := fixture.manager.Migrate(context.Background(), class); err != nil {
				t.Fatalf("enter migrate: %v", err)
			}
			newLeaf := fixture.seedLeaf(t, class, "01J00000000000000000000082")
			newLeaf = fixture.renewLeafFrom(t, newLeaf, successor)
			newLeaf.certificateDER = replaceRotationLeafSerial(t, newLeaf.certificateDER, successor, newLeaf.signer, 777)
			fixture.replaceSeededLeafDER(t, newLeaf)
			fixture.revokeLeaf(t, newLeaf)

			publisher := &crlPublisherStub{}
			issuer, err := NewCRLIssuer(fixture.eventStore, fixture.authorities, publisher)
			if err != nil {
				t.Fatalf("create migration CRL issuer: %v", err)
			}
			issuer.rotationManager = fixture.manager
			issuer.now = fixture.manager.now
			queue, err := store.NewWorkQueue(fixture.pool, issuer.WorkHandlers())
			if err != nil {
				t.Fatalf("create issuer-scoped CRL queue: %v", err)
			}
			for attempts := 0; attempts < 12; attempts++ {
				processed, runErr := queue.RunOnce(context.Background())
				if runErr != nil {
					t.Fatalf("run issuer-scoped CRL work: %v", runErr)
				}
				if !processed {
					break
				}
			}

			oldFingerprint := sha256Fingerprint(current.root.Raw)
			newFingerprint := sha256Fingerprint(successor.root.Raw)
			oldState, err := fixture.eventStore.LatestCRL(context.Background(), class, oldFingerprint)
			if err != nil {
				t.Fatalf("read old-issuer CRL state: %v", err)
			}
			newState, err := fixture.eventStore.LatestCRL(context.Background(), class, newFingerprint)
			if err != nil {
				t.Fatalf("read successor-issuer CRL state: %v", err)
			}
			if oldState.Sequence <= 0 || newState.Sequence <= 0 || oldState.IssuerFingerprint != oldFingerprint || newState.IssuerFingerprint != newFingerprint {
				t.Fatalf("issuer-scoped CRL states = (%+v, %+v); want independent positive sequences and exact issuers", oldState, newState)
			}
			assertIssuerScopedCRL(t, oldState, current.root, 777)
			assertIssuerScopedCRL(t, newState, successor.root, 777)
			if bytes.Equal(oldState.DER, newState.DER) {
				t.Fatal("identical serial numbers under different issuers collapsed into one CRL")
			}
			if len(publisher.published) != 2 || !publishedExactlyOncePerIssuer(publisher.published, class, oldFingerprint, newFingerprint) {
				t.Fatalf("migration CRL publications = %+v; want exactly one per overlapping issuer", publisher.published)
			}

			item := issuerScopedRetryWork(class, newLeaf)
			handler := issuer.HandleAgentCRLWork
			if class == store.CertificateClassGateway {
				handler = issuer.HandleGatewayCRLWork
			}
			beforeRetry := newState.Sequence
			if err := handler(context.Background(), item); err != nil {
				t.Fatalf("retry exact issuer work: %v", err)
			}
			retried, err := fixture.eventStore.LatestCRL(context.Background(), class, newFingerprint)
			if err != nil || retried.Sequence != beforeRetry || !bytes.Equal(retried.DER, newState.DER) {
				t.Fatalf("issuer work retry = (%+v,%v); want exact idempotent state", retried, err)
			}
			receipt, found, err := fixture.eventStore.CRLWorkReceipt(context.Background(), class, newFingerprint, retried.Source)
			if err != nil || !found || receipt != beforeRetry {
				t.Fatalf("issuer work receipt = (%d,%v,%v); want durable exact retry receipt %d", receipt, found, err, beforeRetry)
			}
		})
	}
}

func publishedExactlyOncePerIssuer(publications []store.SignedCRL, class store.CertificateClass, issuers ...[sha256.Size]byte) bool {
	counts := make(map[[sha256.Size]byte]int, len(issuers))
	for _, publication := range publications {
		if publication.Class != class {
			return false
		}
		counts[publication.IssuerFingerprint]++
	}
	for _, issuer := range issuers {
		if counts[issuer] != 1 {
			return false
		}
	}
	return len(counts) == len(issuers)
}

func issuerScopedRetryWork(class store.CertificateClass, reporter rotationReporter) store.WorkItem {
	kind, streamType := store.PublishAgentCRLWorkKind, "device"
	if class == store.CertificateClassGateway {
		kind, streamType = store.PublishGatewayCRLWorkKind, "gateway"
	}
	return store.WorkItem{
		Work: store.Work{Kind: kind, PayloadVersion: 1, Payload: []byte(`{}`)}, SourceStreamType: streamType,
		SourceStreamID: reporter.id, SourceStreamVersion: 3,
	}
}

func (f *rotationManagerFixture) replaceSeededLeafDER(t *testing.T, reporter rotationReporter) {
	t.Helper()
	fingerprint := sha256Fingerprint(reporter.certificateDER)
	table := "devices"
	idColumn := "device_id"
	if reporter.class == store.CertificateClassGateway {
		table = "gateways"
		idColumn = "gateway_id"
	}
	query := "UPDATE " + table + " SET certificate_der = $2, certificate_fingerprint = $3 WHERE " + idColumn + " = $1"
	if _, err := f.pool.Exec(context.Background(), query, reporter.id, reporter.certificateDER, fingerprint[:]); err != nil {
		t.Fatalf("replace seeded leaf fixture DER: %v", err)
	}
}

func replaceRotationLeafSerial(
	t *testing.T,
	certificateDER []byte,
	authority rotationCA,
	signer crypto.Signer,
	serial int64,
) []byte {
	t.Helper()
	certificate, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("parse leaf for serial replacement: %v", err)
	}
	template := *certificate
	template.SerialNumber = big.NewInt(serial)
	template.Raw = nil
	der, err := x509.CreateCertificate(rand.Reader, &template, authority.root, signer.Public(), authority.signer)
	if err != nil {
		t.Fatalf("replace leaf serial: %v", err)
	}
	return der
}

func assertIssuerScopedCRL(t *testing.T, state store.SignedCRL, issuer *x509.Certificate, serial int64) {
	t.Helper()
	list, err := x509.ParseRevocationList(state.DER)
	if err != nil {
		t.Fatalf("parse issuer-scoped CRL: %v", err)
	}
	if err := list.CheckSignatureFrom(issuer); err != nil {
		t.Fatalf("verify issuer-scoped CRL: %v", err)
	}
	count := 0
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(big.NewInt(serial)) == 0 {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("issuer-scoped CRL contains serial %d %d times; want once", serial, count)
	}
}

func sha256Fingerprint(der []byte) [32]byte {
	return sha256.Sum256(der)
}
