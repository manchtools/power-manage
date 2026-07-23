package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/contract/sign"
	"github.com/manchtools/power-manage/server/internal/store"
)

func TestRotationManager_TransitionsAbortNormalizeAndRotateAgain(t *testing.T) {
	exerciseCanonicalRotationBundles(t)
	exerciseInvalidRotationAttempts(t)
	exerciseRotationAppendFailure(t)

	fixture := newRotationManagerFixture(t)
	reporter := fixture.seedGatewayConsumer(t, "01J00000000000000000000031")
	initial := fixture.snapshot(t, store.CertificateClassAgent)
	assertRotationState(t, initial, RotationPhaseStable, 1, 1, fixture.agentCurrent.root.Raw)

	fixture.beginTrust(t, store.CertificateClassAgent, fixture.agentSuccessor)
	trust := fixture.snapshot(t, store.CertificateClassAgent)
	assertRotationState(t, trust, RotationPhaseTrust, 2, 1, fixture.agentCurrent.root.Raw, fixture.agentSuccessor.root.Raw)
	if !bytes.Equal(trust.IssuingRootDER, fixture.agentCurrent.root.Raw) {
		t.Fatal("trust phase stopped issuing from the current root")
	}
	fixture.confirmRootConsumer(t, trust, reporter)

	if err := fixture.manager.Abort(context.Background(), store.CertificateClassAgent); err != nil {
		t.Fatalf("abort trust phase: %v", err)
	}
	aborting := fixture.snapshot(t, store.CertificateClassAgent)
	assertRotationState(t, aborting, RotationPhaseTrust, 2, 2, fixture.agentCurrent.root.Raw)
	if !bytes.Equal(aborting.IssuingRootDER, fixture.agentCurrent.root.Raw) || len(aborting.TransitionCertificateDER) != 0 {
		t.Fatal("abort left abandoned successor material usable")
	}
	fixture.confirmRootConsumer(t, aborting, reporter)
	if err := fixture.manager.Normalize(context.Background(), store.CertificateClassAgent); err != nil {
		t.Fatalf("complete abort normalization: %v", err)
	}
	aborted := fixture.snapshot(t, store.CertificateClassAgent)
	assertRotationState(t, aborted, RotationPhaseStable, 2, 2, fixture.agentCurrent.root.Raw)
	abandonedFingerprint := sha256.Sum256(fixture.agentSuccessor.root.Raw)
	if _, ok := fixture.authorities.authorityForIssuer(store.CertificateClassAgent, abandonedFingerprint); ok {
		t.Fatal("successful abort left the abandoned successor signer usable by issuer lookup")
	}
	lastAbortPublication := fixture.distributor.publications[len(fixture.distributor.publications)-1]
	if containsRotationDER(lastAbortPublication.RootCertificateDER, fixture.agentSuccessor.root.Raw) ||
		len(lastAbortPublication.TransitionCertificateDER) != 0 ||
		slices.Contains(lastAbortPublication.CRLIssuerFingerprints, abandonedFingerprint) {
		t.Fatal("successful abort left abandoned root, proof, or CRL usable in the published authority snapshot")
	}

	third := newRotationCA(t, "agent generation three", fixture.now)
	fixture.beginTrust(t, store.CertificateClassAgent, third)
	secondTrust := fixture.snapshot(t, store.CertificateClassAgent)
	assertRotationState(t, secondTrust, RotationPhaseTrust, 3, 1, fixture.agentCurrent.root.Raw, third.root.Raw)
	if err := fixture.manager.Migrate(context.Background(), store.CertificateClassAgent); err == nil {
		t.Fatal("generation-three migration reused the generation-two consumer confirmation")
	}
	if err := fixture.confirm(t, reporter, consumerClaim(secondTrust, reporter)); err != nil {
		t.Fatalf("confirm generation-three trust bundle: %v", err)
	}
	if err := fixture.manager.Migrate(context.Background(), store.CertificateClassAgent); err != nil {
		t.Fatalf("enter migrate: %v", err)
	}
	migrating := fixture.snapshot(t, store.CertificateClassAgent)
	assertRotationState(t, migrating, RotationPhaseMigrate, 3, 1, fixture.agentCurrent.root.Raw, third.root.Raw)
	if !bytes.Equal(migrating.IssuingRootDER, third.root.Raw) || len(migrating.TransitionCertificateDER) == 0 {
		t.Fatal("migrate did not atomically select successor issuance and retain its proof")
	}
	if err := fixture.manager.Abort(context.Background(), store.CertificateClassAgent); err == nil {
		t.Fatal("migrate accepted the trust-only abort transition")
	}
	if err := fixture.manager.Retire(context.Background(), store.CertificateClassAgent); err != nil {
		t.Fatalf("enter retire with no non-revoked leaves: %v", err)
	}
	retiring := fixture.snapshot(t, store.CertificateClassAgent)
	assertRotationState(t, retiring, RotationPhaseRetire, 3, 2, third.root.Raw)
	fixture.confirmRootConsumer(t, retiring, reporter)
	if err := fixture.manager.Normalize(context.Background(), store.CertificateClassAgent); err != nil {
		t.Fatalf("normalize successor: %v", err)
	}
	stable := fixture.snapshot(t, store.CertificateClassAgent)
	assertRotationState(t, stable, RotationPhaseStable, 3, 2, third.root.Raw)
	if len(stable.TransitionCertificateDER) != 0 || len(stable.PredecessorRootDER) != 0 {
		t.Fatal("normalized stable state retained predecessor or transition material")
	}
}

func exerciseCanonicalRotationBundles(t *testing.T) {
	t.Helper()
	for _, class := range []store.CertificateClass{store.CertificateClassAgent, store.CertificateClassGateway} {
		t.Run(string(class)+" canonical bundle graph", func(t *testing.T) {
			fixture := newRotationManagerFixture(t)
			current, successor := fixture.current(class), fixture.successor(class)
			stable := fixture.snapshot(t, class)
			assertRotationState(t, stable, RotationPhaseStable, 1, 1, current.root.Raw)
			fixture.beginTrust(t, class, successor)
			trust := fixture.snapshot(t, class)
			assertRotationState(t, trust, RotationPhaseTrust, 2, 1, current.root.Raw, successor.root.Raw)
			if !bytes.Equal(trust.IssuingRootDER, current.root.Raw) || len(trust.TransitionCertificateDER) == 0 {
				t.Fatal("trust did not retain current issuance and exact transition proof")
			}
			if class == store.CertificateClassGateway {
				fixture.confirmControlForGatewayRoots(t, trust)
			}
			if err := fixture.manager.Migrate(context.Background(), class); err != nil {
				t.Fatalf("Migrate canonical %s graph: %v", class, err)
			}
			migrate := fixture.snapshot(t, class)
			assertRotationState(t, migrate, RotationPhaseMigrate, 2, 1, current.root.Raw, successor.root.Raw)
			if !bytes.Equal(migrate.IssuingRootDER, successor.root.Raw) || !bytes.Equal(migrate.TransitionCertificateDER, trust.TransitionCertificateDER) {
				t.Fatal("migrate changed canonical order/proof or failed to select successor issuer")
			}
			if err := fixture.manager.Retire(context.Background(), class); err != nil {
				t.Fatalf("Retire canonical %s graph: %v", class, err)
			}
			retire := fixture.snapshot(t, class)
			assertRotationState(t, retire, RotationPhaseRetire, 2, 2, successor.root.Raw)
			if len(retire.PredecessorRootDER) == 0 {
				t.Fatal("retire stopped retaining predecessor material before prune confirmations")
			}
			if class == store.CertificateClassGateway {
				fixture.confirmControlForGatewayRoots(t, retire)
			}
			if err := fixture.manager.Normalize(context.Background(), class); err != nil {
				t.Fatalf("Normalize canonical %s graph: %v", class, err)
			}
			assertRotationState(t, fixture.snapshot(t, class), RotationPhaseStable, 2, 2, successor.root.Raw)
			predecessorFingerprint := sha256.Sum256(current.root.Raw)
			if _, ok := fixture.authorities.authorityForIssuer(class, predecessorFingerprint); ok {
				t.Fatalf("normalized %s rotation left predecessor issuer/signer usable", class)
			}
			successorFingerprint := sha256.Sum256(successor.root.Raw)
			if authority, ok := fixture.authorities.authorityForIssuer(class, successorFingerprint); !ok ||
				!bytes.Equal(authority.certificate.Raw, successor.root.Raw) {
				t.Fatalf("normalized %s rotation lost exact successor issuer/signer", class)
			}
		})

		t.Run(string(class)+" canonical abort bundle", func(t *testing.T) {
			fixture := newRotationManagerFixture(t)
			current := fixture.current(class)
			successor := fixture.successor(class)
			consumer := fixture.seedOppositeConsumer(t, class, "01J00000000000000000000032")
			fixture.beginTrust(t, class, successor)
			if err := fixture.manager.Abort(context.Background(), class); err != nil {
				t.Fatalf("Abort %s trust: %v", class, err)
			}
			abort := fixture.snapshot(t, class)
			assertRotationState(t, abort, RotationPhaseTrust, 2, 2, current.root.Raw)
			if len(abort.TransitionCertificateDER) != 0 || len(abort.SuccessorRootDER) != 0 {
				t.Fatal("abort desired bundle or effective snapshot retained abandoned successor material")
			}
			fixture.confirmRootConsumer(t, abort, consumer)
			if err := fixture.manager.Normalize(context.Background(), class); err != nil {
				t.Fatalf("normalize canonical %s abort: %v", class, err)
			}
			abandonedFingerprint := sha256.Sum256(successor.root.Raw)
			if _, ok := fixture.authorities.authorityForIssuer(class, abandonedFingerprint); ok {
				t.Fatalf("normalized %s abort left abandoned issuer/signer usable", class)
			}
			publication := fixture.distributor.publications[len(fixture.distributor.publications)-1]
			if containsRotationDER(publication.RootCertificateDER, successor.root.Raw) ||
				len(publication.TransitionCertificateDER) != 0 ||
				slices.Contains(publication.CRLIssuerFingerprints, abandonedFingerprint) {
				t.Fatalf("normalized %s abort published abandoned root, proof, or CRL", class)
			}
		})
	}
}

func exerciseInvalidRotationAttempts(t *testing.T) {
	t.Helper()
	t.Run("invalid edges preserve all observable state", func(t *testing.T) {
		for _, class := range []store.CertificateClass{store.CertificateClassAgent, store.CertificateClassGateway} {
			fixture := newRotationManagerFixture(t)
			for name, attempt := range map[string]func() error{
				"stable abort":     func() error { return fixture.manager.Abort(context.Background(), class) },
				"stable migrate":   func() error { return fixture.manager.Migrate(context.Background(), class) },
				"stable retire":    func() error { return fixture.manager.Retire(context.Background(), class) },
				"stable normalize": func() error { return fixture.manager.Normalize(context.Background(), class) },
			} {
				assertRotationAttemptRejectedWithoutEffects(t, &fixture, class, name, attempt)
			}

			fixture.beginTrust(t, class, fixture.successor(class))
			trustInvalid := map[string]func() error{
				"trust begin": func() error {
					return fixture.manager.BeginTrust(context.Background(), class, fixture.successor(class).root.Raw, crossSignRotationCA(t, fixture.current(class), fixture.successor(class)), fixture.successor(class).signer)
				},
				"trust retire":    func() error { return fixture.manager.Retire(context.Background(), class) },
				"trust normalize": func() error { return fixture.manager.Normalize(context.Background(), class) },
			}
			if class == store.CertificateClassGateway {
				trustInvalid["trust gated migrate"] = func() error { return fixture.manager.Migrate(context.Background(), class) }
			}
			for name, attempt := range trustInvalid {
				assertRotationAttemptRejectedWithoutEffects(t, &fixture, class, name, attempt)
			}
			trust := fixture.snapshot(t, class)
			if class == store.CertificateClassGateway {
				fixture.confirmControlForGatewayRoots(t, trust)
			}
			if err := fixture.manager.Migrate(context.Background(), class); err != nil {
				t.Fatalf("enter migrate for invalid-edge matrix: %v", err)
			}
			for name, attempt := range map[string]func() error{
				"migrate begin": func() error {
					return fixture.manager.BeginTrust(context.Background(), class, fixture.successor(class).root.Raw, crossSignRotationCA(t, fixture.current(class), fixture.successor(class)), fixture.successor(class).signer)
				},
				"migrate abort":     func() error { return fixture.manager.Abort(context.Background(), class) },
				"migrate again":     func() error { return fixture.manager.Migrate(context.Background(), class) },
				"migrate normalize": func() error { return fixture.manager.Normalize(context.Background(), class) },
			} {
				assertRotationAttemptRejectedWithoutEffects(t, &fixture, class, name, attempt)
			}
			if err := fixture.manager.Retire(context.Background(), class); err != nil {
				t.Fatalf("enter retire for invalid-edge matrix: %v", err)
			}
			retireInvalid := map[string]func() error{
				"retire begin": func() error {
					return fixture.manager.BeginTrust(context.Background(), class, fixture.successor(class).root.Raw, crossSignRotationCA(t, fixture.current(class), fixture.successor(class)), fixture.successor(class).signer)
				},
				"retire abort":   func() error { return fixture.manager.Abort(context.Background(), class) },
				"retire migrate": func() error { return fixture.manager.Migrate(context.Background(), class) },
				"retire again":   func() error { return fixture.manager.Retire(context.Background(), class) },
			}
			if class == store.CertificateClassGateway {
				retireInvalid["retire gated normalize"] = func() error { return fixture.manager.Normalize(context.Background(), class) }
			}
			for name, attempt := range retireInvalid {
				assertRotationAttemptRejectedWithoutEffects(t, &fixture, class, name, attempt)
			}
		}
	})

	t.Run("invalid BeginTrust payloads start from valid stable state", func(t *testing.T) {
		for _, class := range []store.CertificateClass{store.CertificateClassAgent, store.CertificateClassGateway} {
			for _, test := range []struct {
				name   string
				root   func(*rotationManagerFixture) []byte
				proof  func(*rotationManagerFixture) []byte
				signer func(*rotationManagerFixture) crypto.Signer
			}{
				{name: "empty root", root: func(*rotationManagerFixture) []byte { return nil }},
				{name: "malformed root", root: func(*rotationManagerFixture) []byte { return []byte("not DER") }},
				{name: "trailing root DER", root: func(f *rotationManagerFixture) []byte { return append(bytes.Clone(f.successor(class).root.Raw), 0) }},
				{name: "non-self-issued root", root: func(f *rotationManagerFixture) []byte {
					return crossSignRotationCA(t, f.current(class), f.successor(class))
				}},
				{name: "bad root self-signature", root: func(f *rotationManagerFixture) []byte {
					der := bytes.Clone(f.successor(class).root.Raw)
					der[len(der)-1] ^= 0xff
					return der
				}},
				{name: "current root reused", root: func(f *rotationManagerFixture) []byte { return f.current(class).root.Raw }},
				{name: "missing proof", proof: func(*rotationManagerFixture) []byte { return nil }},
				{name: "malformed proof", proof: func(*rotationManagerFixture) []byte { return []byte("not DER") }},
				{name: "trailing proof DER", proof: func(f *rotationManagerFixture) []byte {
					return append(crossSignRotationCA(t, f.current(class), f.successor(class)), 0)
				}},
				{name: "proof subject drift", proof: func(f *rotationManagerFixture) []byte {
					return crossSignRotationCAWithMutation(t, f.current(class), f.successor(class), func(c *x509.Certificate) { c.Subject.CommonName = "drift" })
				}},
				{name: "proof public key drift", proof: func(f *rotationManagerFixture) []byte {
					return crossSignRotationCAWithPublicKey(t, f.current(class), f.successor(class), newEnrollmentSigningKey(t).Public(), nil)
				}},
				{name: "proof SKI drift", proof: func(f *rotationManagerFixture) []byte {
					return crossSignRotationCAWithMutation(t, f.current(class), f.successor(class), func(c *x509.Certificate) { c.SubjectKeyId = []byte("drift") })
				}},
				{name: "proof CA constraint drift", proof: func(f *rotationManagerFixture) []byte {
					return crossSignRotationCAWithMutation(t, f.current(class), f.successor(class), func(c *x509.Certificate) { c.IsCA = false })
				}},
				{name: "proof basic constraints drift", proof: func(f *rotationManagerFixture) []byte {
					return crossSignRotationCAWithMutation(t, f.current(class), f.successor(class), func(c *x509.Certificate) { c.BasicConstraintsValid = false })
				}},
				{name: "proof path length drift", proof: func(f *rotationManagerFixture) []byte {
					return crossSignRotationCAWithMutation(t, f.current(class), f.successor(class), func(c *x509.Certificate) { c.MaxPathLen = 1; c.MaxPathLenZero = false })
				}},
				{name: "proof usage drift", proof: func(f *rotationManagerFixture) []byte {
					return crossSignRotationCAWithMutation(t, f.current(class), f.successor(class), func(c *x509.Certificate) { c.KeyUsage &^= x509.KeyUsageCRLSign })
				}},
				{name: "proof issuer drift", proof: func(f *rotationManagerFixture) []byte {
					parent := f.current(class)
					copy := *parent.root
					copy.RawSubject = nil
					copy.Subject.CommonName = "drift"
					parent.root = &copy
					return crossSignRotationCA(t, parent, f.successor(class))
				}},
				{name: "proof AKI drift", proof: func(f *rotationManagerFixture) []byte {
					return crossSignRotationCAWithMutation(t, f.current(class), f.successor(class), func(c *x509.Certificate) {
						value, err := asn1.Marshal(struct {
							KeyIdentifier []byte `asn1:"tag:0,optional"`
						}{KeyIdentifier: []byte("drift")})
						if err != nil {
							t.Fatalf("marshal drifted authority key identifier: %v", err)
						}
						c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Value: value}}
					})
				}},
				{name: "proof unsupported critical extension", proof: func(f *rotationManagerFixture) []byte {
					return crossSignRotationCAWithMutation(t, f.current(class), f.successor(class), func(c *x509.Certificate) {
						c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 6006}, Critical: true, Value: []byte{5, 0}}}
					})
				}},
				{name: "proof not yet valid", proof: func(f *rotationManagerFixture) []byte {
					return crossSignRotationCAWithMutation(t, f.current(class), f.successor(class), func(c *x509.Certificate) { c.NotBefore = f.now.Add(time.Hour); c.NotAfter = f.now.Add(2 * time.Hour) })
				}},
				{name: "proof expired", proof: func(f *rotationManagerFixture) []byte {
					return crossSignRotationCAWithMutation(t, f.current(class), f.successor(class), func(c *x509.Certificate) { c.NotBefore = f.now.Add(-2 * time.Hour); c.NotAfter = f.now.Add(-time.Hour) })
				}},
				{name: "other-class proof", proof: func(f *rotationManagerFixture) []byte {
					other := store.CertificateClassAgent
					if class == store.CertificateClassAgent {
						other = store.CertificateClassGateway
					}
					return crossSignRotationCA(t, f.current(other), f.successor(other))
				}},
				{name: "wrong signer", signer: func(f *rotationManagerFixture) crypto.Signer { return f.current(class).signer }},
				{name: "nil signer", signer: func(*rotationManagerFixture) crypto.Signer { return nil }},
			} {
				t.Run(string(class)+"/"+test.name, func(t *testing.T) {
					fixture := newRotationManagerFixture(t)
					root := fixture.successor(class).root.Raw
					proof := crossSignRotationCA(t, fixture.current(class), fixture.successor(class))
					signer := fixture.successor(class).signer
					if test.root != nil {
						root = test.root(&fixture)
					}
					if test.proof != nil {
						proof = test.proof(&fixture)
					}
					if test.signer != nil {
						signer = test.signer(&fixture)
					}
					assertRotationAttemptRejectedWithoutEffects(t, &fixture, class, test.name, func() error {
						return fixture.manager.BeginTrust(context.Background(), class, root, proof, signer)
					}, root)
				})
			}
		}
		fixture := newRotationManagerFixture(t)
		candidate := fixture.agentSuccessor.root.Raw
		agentBefore := captureRotationObservableState(t, &fixture, store.CertificateClassAgent, candidate)
		gatewayBefore := captureRotationObservableState(t, &fixture, store.CertificateClassGateway, candidate)
		if err := fixture.manager.BeginTrust(context.Background(), store.CertificateClass("operator"),
			candidate, crossSignRotationCA(t, fixture.agentCurrent, fixture.agentSuccessor), fixture.agentSuccessor.signer); err == nil {
			t.Fatal("BeginTrust accepted an unknown certificate class")
		}
		if !reflect.DeepEqual(agentBefore, captureRotationObservableState(t, &fixture, store.CertificateClassAgent, candidate)) ||
			!reflect.DeepEqual(gatewayBefore, captureRotationObservableState(t, &fixture, store.CertificateClassGateway, candidate)) {
			t.Fatal("unknown-class BeginTrust changed a valid class")
		}
	})
}

func exerciseRotationAppendFailure(t *testing.T) {
	t.Helper()
	t.Run("event append failure is pre-commit", func(t *testing.T) {
		fixture := newRotationManagerFixture(t)
		if _, err := fixture.pool.Exec(context.Background(), `
			CREATE FUNCTION reject_spec006_rotation_append() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN
				IF NEW.stream_type = 'ca-rotation' THEN RAISE EXCEPTION 'forced rotation append failure'; END IF;
				RETURN NEW;
			END $$;
			CREATE TRIGGER reject_spec006_rotation_append BEFORE INSERT ON events
			FOR EACH ROW EXECUTE FUNCTION reject_spec006_rotation_append()`); err != nil {
			t.Fatalf("install append-failure trigger: %v", err)
		}
		assertRotationAttemptRejectedWithoutEffects(t, &fixture, store.CertificateClassAgent, "event append failure", func() error {
			return fixture.manager.BeginTrust(context.Background(), store.CertificateClassAgent,
				fixture.agentSuccessor.root.Raw, crossSignRotationCA(t, fixture.agentCurrent, fixture.agentSuccessor), fixture.agentSuccessor.signer)
		}, fixture.agentSuccessor.root.Raw)
	})
}

func TestRotationManager_ConsumerBundlesGateMigrateAbortAndNormalize(t *testing.T) {
	exerciseRotationRoleMatrix(t)
	exercisePkiServiceTrustConfirmationHandlers(t)

	t.Run("migrate gate includes offline durable consumers and exact CRL receipts", func(t *testing.T) {
		fixture := newRotationManagerFixture(t)
		reporter := fixture.seedGatewayConsumer(t, "01J00000000000000000000041")
		fixture.beginTrust(t, store.CertificateClassAgent, fixture.agentSuccessor)
		trust := fixture.snapshot(t, store.CertificateClassAgent)
		if err := fixture.manager.Migrate(context.Background(), store.CertificateClassAgent); err == nil || !strings.Contains(err.Error(), reporter.id) {
			t.Fatalf("Migrate with offline consumer error = %v; want durable reporter gate", err)
		}
		assertAuthoritySnapshotsEqual(t, fixture.snapshot(t, store.CertificateClassAgent), trust)

		invalid := []struct {
			name   string
			mutate func(*sign.TrustStateClaim)
		}{
			{name: "stale generation", mutate: func(c *sign.TrustStateClaim) { c.Generation-- }},
			{name: "wrong revision", mutate: func(c *sign.TrustStateClaim) { c.Revision++ }},
			{name: "wrong root order", mutate: func(c *sign.TrustStateClaim) {
				c.RootFingerprints[0], c.RootFingerprints[1] = c.RootFingerprints[1], c.RootFingerprints[0]
			}},
			{name: "cross-class receipt", mutate: func(c *sign.TrustStateClaim) { c.ClaimedClass = "gateway" }},
			{name: "cross-issuer receipt", mutate: func(c *sign.TrustStateClaim) { c.CRLIssuerFingerprint[0] ^= 0xff }},
			{name: "below baseline receipt", mutate: func(c *sign.TrustStateClaim) { c.CRLSequence = trust.RequiredCRLSequence - 1 }},
			{name: "beyond published receipt", mutate: func(c *sign.TrustStateClaim) { c.CRLSequence = trust.PublishedCRLSequence + 1 }},
		}
		for _, test := range invalid {
			t.Run(test.name, func(t *testing.T) {
				claim := consumerClaim(trust, reporter)
				test.mutate(&claim)
				if err := fixture.confirm(t, reporter, claim); !errors.Is(err, ErrTrustStateRejected) {
					t.Fatalf("ConfirmTrustState error = %v; want %v", err, ErrTrustStateRejected)
				}
			})
		}
		if err := fixture.confirm(t, reporter, consumerClaim(trust, reporter)); err != nil {
			t.Fatalf("confirm exact offline consumer state: %v", err)
		}
		if err := fixture.manager.Migrate(context.Background(), store.CertificateClassAgent); err != nil {
			t.Fatalf("Migrate after every exact confirmation: %v", err)
		}
	})

	t.Run("revocation is the only consumer exclusion", func(t *testing.T) {
		fixture := newRotationManagerFixture(t)
		reporter := fixture.seedGatewayConsumer(t, "01J00000000000000000000042")
		next := newRotationCA(t, "post-abort successor", fixture.now)
		fixture.beginTrust(t, store.CertificateClassAgent, next)
		fixture.revokeGateway(t, reporter)
		if err := fixture.manager.Migrate(context.Background(), store.CertificateClassAgent); err != nil {
			t.Fatalf("Migrate after sole offline consumer revocation: %v", err)
		}
	})

	t.Run("abort and retirement each require exact prune confirmations", func(t *testing.T) {
		fixture := newRotationManagerFixture(t)
		reporter := fixture.seedGatewayConsumer(t, "01J00000000000000000000043")
		fixture.beginTrust(t, store.CertificateClassAgent, fixture.agentSuccessor)
		trust := fixture.snapshot(t, store.CertificateClassAgent)
		fixture.confirmRootConsumer(t, trust, reporter)
		if err := fixture.manager.Abort(context.Background(), store.CertificateClassAgent); err != nil {
			t.Fatalf("begin abort: %v", err)
		}
		aborting := fixture.snapshot(t, store.CertificateClassAgent)
		if err := fixture.manager.Normalize(context.Background(), store.CertificateClassAgent); err == nil {
			t.Fatal("abort normalized before the offline consumer pruned the successor")
		}
		if err := fixture.confirm(t, reporter, consumerClaim(aborting, reporter)); err != nil {
			t.Fatalf("confirm abort prune: %v", err)
		}
		if err := fixture.manager.Normalize(context.Background(), store.CertificateClassAgent); err != nil {
			t.Fatalf("normalize abort after exact prune confirmations: %v", err)
		}

		postAbortSuccessor := newRotationCA(t, "post-abort successor", fixture.now)
		fixture.beginTrust(t, store.CertificateClassAgent, postAbortSuccessor)
		trust = fixture.snapshot(t, store.CertificateClassAgent)
		fixture.confirmRootConsumer(t, trust, reporter)
		if err := fixture.manager.Migrate(context.Background(), store.CertificateClassAgent); err != nil {
			t.Fatalf("enter migrate: %v", err)
		}
		if err := fixture.manager.Retire(context.Background(), store.CertificateClassAgent); err != nil {
			t.Fatalf("enter retire: %v", err)
		}
		retire := fixture.snapshot(t, store.CertificateClassAgent)
		if err := fixture.manager.Normalize(context.Background(), store.CertificateClassAgent); err == nil {
			t.Fatal("retirement normalized before the offline consumer pruned the predecessor")
		}
		if err := fixture.confirm(t, reporter, consumerClaim(retire, reporter)); err != nil {
			t.Fatalf("confirm predecessor prune: %v", err)
		}
		if err := fixture.manager.Normalize(context.Background(), store.CertificateClassAgent); err != nil {
			t.Fatalf("normalize retire after exact prune confirmations: %v", err)
		}
	})

	t.Run("reporter rejection is uniform and exact replay is idempotent", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(*testing.T, *rotationManagerFixture, *rotationReporter, *TrustStateConfirmation)
		}{
			{name: "unknown reporter", mutate: func(t *testing.T, f *rotationManagerFixture, _ *rotationReporter, confirmation *TrustStateConfirmation) {
				unknown := f.unstoredGatewayReporter(t, "01J00000000000000000000044")
				confirmation.ReporterCertificateDER = unknown.certificateDER
				confirmation.Signature = signRotationClaim(t, unknown.signer, confirmation.Claim)
			}},
			{name: "revoked reporter", mutate: func(t *testing.T, f *rotationManagerFixture, reporter *rotationReporter, _ *TrustStateConfirmation) {
				f.revokeGateway(t, *reporter)
			}},
			{name: "superseded reporter certificate", mutate: func(t *testing.T, f *rotationManagerFixture, reporter *rotationReporter, _ *TrustStateConfirmation) {
				_ = f.renewLeafFrom(t, *reporter, f.gatewayCurrent)
			}},
			{name: "same-key renewed certificate substituted for signed certificate", mutate: func(t *testing.T, f *rotationManagerFixture, reporter *rotationReporter, confirmation *TrustStateConfirmation) {
				renewed := f.renewLeafFrom(t, *reporter, f.gatewayCurrent)
				confirmation.ReporterCertificateDER = renewed.certificateDER
				// Keep the original claim and signature: the public key is the same,
				// so only the covered certificate fingerprint detects substitution.
			}},
			{name: "absent reporter certificate fingerprint", mutate: func(t *testing.T, _ *rotationManagerFixture, reporter *rotationReporter, confirmation *TrustStateConfirmation) {
				confirmation.Claim.ReporterCertificateFingerprint = nil
				confirmation.Signature = signRotationClaim(t, reporter.signer, confirmation.Claim)
			}},
			{name: "malformed reporter certificate fingerprint", mutate: func(t *testing.T, _ *rotationManagerFixture, reporter *rotationReporter, confirmation *TrustStateConfirmation) {
				confirmation.Claim.ReporterCertificateFingerprint = []byte{1}
				confirmation.Signature = signRotationClaim(t, reporter.signer, confirmation.Claim)
			}},
			{name: "absent signature", mutate: func(_ *testing.T, _ *rotationManagerFixture, _ *rotationReporter, confirmation *TrustStateConfirmation) {
				confirmation.Signature = nil
			}},
			{name: "malformed signature", mutate: func(_ *testing.T, _ *rotationManagerFixture, _ *rotationReporter, confirmation *TrustStateConfirmation) {
				confirmation.Signature = []byte("not ASN.1")
			}},
			{name: "wrong reporter key", mutate: func(t *testing.T, f *rotationManagerFixture, _ *rotationReporter, confirmation *TrustStateConfirmation) {
				other := f.unstoredGatewayReporter(t, "01J00000000000000000000045")
				confirmation.Signature = signRotationClaim(t, other.signer, confirmation.Claim)
			}},
			{name: "wrong generation", mutate: func(t *testing.T, _ *rotationManagerFixture, reporter *rotationReporter, confirmation *TrustStateConfirmation) {
				confirmation.Claim.Generation--
				confirmation.Signature = signRotationClaim(t, reporter.signer, confirmation.Claim)
			}},
		}
		var rejection string
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				fixture := newRotationManagerFixture(t)
				reporter := fixture.seedGatewayConsumer(t, "01J00000000000000000000046")
				fixture.beginTrust(t, store.CertificateClassAgent, fixture.agentSuccessor)
				state := fixture.snapshot(t, store.CertificateClassAgent)
				claim := consumerClaim(state, reporter)
				confirmation := TrustStateConfirmation{
					ReporterCertificateDER: bytes.Clone(reporter.certificateDER), Claim: claim,
					Signature: signRotationClaim(t, reporter.signer, claim),
				}
				test.mutate(t, &fixture, &reporter, &confirmation)
				beforeEvents := rotationConfirmationEventCount(t, fixture.pool)
				err := fixture.manager.ConfirmTrustState(context.Background(), confirmation)
				if !errors.Is(err, ErrTrustStateRejected) {
					t.Fatalf("ConfirmTrustState error = %v; want uniform rejection sentinel", err)
				}
				if rejection == "" {
					rejection = err.Error()
				} else if err.Error() != rejection {
					t.Fatalf("external rejection = %q; want anti-enumerating %q", err, rejection)
				}
				if got := rotationConfirmationEventCount(t, fixture.pool); got != beforeEvents {
					t.Fatalf("rejected confirmation events = %d; want unchanged %d", got, beforeEvents)
				}
			})
		}

		fixture := newRotationManagerFixture(t)
		reporter := fixture.seedGatewayConsumer(t, "01J00000000000000000000047")
		fixture.beginTrust(t, store.CertificateClassAgent, fixture.agentSuccessor)
		claim := consumerClaim(fixture.snapshot(t, store.CertificateClassAgent), reporter)
		confirmation := TrustStateConfirmation{
			ReporterCertificateDER: reporter.certificateDER, Claim: claim,
			Signature: signRotationClaim(t, reporter.signer, claim),
		}
		if err := fixture.manager.ConfirmTrustState(context.Background(), confirmation); err != nil {
			t.Fatalf("first exact confirmation: %v", err)
		}
		events := rotationConfirmationEventCount(t, fixture.pool)
		if err := fixture.manager.ConfirmTrustState(context.Background(), confirmation); err != nil {
			t.Fatalf("exact confirmation replay: %v", err)
		}
		if got := rotationConfirmationEventCount(t, fixture.pool); got != events {
			t.Fatalf("exact replay appended %d events; want idempotent %d", got, events)
		}
	})

	t.Run("unavailable bundle distributor leaves durable state and snapshot unchanged", func(t *testing.T) {
		fixture := newRotationManagerFixture(t)
		fixture.distributor.err = errors.New("remote bundle distributor unavailable")
		assertRotationAttemptRejectedWithoutEffects(t, &fixture, store.CertificateClassGateway, "bundle distributor failure", func() error {
			return fixture.manager.BeginTrust(
				context.Background(), store.CertificateClassGateway,
				fixture.gatewaySuccessor.root.Raw,
				crossSignRotationCA(t, fixture.gatewayCurrent, fixture.gatewaySuccessor),
				fixture.gatewaySuccessor.signer,
			)
		}, fixture.gatewaySuccessor.root.Raw)
	})
}

func exerciseRotationRoleMatrix(t *testing.T) {
	t.Helper()
	for _, class := range []store.CertificateClass{store.CertificateClassAgent, store.CertificateClassGateway} {
		t.Run(string(class)+" closed consumer role matrix", func(t *testing.T) {
			fixture := newRotationManagerFixture(t)
			consumer := fixture.seedOppositeConsumer(t, class, "01J00000000000000000000048")
			fixture.beginTrust(t, class, fixture.successor(class))
			state := fixture.snapshot(t, class)
			if class == store.CertificateClassGateway {
				fixture.confirmControlForGatewayRoots(t, state)
			} else if err := fixture.manager.ConfirmControlTrustState(context.Background(), controlTrustStateClaim(state)); err == nil {
				t.Fatal("control intrinsic consumer was accepted for agent roots/CRLs")
			}
			valid := consumerClaim(state, consumer)
			invalid := []struct {
				name   string
				mutate func(*sign.TrustStateClaim)
			}{
				{name: "cross class", mutate: func(c *sign.TrustStateClaim) { c.ClaimedClass = string(consumer.class) }},
				{name: "missing required gateway receipt", mutate: func(c *sign.TrustStateClaim) {
					if consumer.class == store.CertificateClassGateway {
						c.CRLIssuerFingerprint = nil
						c.CRLSequence = 0
					} else {
						c.RootFingerprints = nil
					}
				}},
				{name: "forbidden agent receipt", mutate: func(c *sign.TrustStateClaim) {
					if consumer.class == store.CertificateClassAgent {
						c.CRLIssuerFingerprint = bytes.Repeat([]byte{1}, sha256.Size)
						c.CRLSequence = 1
					} else {
						c.ClaimedClass = "gateway"
					}
				}},
				{name: "cross issuer", mutate: func(c *sign.TrustStateClaim) {
					if len(c.CRLIssuerFingerprint) == sha256.Size {
						c.CRLIssuerFingerprint[0] ^= 0xff
					} else {
						c.CRLIssuerFingerprint = bytes.Repeat([]byte{2}, sha256.Size)
						c.CRLSequence = 1
					}
				}},
			}
			for _, test := range invalid {
				t.Run(test.name, func(t *testing.T) {
					claim := cloneRotationClaim(valid)
					test.mutate(&claim)
					if err := fixture.confirm(t, consumer, claim); !errors.Is(err, ErrTrustStateRejected) {
						t.Fatalf("closed role-matrix confirmation error = %v; want %v", err, ErrTrustStateRejected)
					}
				})
			}
			if err := fixture.confirm(t, consumer, valid); err != nil {
				t.Fatalf("confirm authorized role-matrix claim: %v", err)
			}
			if err := fixture.manager.Migrate(context.Background(), class); err != nil {
				t.Fatalf("Migrate after authorized role-matrix claim: %v", err)
			}
			if err := fixture.manager.Retire(context.Background(), class); err != nil {
				t.Fatalf("Retire role-matrix fixture: %v", err)
			}
			retire := fixture.snapshot(t, class)
			if class == store.CertificateClassGateway {
				fixture.confirmControlForGatewayRoots(t, retire)
			}
			if err := fixture.manager.Normalize(context.Background(), class); err == nil {
				t.Fatal("retire normalized before opposite-class consumer confirmed predecessor prune")
			}
			if err := fixture.confirm(t, consumer, consumerClaim(retire, consumer)); err != nil {
				t.Fatalf("confirm authorized retire prune: %v", err)
			}
			if err := fixture.manager.Normalize(context.Background(), class); err != nil {
				t.Fatalf("normalize after authorized retire prune: %v", err)
			}

			abortFixture := newRotationManagerFixture(t)
			abortConsumer := abortFixture.seedOppositeConsumer(t, class, "01J00000000000000000000040")
			abortFixture.beginTrust(t, class, abortFixture.successor(class))
			if err := abortFixture.manager.Abort(context.Background(), class); err != nil {
				t.Fatalf("begin role-matrix abort: %v", err)
			}
			abortState := abortFixture.snapshot(t, class)
			if class == store.CertificateClassGateway {
				abortFixture.confirmControlForGatewayRoots(t, abortState)
			}
			if err := abortFixture.manager.Normalize(context.Background(), class); err == nil {
				t.Fatal("abort normalized before opposite-class consumer confirmed successor prune")
			}
			if err := abortFixture.confirm(t, abortConsumer, consumerClaim(abortState, abortConsumer)); err != nil {
				t.Fatalf("confirm authorized abort prune: %v", err)
			}
			if err := abortFixture.manager.Normalize(context.Background(), class); err != nil {
				t.Fatalf("normalize after authorized abort prune: %v", err)
			}
		})

		t.Run(string(class)+" new offline consumer joins every active gate", func(t *testing.T) {
			fixture := newRotationManagerFixture(t)
			fixture.beginTrust(t, class, fixture.successor(class))
			state := fixture.snapshot(t, class)
			if class == store.CertificateClassGateway {
				fixture.confirmControlForGatewayRoots(t, state)
			}
			late := fixture.seedOppositeConsumer(t, class, "01J00000000000000000000049")
			if err := fixture.manager.Migrate(context.Background(), class); err == nil || !strings.Contains(err.Error(), late.id) {
				t.Fatalf("Migrate after mid-rotation enrollment error = %v; want durable late consumer gate", err)
			}
			if err := fixture.confirm(t, late, consumerClaim(state, late)); err != nil {
				t.Fatalf("confirm late consumer: %v", err)
			}
			if err := fixture.manager.Migrate(context.Background(), class); err != nil {
				t.Fatalf("Migrate after late consumer confirmation: %v", err)
			}
		})
	}

	t.Run("gateway receipt lower and upper published bounds are inclusive", func(t *testing.T) {
		fixture := newRotationManagerFixture(t)
		lower := fixture.seedGatewayConsumer(t, "01J00000000000000000000045")
		upper := fixture.seedGatewayConsumer(t, "01J00000000000000000000046")
		fixture.beginTrust(t, store.CertificateClassAgent, fixture.agentSuccessor)
		state := fixture.snapshot(t, store.CertificateClassAgent)
		fixture.advanceIssuerCRL(t, state, fixture.agentSuccessor)
		state = fixture.snapshot(t, store.CertificateClassAgent)
		if state.PublishedCRLSequence <= state.RequiredCRLSequence {
			t.Fatalf("receipt-bound fixture = [%d,%d]; want distinct inclusive endpoints", state.RequiredCRLSequence, state.PublishedCRLSequence)
		}
		lowerClaim := consumerClaim(state, lower)
		lowerClaim.CRLSequence = state.RequiredCRLSequence
		upperClaim := consumerClaim(state, upper)
		upperClaim.CRLSequence = state.PublishedCRLSequence
		if err := fixture.confirm(t, lower, lowerClaim); err != nil {
			t.Fatalf("accept lower inclusive receipt: %v", err)
		}
		if err := fixture.confirm(t, upper, upperClaim); err != nil {
			t.Fatalf("accept upper inclusive receipt: %v", err)
		}
	})
}

func exercisePkiServiceTrustConfirmationHandlers(t *testing.T) {
	t.Helper()
	t.Run("real procedures derive reporter class and persist exact leaf versus consumer events", func(t *testing.T) {
		fixture := newRotationManagerFixture(t)
		agent := fixture.seedAgent(t, "01J00000000000000000000093", fixture.agentSuccessor)
		gateway := fixture.seedGateway(t, "01J00000000000000000000094", fixture.gatewaySuccessor)
		fixture.beginTrust(t, store.CertificateClassAgent, fixture.agentSuccessor)
		fixture.beginTrust(t, store.CertificateClassGateway, fixture.gatewaySuccessor)
		agentState := fixture.snapshot(t, store.CertificateClassAgent)
		gatewayState := fixture.snapshot(t, store.CertificateClassGateway)

		tokens, err := NewRegistrationTokens(fixture.eventStore)
		if err != nil {
			t.Fatalf("create real confirmation-handler token dependency: %v", err)
		}
		service, err := NewEnrollmentService(
			tokens, fixture.eventStore, fixture.authorities, &testLifecycleAuthorizer{allow: true},
		)
		if err != nil {
			t.Fatalf("create real confirmation-handler service: %v", err)
		}
		service.rotationManager = fixture.manager
		path, handler := NewEnrollmentHTTPHandler(service)
		mux := http.NewServeMux()
		mux.Handle(path, handler)
		server := httptest.NewTLSServer(mux)
		t.Cleanup(server.Close)
		client := powermanagev1connect.NewPkiServiceClient(server.Client(), server.URL)

		agentLeaf := rotationConfirmationRequest(t, agent, leafClaim(agentState, agent))
		agentConsumer := rotationConfirmationRequest(t, agent, consumerClaim(gatewayState, agent))
		gatewayLeaf := rotationConfirmationRequest(t, gateway, leafClaim(gatewayState, gateway))
		gatewayConsumer := rotationConfirmationRequest(t, gateway, consumerClaim(agentState, gateway))

		t.Run("missing failure ladder rejects before persistence", func(t *testing.T) {
			before := rotationConfirmationEventCount(t, fixture.pool)
			failureLadder := service.failureLadder
			service.failureLadder = nil
			response, err := client.ConfirmAgentTrustState(
				context.Background(),
				connect.NewRequest(agentLeaf),
			)
			service.failureLadder = failureLadder

			wantError := connect.CodeInternal.String() + ": trust confirmation unavailable"
			if response != nil || connect.CodeOf(err) != connect.CodeInternal || err.Error() != wantError {
				t.Errorf("confirmation without failure ladder = (%v, %v); want no response and %q", response, err, wantError)
			}
			if after := rotationConfirmationEventCount(t, fixture.pool); after != before {
				t.Fatalf("confirmation without failure ladder persisted %d events; want unchanged %d", after, before)
			}
		})

		before := rotationConfirmationEventCount(t, fixture.pool)
		_, swappedAgentErr := client.ConfirmGatewayTrustState(context.Background(), connect.NewRequest(agentLeaf))
		_, swappedGatewayErr := client.ConfirmAgentTrustState(context.Background(), connect.NewRequest(gatewayLeaf))
		if swappedAgentErr == nil || swappedGatewayErr == nil ||
			connect.CodeOf(swappedAgentErr) != connect.CodeOf(swappedGatewayErr) ||
			swappedAgentErr.Error() != swappedGatewayErr.Error() {
			t.Fatalf("swapped reporter/procedure errors = (%v, %v); want one uniform rejection independent of stored identity", swappedAgentErr, swappedGatewayErr)
		}
		if got := rotationConfirmationEventCount(t, fixture.pool); got != before {
			t.Fatalf("swapped reporter/procedure persisted %d confirmation events; want unchanged %d", got, before)
		}

		for _, call := range []struct {
			name string
			run  func() error
		}{
			{name: "agent leaf", run: func() error {
				_, err := client.ConfirmAgentTrustState(context.Background(), connect.NewRequest(agentLeaf))
				return err
			}},
			{name: "agent consumer", run: func() error {
				_, err := client.ConfirmAgentTrustState(context.Background(), connect.NewRequest(agentConsumer))
				return err
			}},
			{name: "gateway leaf", run: func() error {
				_, err := client.ConfirmGatewayTrustState(context.Background(), connect.NewRequest(gatewayLeaf))
				return err
			}},
			{name: "gateway consumer", run: func() error {
				_, err := client.ConfirmGatewayTrustState(context.Background(), connect.NewRequest(gatewayConsumer))
				return err
			}},
		} {
			if err := call.run(); err != nil {
				t.Fatalf("real %s confirmation handler: %v", call.name, err)
			}
		}
		for _, eventType := range []string{
			"AgentLeafTrustConfirmed", "AgentConsumerTrustConfirmed",
			"GatewayLeafTrustConfirmed", "GatewayConsumerTrustConfirmed",
		} {
			var count int
			if err := fixture.pool.QueryRow(context.Background(),
				`SELECT count(*) FROM events WHERE event_type = $1`, eventType,
			).Scan(&count); err != nil {
				t.Fatalf("count exact %s persistence: %v", eventType, err)
			}
			if count != 1 {
				t.Fatalf("exact %s persistence count = %d; want one leaf/consumer event selected by derived reporter and claimed class", eventType, count)
			}
		}
	})
}

func rotationConfirmationRequest(
	t *testing.T,
	reporter rotationReporter,
	claim sign.TrustStateClaim,
) *powermanagev1.ConfirmTrustStateRequest {
	t.Helper()
	signature := signRotationClaim(t, reporter.signer, claim)
	request := &powermanagev1.ConfirmTrustStateRequest{
		CertificateDer: bytes.Clone(reporter.certificateDER), ClaimedClass: claim.ClaimedClass,
		Generation: claim.Generation, Revision: claim.Revision,
		RootFingerprints:     cloneRotationDERList(claim.RootFingerprints),
		CrlIssuerFingerprint: bytes.Clone(claim.CRLIssuerFingerprint),
		CrlSequence:          claim.CRLSequence,
		Signature:            bytes.Clone(signature),
	}
	reconstructed := rotationClaimFromRequest(string(reporter.class), request)
	certificate, err := x509.ParseCertificate(request.GetCertificateDer())
	if err != nil || len(request.GetSignature()) == 0 ||
		sign.VerifyTrustState(certificate.PublicKey, reconstructed, request.GetSignature()) != nil ||
		!reflect.DeepEqual(reconstructed, claim) {
		t.Fatalf("constructed real confirmation request does not bind exact procedure class, certificate, claim, and key: parse=%v", err)
	}
	return request
}

func rotationClaimFromRequest(
	reporterClass string,
	request *powermanagev1.ConfirmTrustStateRequest,
) sign.TrustStateClaim {
	reporterFingerprint := sha256.Sum256(request.GetCertificateDer())
	return sign.TrustStateClaim{
		ReporterClass: reporterClass, ClaimedClass: request.GetClaimedClass(),
		Generation: request.GetGeneration(), Revision: request.GetRevision(),
		ReporterCertificateFingerprint: bytes.Clone(reporterFingerprint[:]),
		RootFingerprints:               cloneRotationDERList(request.GetRootFingerprints()),
		CRLIssuerFingerprint:           bytes.Clone(request.GetCrlIssuerFingerprint()),
		CRLSequence:                    request.GetCrlSequence(),
	}
}

func cloneRotationClaim(value sign.TrustStateClaim) sign.TrustStateClaim {
	value.ReporterCertificateFingerprint = bytes.Clone(value.ReporterCertificateFingerprint)
	value.RootFingerprints = cloneRotationDERList(value.RootFingerprints)
	value.CRLIssuerFingerprint = bytes.Clone(value.CRLIssuerFingerprint)
	return value
}

func TestRotationManager_RetireRequiresEveryNonRevokedDeviceMigrated(t *testing.T) {
	for _, class := range []store.CertificateClass{store.CertificateClassAgent, store.CertificateClassGateway} {
		t.Run(string(class), func(t *testing.T) {
			fixture := newRotationManagerFixture(t)
			first := fixture.seedLeaf(t, class, "01J00000000000000000000051")
			second := fixture.seedLeaf(t, class, "01J00000000000000000000052")
			unconfirmedSuccessor := fixture.seedLeaf(t, class, "01J00000000000000000000054")
			consumer := fixture.seedOppositeConsumer(t, class, "01J00000000000000000000053")
			successor := fixture.successor(class)
			fixture.beginTrust(t, class, successor)
			trust := fixture.snapshot(t, class)
			fixture.confirmRootConsumer(t, trust, consumer)
			if err := fixture.manager.Migrate(context.Background(), class); err != nil {
				t.Fatalf("enter migrate: %v", err)
			}
			first = fixture.renewLeafFrom(t, first, successor)
			unconfirmedSuccessor = fixture.renewLeafFrom(t, unconfirmedSuccessor, successor)
			migrate := fixture.snapshot(t, class)
			if err := fixture.confirm(t, first, leafClaim(migrate, first)); err != nil {
				t.Fatalf("confirm first successor-issued leaf: %v", err)
			}
			if err := fixture.manager.Retire(context.Background(), class); err == nil || !strings.Contains(err.Error(), second.id) {
				t.Fatalf("Retire with unmigrated non-revoked leaf error = %v; want exact blocking identity", err)
			}
			fixture.revokeLeaf(t, second)
			if err := fixture.manager.Retire(context.Background(), class); err == nil || !strings.Contains(err.Error(), unconfirmedSuccessor.id) {
				t.Fatalf("Retire with successor-issued but unconfirmed leaf error = %v; want exact blocking identity", err)
			}
			if err := fixture.confirm(t, unconfirmedSuccessor, leafClaim(migrate, unconfirmedSuccessor)); err != nil {
				t.Fatalf("confirm second successor-issued leaf: %v", err)
			}
			if err := fixture.manager.Retire(context.Background(), class); err != nil {
				t.Fatalf("Retire after old leaf revocation and every successor confirmation: %v", err)
			}
		})
	}
}

func TestRotationManager_RestartRebuildsEveryPhaseAndConfirmationGate(t *testing.T) {
	type restartPhase struct {
		name    string
		prepare func(*testing.T, *rotationManagerFixture, store.CertificateClass, rotationReporter)
		resume  func(*testing.T, *rotationManagerFixture, store.CertificateClass, rotationReporter)
	}
	phases := []restartPhase{
		{name: "stable", resume: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, _ rotationReporter) {
			f.beginTrust(t, class, f.successor(class))
		}},
		{name: "normalized-successor-stable", prepare: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, reporter rotationReporter) {
			prepareRestartMigrate(t, f, class, reporter)
			if err := f.manager.Retire(context.Background(), class); err != nil {
				t.Fatalf("enter retire before normalized-stable restart: %v", err)
			}
			f.confirmRootConsumer(t, f.snapshot(t, class), reporter)
			if err := f.manager.Normalize(context.Background(), class); err != nil {
				t.Fatalf("normalize successor before restart: %v", err)
			}
		}, resume: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, _ rotationReporter) {
			state := f.snapshot(t, class)
			assertRotationState(t, state, RotationPhaseStable, 2, 2, f.successor(class).root.Raw)
			fingerprint := sha256.Sum256(f.successor(class).root.Raw)
			if authority, ok := f.authorities.authorityForIssuer(class, fingerprint); !ok ||
				!bytes.Equal(authority.certificate.Raw, f.successor(class).root.Raw) {
				t.Fatal("restart did not make the normalized successor the sole usable authority")
			} else {
				gotPublic, err := x509.MarshalPKIXPublicKey(authority.signer.Public())
				if err != nil {
					t.Fatalf("marshal normalized usable signer public key: %v", err)
				}
				wantPublic, err := x509.MarshalPKIXPublicKey(f.successor(class).signer.Public())
				if err != nil || !bytes.Equal(gotPublic, wantPublic) {
					t.Fatalf("normalized usable signer public key does not equal the exact generation-two successor: %v", err)
				}
			}
		}},
		{name: "trust", prepare: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, _ rotationReporter) {
			f.beginTrust(t, class, f.successor(class))
		}, resume: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, reporter rotationReporter) {
			state := f.snapshot(t, class)
			if err := f.manager.Migrate(context.Background(), class); err == nil {
				t.Fatal("restart forgot the trust confirmation gate")
			}
			f.confirmRootConsumer(t, state, reporter)
			if err := f.manager.Migrate(context.Background(), class); err != nil {
				t.Fatalf("resume rebuilt trust phase: %v", err)
			}
		}},
		{name: "trust-confirmed-before-crash", prepare: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, reporter rotationReporter) {
			f.beginTrust(t, class, f.successor(class))
			f.confirmRootConsumerDurably(t, f.snapshot(t, class), reporter)
		}, resume: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, _ rotationReporter) {
			before := rotationConfirmationEventCount(t, f.pool)
			if err := f.manager.Migrate(context.Background(), class); err != nil {
				t.Fatalf("fresh manager did not honor durable pre-crash trust confirmations: %v", err)
			}
			if got := rotationConfirmationEventCount(t, f.pool); got != before {
				t.Fatalf("resuming confirmed trust appended confirmation events = %d; want unchanged %d", got, before)
			}
		}},
		{name: "migrate", prepare: prepareRestartMigrate, resume: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, _ rotationReporter) {
			if err := f.manager.Retire(context.Background(), class); err != nil {
				t.Fatalf("resume rebuilt migrate phase: %v", err)
			}
		}},
		{name: "migrate-successor-leaf-confirmed-before-crash", prepare: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, reporter rotationReporter) {
			prepareRestartMigrate(t, f, class, reporter)
			leaf := f.seedLeaf(t, class, "01J00000000000000000000062")
			leaf = f.renewLeafFrom(t, leaf, f.successor(class))
			state := f.snapshot(t, class)
			before := rotationConfirmationEventCount(t, f.pool)
			if err := f.confirm(t, leaf, leafClaim(state, leaf)); err != nil {
				t.Fatalf("record signed successor-leaf confirmation before crash: %v", err)
			}
			if after := rotationConfirmationEventCount(t, f.pool); after <= before {
				t.Fatalf("successor-leaf confirmation was not durable before crash: before=%d after=%d", before, after)
			}
		}, resume: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, _ rotationReporter) {
			before := rotationConfirmationEventCount(t, f.pool)
			if err := f.manager.Retire(context.Background(), class); err != nil {
				t.Fatalf("fresh manager did not honor durable signed successor-leaf confirmation: %v", err)
			}
			if got := rotationConfirmationEventCount(t, f.pool); got != before {
				t.Fatalf("Retire after restart appended confirmation events = %d; want unchanged %d", got, before)
			}
		}},
		{name: "abort-pending", prepare: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, _ rotationReporter) {
			f.beginTrust(t, class, f.successor(class))
			if err := f.manager.Abort(context.Background(), class); err != nil {
				t.Fatalf("begin pending abort: %v", err)
			}
		}, resume: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, reporter rotationReporter) {
			state := f.snapshot(t, class)
			if err := f.manager.Normalize(context.Background(), class); err == nil {
				t.Fatal("restart forgot abort prune gate")
			}
			f.confirmRootConsumer(t, state, reporter)
			if err := f.manager.Normalize(context.Background(), class); err != nil {
				t.Fatalf("finish rebuilt abort: %v", err)
			}
		}},
		{name: "abort-confirmed-before-crash", prepare: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, reporter rotationReporter) {
			f.beginTrust(t, class, f.successor(class))
			if err := f.manager.Abort(context.Background(), class); err != nil {
				t.Fatalf("begin confirmed abort before restart: %v", err)
			}
			f.confirmRootConsumerDurably(t, f.snapshot(t, class), reporter)
		}, resume: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, _ rotationReporter) {
			before := rotationConfirmationEventCount(t, f.pool)
			if err := f.manager.Normalize(context.Background(), class); err != nil {
				t.Fatalf("fresh manager did not honor durable pre-crash abort confirmations: %v", err)
			}
			if got := rotationConfirmationEventCount(t, f.pool); got != before {
				t.Fatalf("resuming confirmed abort appended confirmation events = %d; want unchanged %d", got, before)
			}
		}},
		{name: "retire-pending", prepare: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, reporter rotationReporter) {
			prepareRestartMigrate(t, f, class, reporter)
			if err := f.manager.Retire(context.Background(), class); err != nil {
				t.Fatalf("enter pending retire: %v", err)
			}
		}, resume: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, reporter rotationReporter) {
			state := f.snapshot(t, class)
			if err := f.manager.Normalize(context.Background(), class); err == nil {
				t.Fatal("restart forgot predecessor prune gate")
			}
			f.confirmRootConsumer(t, state, reporter)
			if err := f.manager.Normalize(context.Background(), class); err != nil {
				t.Fatalf("finish rebuilt retire: %v", err)
			}
		}},
		{name: "retire-confirmed-before-crash", prepare: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, reporter rotationReporter) {
			prepareRestartMigrate(t, f, class, reporter)
			if err := f.manager.Retire(context.Background(), class); err != nil {
				t.Fatalf("enter confirmed retire before restart: %v", err)
			}
			f.confirmRootConsumerDurably(t, f.snapshot(t, class), reporter)
		}, resume: func(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, _ rotationReporter) {
			before := rotationConfirmationEventCount(t, f.pool)
			if err := f.manager.Normalize(context.Background(), class); err != nil {
				t.Fatalf("fresh manager did not honor durable pre-crash retire confirmations: %v", err)
			}
			if got := rotationConfirmationEventCount(t, f.pool); got != before {
				t.Fatalf("resuming confirmed retire appended confirmation events = %d; want unchanged %d", got, before)
			}
		}},
	}

	for _, class := range []store.CertificateClass{store.CertificateClassAgent, store.CertificateClassGateway} {
		for _, test := range phases {
			t.Run(string(class)+"/"+test.name, func(t *testing.T) {
				fixture := newRotationManagerFixture(t)
				reporter := fixture.seedOppositeConsumer(t, class, "01J00000000000000000000061")
				if test.prepare != nil {
					test.prepare(t, &fixture, class, reporter)
				}
				before := fixture.snapshot(t, class)
				freshStore, err := store.NewProduction(fixture.pool)
				if err != nil {
					t.Fatalf("create fresh event store: %v", err)
				}
				freshAuthorities, err := NewAuthorities(
					fixture.agentCurrent.root.Raw, fixture.agentCurrent.signer,
					fixture.gatewayCurrent.root.Raw, fixture.gatewayCurrent.signer,
					newEnrollmentSigningKey(t),
				)
				if err != nil {
					t.Fatalf("create fresh configured authorities: %v", err)
				}
				restarted, err := NewRotationManager(RotationManagerConfig{
					EventStore: freshStore, Authorities: freshAuthorities, Distributor: &recordingTrustBundleDistributor{},
					SuccessorSigners: map[store.CertificateClass]crypto.Signer{
						store.CertificateClassAgent:   fixture.agentSuccessor.signer,
						store.CertificateClassGateway: fixture.gatewaySuccessor.signer,
					},
				})
				if err != nil {
					t.Fatalf("restart RotationManager from durable state: %v", err)
				}
				restarted.now = fixture.manager.now
				fixture.eventStore, fixture.authorities, fixture.manager = freshStore, freshAuthorities, restarted
				after := fixture.snapshot(t, class)
				assertAuthoritySnapshotsEqual(t, after, before)
				if before.Phase != RotationPhaseStable {
					wrongSigner := newRotationCA(t, "wrong configured signer", fixture.now)
					if _, err := NewRotationManager(RotationManagerConfig{
						EventStore: freshStore, Authorities: freshAuthorities, Distributor: &recordingTrustBundleDistributor{},
						SuccessorSigners: map[store.CertificateClass]crypto.Signer{class: wrongSigner.signer},
					}); err == nil || !strings.Contains(strings.ToLower(err.Error()), "signer") {
						t.Fatalf("restart with mismatched signer error = %v; want fail-closed signer binding", err)
					}
				} else if before.Generation > 1 {
					wrongAuthorities, err := NewAuthorities(
						fixture.agentCurrent.root.Raw, fixture.agentCurrent.signer,
						fixture.gatewayCurrent.root.Raw, fixture.gatewayCurrent.signer,
						newEnrollmentSigningKey(t),
					)
					if err != nil {
						t.Fatalf("create isolated authorities for normalized wrong-signer boot: %v", err)
					}
					wrongSigner := newRotationCA(t, "wrong normalized successor signer", fixture.now)
					if _, err := NewRotationManager(RotationManagerConfig{
						EventStore: freshStore, Authorities: wrongAuthorities, Distributor: &recordingTrustBundleDistributor{},
						SuccessorSigners: map[store.CertificateClass]crypto.Signer{class: wrongSigner.signer},
					}); err == nil || !strings.Contains(strings.ToLower(err.Error()), "signer") {
						t.Fatalf("normalized generation-%d restart with wrong successor signer error = %v; want fail-closed signer binding",
							before.Generation, err)
					}
				}
				test.resume(t, &fixture, class, reporter)
			})
		}
	}
}

func prepareRestartMigrate(t *testing.T, f *rotationManagerFixture, class store.CertificateClass, reporter rotationReporter) {
	t.Helper()
	f.beginTrust(t, class, f.successor(class))
	state := f.snapshot(t, class)
	f.confirmRootConsumer(t, state, reporter)
	if err := f.manager.Migrate(context.Background(), class); err != nil {
		t.Fatalf("enter migrate: %v", err)
	}
}

type rotationManagerFixture struct {
	pool             *pgxpool.Pool
	eventStore       *store.Store
	authorities      *Authorities
	manager          *RotationManager
	distributor      *recordingTrustBundleDistributor
	agentCurrent     rotationCA
	agentSuccessor   rotationCA
	gatewayCurrent   rotationCA
	gatewaySuccessor rotationCA
	now              time.Time
}

type rotationCA struct {
	root   *x509.Certificate
	signer crypto.Signer
}

type rotationReporter struct {
	id             string
	class          store.CertificateClass
	certificateDER []byte
	signer         crypto.Signer
	dnsNames       []string
}

type recordingTrustBundleDistributor struct {
	mu           sync.Mutex
	publications []TrustBundlePublication
	err          error
}

func (d *recordingTrustBundleDistributor) PublishTrustBundle(_ context.Context, publication TrustBundlePublication) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return d.err
	}
	publication.RootCertificateDER = cloneRotationDERList(publication.RootCertificateDER)
	publication.TransitionCertificateDER = bytes.Clone(publication.TransitionCertificateDER)
	publication.CRLIssuerFingerprints = slices.Clone(publication.CRLIssuerFingerprints)
	d.publications = append(d.publications, publication)
	return nil
}

func newRotationManagerFixture(t *testing.T) rotationManagerFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	pool := registrationPostgres.Database(t, store.Migrate)
	eventStore, err := store.NewProduction(pool)
	if err != nil {
		t.Fatalf("create production event store: %v", err)
	}
	agentCurrent := newRotationCA(t, "agent current", now)
	agentSuccessor := newRotationCA(t, "agent successor", now)
	gatewayCurrent := newRotationCA(t, "gateway current", now)
	gatewaySuccessor := newRotationCA(t, "gateway successor", now)
	authorities, err := NewAuthorities(
		agentCurrent.root.Raw, agentCurrent.signer,
		gatewayCurrent.root.Raw, gatewayCurrent.signer,
		newEnrollmentSigningKey(t),
	)
	if err != nil {
		t.Fatalf("create rotation authorities: %v", err)
	}
	distributor := &recordingTrustBundleDistributor{}
	manager, err := NewRotationManager(RotationManagerConfig{
		EventStore: eventStore, Authorities: authorities, Distributor: distributor,
		SuccessorSigners: map[store.CertificateClass]crypto.Signer{
			store.CertificateClassAgent:   agentSuccessor.signer,
			store.CertificateClassGateway: gatewaySuccessor.signer,
		},
	})
	if err != nil {
		t.Fatalf("create rotation manager: %v", err)
	}
	manager.now = func() time.Time { return now }
	return rotationManagerFixture{
		pool: pool, eventStore: eventStore, authorities: authorities, manager: manager,
		distributor: distributor, agentCurrent: agentCurrent, agentSuccessor: agentSuccessor,
		gatewayCurrent: gatewayCurrent, gatewaySuccessor: gatewaySuccessor, now: now,
	}
}

func (f *rotationManagerFixture) beginTrust(t *testing.T, class store.CertificateClass, successor rotationCA) {
	t.Helper()
	current := f.current(class)
	transition := crossSignRotationCA(t, current, successor)
	if err := f.manager.BeginTrust(
		context.Background(), class, successor.root.Raw, transition, successor.signer,
	); err != nil {
		t.Fatalf("BeginTrust(%s): %v", class, err)
	}
}

func (f *rotationManagerFixture) advanceIssuerCRL(t *testing.T, state AuthoritySnapshot, issuer rotationCA) {
	t.Helper()
	sequence := state.PublishedCRLSequence + 1
	issuedAt := f.now.Add(time.Minute)
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(int64(sequence)), ThisUpdate: issuedAt, NextUpdate: issuedAt.Add(DefaultCRLMaxAge),
	}, issuer.root, issuer.signer)
	if err != nil {
		t.Fatalf("sign advanced issuer CRL: %v", err)
	}
	stored, err := f.eventStore.CompareAndSwapCRL(
		context.Background(), state.Class, sha256.Sum256(issuer.root.Raw),
		state.PublishedCRLSequence, der, issuedAt, store.CRLSource{},
	)
	if err != nil || !stored {
		t.Fatalf("advance issuer-scoped CRL = (stored %v, err %v); want one committed publication", stored, err)
	}
}

func (f *rotationManagerFixture) snapshot(t *testing.T, class store.CertificateClass) AuthoritySnapshot {
	t.Helper()
	state, err := f.manager.Snapshot(context.Background(), class)
	if err != nil {
		t.Fatalf("Snapshot(%s): %v", class, err)
	}
	return state
}

func (f *rotationManagerFixture) current(class store.CertificateClass) rotationCA {
	if class == store.CertificateClassAgent {
		return f.agentCurrent
	}
	return f.gatewayCurrent
}

func (f *rotationManagerFixture) successor(class store.CertificateClass) rotationCA {
	if class == store.CertificateClassAgent {
		return f.agentSuccessor
	}
	return f.gatewaySuccessor
}

func (f *rotationManagerFixture) seedGatewayConsumer(t *testing.T, gatewayID string) rotationReporter {
	t.Helper()
	return f.seedGateway(t, gatewayID, f.gatewayCurrent)
}

func (f *rotationManagerFixture) seedOppositeConsumer(t *testing.T, class store.CertificateClass, id string) rotationReporter {
	t.Helper()
	if class == store.CertificateClassAgent {
		return f.seedGateway(t, id, f.gatewayCurrent)
	}
	return f.seedAgent(t, id, f.agentCurrent)
}

func (f *rotationManagerFixture) seedLeaf(t *testing.T, class store.CertificateClass, id string) rotationReporter {
	t.Helper()
	if class == store.CertificateClassAgent {
		return f.seedAgent(t, id, f.agentCurrent)
	}
	return f.seedGateway(t, id, f.gatewayCurrent)
}

func (f *rotationManagerFixture) seedAgent(t *testing.T, deviceID string, authority rotationCA) rotationReporter {
	t.Helper()
	key := newEnrollmentSigningKey(t)
	serial := int64(300) + int64(deviceID[len(deviceID)-1])
	certificateDER := newRotationLeaf(t, authority, key.Public(), store.CertificateClassAgent, deviceID, nil, f.now, serial)
	sealing := newEnrollmentSealingKey(t)
	event, err := store.AgentEnrolledEvent(deviceID, certificateDER, sealing, "01J00000000000000000000071", "owner@example.com")
	if err != nil {
		t.Fatalf("build agent enrollment event: %v", err)
	}
	if err := f.eventStore.WithDeviceLifecycleLock(context.Background(), deviceID, func(lifecycle *store.DeviceLifecycle) error {
		return lifecycle.AppendEvent(context.Background(), event, 0)
	}); err != nil {
		t.Fatalf("seed agent consumer: %v", err)
	}
	return rotationReporter{id: deviceID, class: store.CertificateClassAgent, certificateDER: certificateDER, signer: key}
}

func (f *rotationManagerFixture) seedGateway(t *testing.T, gatewayID string, authority rotationCA) rotationReporter {
	t.Helper()
	key := newEnrollmentSigningKey(t)
	dnsNames := []string{"gateway-" + strings.ToLower(gatewayID[len(gatewayID)-2:]) + ".internal.example"}
	serial := int64(400) + int64(gatewayID[len(gatewayID)-1])
	certificateDER := newRotationLeaf(t, authority, key.Public(), store.CertificateClassGateway, gatewayID, dnsNames, f.now, serial)
	event, err := store.GatewayEnrolledEvent(gatewayID, certificateDER, "01J00000000000000000000072", "owner@example.com", dnsNames)
	if err != nil {
		t.Fatalf("build gateway enrollment event: %v", err)
	}
	if err := f.eventStore.WithDeviceLifecycleLock(context.Background(), gatewayID, func(lifecycle *store.DeviceLifecycle) error {
		return lifecycle.AppendGatewayEvent(context.Background(), event, 0)
	}); err != nil {
		t.Fatalf("seed gateway consumer: %v", err)
	}
	return rotationReporter{id: gatewayID, class: store.CertificateClassGateway, certificateDER: certificateDER, signer: key, dnsNames: dnsNames}
}

func (f *rotationManagerFixture) unstoredGatewayReporter(t *testing.T, gatewayID string) rotationReporter {
	t.Helper()
	key := newEnrollmentSigningKey(t)
	dnsNames := []string{"unknown.internal.example"}
	certificateDER := newRotationLeaf(t, f.gatewayCurrent, key.Public(), store.CertificateClassGateway, gatewayID, dnsNames, f.now, 49)
	return rotationReporter{id: gatewayID, class: store.CertificateClassGateway, certificateDER: certificateDER, signer: key, dnsNames: dnsNames}
}

func (f *rotationManagerFixture) renewLeafFrom(t *testing.T, reporter rotationReporter, authority rotationCA) rotationReporter {
	t.Helper()
	serial := int64(500) + int64(reporter.id[len(reporter.id)-1])
	certificateDER := newRotationLeaf(t, authority, reporter.signer.Public(), reporter.class, reporter.id, reporter.dnsNames, f.now, serial)
	var event store.Event
	var err error
	if reporter.class == store.CertificateClassAgent {
		event, err = store.AgentCertificateRenewedEvent(reporter.id, certificateDER, newEnrollmentSealingKey(t), reporter.certificateDER)
	} else {
		event, err = store.GatewayCertificateRenewedEvent(reporter.id, certificateDER, reporter.certificateDER)
	}
	if err != nil {
		t.Fatalf("build successor renewal event: %v", err)
	}
	if err := f.eventStore.WithDeviceLifecycleLock(context.Background(), reporter.id, func(lifecycle *store.DeviceLifecycle) error {
		if reporter.class == store.CertificateClassAgent {
			current, readErr := lifecycle.Device(context.Background())
			if readErr != nil {
				return readErr
			}
			return lifecycle.AppendEvent(context.Background(), event, current.ProjectionVersion)
		}
		current, readErr := lifecycle.Gateway(context.Background())
		if readErr != nil {
			return readErr
		}
		return lifecycle.AppendGatewayEvent(context.Background(), event, current.ProjectionVersion)
	}); err != nil {
		t.Fatalf("persist successor renewal: %v", err)
	}
	reporter.certificateDER = certificateDER
	return reporter
}

func (f *rotationManagerFixture) revokeGateway(t *testing.T, reporter rotationReporter) {
	t.Helper()
	f.revokeLeaf(t, reporter)
}

func (f *rotationManagerFixture) revokeLeaf(t *testing.T, reporter rotationReporter) {
	t.Helper()
	var event store.Event
	var err error
	if reporter.class == store.CertificateClassAgent {
		event, err = store.AgentCertificateRevokedEvent(reporter.id, reporter.certificateDER)
	} else {
		event, err = store.GatewayCertificateRevokedEvent(reporter.id, reporter.certificateDER)
	}
	if err != nil {
		t.Fatalf("build leaf revocation: %v", err)
	}
	if err := f.eventStore.WithDeviceLifecycleLock(context.Background(), reporter.id, func(lifecycle *store.DeviceLifecycle) error {
		if reporter.class == store.CertificateClassAgent {
			current, readErr := lifecycle.Device(context.Background())
			if readErr != nil {
				return readErr
			}
			return lifecycle.AppendEvent(context.Background(), event, current.ProjectionVersion)
		}
		current, readErr := lifecycle.Gateway(context.Background())
		if readErr != nil {
			return readErr
		}
		return lifecycle.AppendGatewayEvent(context.Background(), event, current.ProjectionVersion)
	}); err != nil {
		t.Fatalf("persist leaf revocation: %v", err)
	}
}

func (f *rotationManagerFixture) confirmControlForGatewayRoots(t *testing.T, state AuthoritySnapshot) {
	t.Helper()
	if state.Class != store.CertificateClassGateway {
		t.Fatalf("control intrinsic trust confirmation is authorized only for gateway roots, got %q", state.Class)
	}
	if err := f.manager.ConfirmControlTrustState(context.Background(), controlTrustStateClaim(state)); err != nil {
		t.Fatalf("confirm intrinsic control trust state: %v", err)
	}
}

func controlTrustStateClaim(state AuthoritySnapshot) ControlTrustStateConfirmation {
	return ControlTrustStateConfirmation{
		ClaimedClass: state.Class, Generation: state.Generation, Revision: state.Revision,
		RootFingerprints:     rotationRootFingerprints(state.DesiredRootDER...),
		CRLIssuerFingerprint: bytes.Clone(state.RequiredCRLIssuerFingerprint),
		CRLSequence:          state.RequiredCRLSequence,
	}
}

func (f *rotationManagerFixture) confirmRootConsumer(t *testing.T, state AuthoritySnapshot, reporter rotationReporter) {
	t.Helper()
	if state.Class == store.CertificateClassGateway {
		f.confirmControlForGatewayRoots(t, state)
	}
	if err := f.confirm(t, reporter, consumerClaim(state, reporter)); err != nil {
		t.Fatalf("confirm exact %s-root consumer %s: %v", state.Class, reporter.id, err)
	}
}

func (f *rotationManagerFixture) confirmRootConsumerDurably(t *testing.T, state AuthoritySnapshot, reporter rotationReporter) {
	t.Helper()
	before := rotationConfirmationEventCount(t, f.pool)
	f.confirmRootConsumer(t, state, reporter)
	if after := rotationConfirmationEventCount(t, f.pool); after <= before {
		t.Fatalf("pre-crash %s-root confirmations were not durably recorded: before=%d after=%d", state.Class, before, after)
	}
}

func (f *rotationManagerFixture) confirm(t *testing.T, reporter rotationReporter, claim sign.TrustStateClaim) error {
	t.Helper()
	signature, err := sign.SignTrustState(reporter.signer, claim)
	if err != nil {
		signature = []byte("intentionally invalid trust-state fixture")
	}
	return f.manager.ConfirmTrustState(context.Background(), TrustStateConfirmation{
		ReporterCertificateDER: bytes.Clone(reporter.certificateDER), Claim: claim, Signature: signature,
	})
}

func consumerClaim(state AuthoritySnapshot, reporter rotationReporter) sign.TrustStateClaim {
	reporterFingerprint := sha256.Sum256(reporter.certificateDER)
	claim := sign.TrustStateClaim{
		ReporterClass: string(reporter.class), ClaimedClass: string(state.Class),
		Generation: state.Generation, Revision: state.Revision,
		ReporterCertificateFingerprint: bytes.Clone(reporterFingerprint[:]),
		RootFingerprints:               rotationRootFingerprints(state.DesiredRootDER...),
	}
	if reporter.class == store.CertificateClassGateway && state.Class == store.CertificateClassAgent {
		claim.CRLIssuerFingerprint = bytes.Clone(state.RequiredCRLIssuerFingerprint)
		claim.CRLSequence = state.RequiredCRLSequence
	}
	return claim
}

func leafClaim(state AuthoritySnapshot, reporter rotationReporter) sign.TrustStateClaim {
	reporterFingerprint := sha256.Sum256(reporter.certificateDER)
	return sign.TrustStateClaim{
		ReporterClass: string(reporter.class), ClaimedClass: string(reporter.class),
		Generation: state.Generation, Revision: state.Revision,
		ReporterCertificateFingerprint: bytes.Clone(reporterFingerprint[:]),
		RootFingerprints:               rotationRootFingerprints(state.DesiredRootDER...),
	}
}

func assertRotationState(t *testing.T, state AuthoritySnapshot, phase RotationPhase, generation, revision uint64, roots ...[]byte) {
	t.Helper()
	if state.Phase != phase || state.Generation != generation || state.Revision != revision || !equalRotationDERLists(state.DesiredRootDER, roots) {
		t.Fatalf("rotation state = (phase %q generation %d revision %d roots %x); want (%q %d %d %x)",
			state.Phase, state.Generation, state.Revision, state.DesiredRootDER, phase, generation, revision, roots)
	}
}

func assertAuthoritySnapshotsEqual(t *testing.T, got, want AuthoritySnapshot) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rebuilt snapshot = %+v; want exact %+v", got, want)
	}
}

type rotationObservableState struct {
	durableVersion int64
	snapshot       AuthoritySnapshot
	crls           []store.SignedCRL
	publications   []TrustBundlePublication
	authorities    map[[sha256.Size]byte]rotationAuthorityLookup
}

type rotationAuthorityLookup struct {
	found                  bool
	certificateFingerprint [sha256.Size]byte
	signerFingerprint      [sha256.Size]byte
}

func captureRotationObservableState(
	t *testing.T,
	fixture *rotationManagerFixture,
	class store.CertificateClass,
	attemptedCandidateDER ...[]byte,
) rotationObservableState {
	t.Helper()
	state := rotationObservableState{snapshot: fixture.snapshot(t, class)}
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT COALESCE(MAX(stream_version), 0)
		FROM events WHERE stream_type = 'ca-rotation' AND stream_id = $1`, string(class),
	).Scan(&state.durableVersion); err != nil {
		t.Fatalf("read durable rotation version: %v", err)
	}
	crls, err := fixture.eventStore.CurrentCRLs(context.Background(), class)
	if err != nil {
		t.Fatalf("read issuer-scoped CRLs: %v", err)
	}
	state.crls = slices.Clone(crls)
	state.publications = slices.Clone(fixture.distributor.publications)
	state.authorities = make(map[[sha256.Size]byte]rotationAuthorityLookup)
	candidates := cloneRotationDERList(state.snapshot.DesiredRootDER)
	candidates = append(candidates,
		state.snapshot.IssuingRootDER, state.snapshot.SuccessorRootDER, state.snapshot.PredecessorRootDER,
		fixture.current(class).root.Raw, fixture.successor(class).root.Raw,
	)
	recordLookup := func(certificateDER []byte) {
		fingerprint := sha256.Sum256(certificateDER)
		if _, checked := state.authorities[fingerprint]; checked {
			return
		}
		authority, found := fixture.authorities.authorityForIssuer(class, fingerprint)
		lookup := rotationAuthorityLookup{found: found}
		if found {
			if authority.certificate == nil {
				t.Fatalf("usable %s authority lookup %x returned no certificate", class, fingerprint)
			}
			if err := sign.ValidateSigningKey(authority.signer); err != nil {
				t.Fatalf("usable %s authority lookup %x returned invalid signer: %v", class, fingerprint, err)
			}
			lookup.certificateFingerprint = sha256.Sum256(authority.certificate.Raw)
			publicDER, err := x509.MarshalPKIXPublicKey(authority.signer.Public())
			if err != nil {
				t.Fatalf("marshal usable %s authority signer for observable-state check: %v", class, err)
			}
			lookup.signerFingerprint = sha256.Sum256(publicDER)
		}
		state.authorities[fingerprint] = lookup
	}
	for _, certificateDER := range candidates {
		if len(certificateDER) != 0 {
			recordLookup(certificateDER)
		}
	}
	for _, certificateDER := range attemptedCandidateDER {
		// An absent or malformed candidate still has an exact attempted-byte
		// fingerprint whose issuer lookup must remain absent after rejection.
		recordLookup(certificateDER)
	}
	return state
}

func assertRotationAttemptRejectedWithoutEffects(
	t *testing.T,
	fixture *rotationManagerFixture,
	class store.CertificateClass,
	name string,
	attempt func() error,
	attemptedCandidateDER ...[]byte,
) {
	t.Helper()
	before := captureRotationObservableState(t, fixture, class, attemptedCandidateDER...)
	if err := attempt(); err == nil {
		t.Fatalf("%s unexpectedly succeeded", name)
	}
	after := captureRotationObservableState(t, fixture, class, attemptedCandidateDER...)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("%s changed durable version, issuer/CRLs, distribution, or effective snapshot:\n before %+v\n after  %+v", name, before, after)
	}
}

func newRotationCA(t *testing.T, name string, now time.Time) rotationCA {
	t.Helper()
	signer := newEnrollmentSigningKey(t)
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatalf("marshal %s key: %v", name, err)
	}
	keyID := sha256.Sum256(publicDER)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(2 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: bytes.Clone(keyID[:20]), AuthorityKeyId: bytes.Clone(keyID[:20]),
		MaxPathLen: 0, MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return rotationCA{root: root, signer: signer}
}

func crossSignRotationCA(t *testing.T, current, successor rotationCA) []byte {
	t.Helper()
	return crossSignRotationCAWithPublicKey(t, current, successor, successor.signer.Public(), nil)
}

func crossSignRotationCAWithMutation(t *testing.T, current, successor rotationCA, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	return crossSignRotationCAWithPublicKey(t, current, successor, successor.signer.Public(), mutate)
}

func crossSignRotationCAWithPublicKey(
	t *testing.T,
	current, successor rotationCA,
	publicKey crypto.PublicKey,
	mutate func(*x509.Certificate),
) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: successor.root.Subject,
		NotBefore: successor.root.NotBefore, NotAfter: successor.root.NotAfter,
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: successor.root.KeyUsage, SubjectKeyId: bytes.Clone(successor.root.SubjectKeyId),
		AuthorityKeyId: bytes.Clone(current.root.SubjectKeyId), MaxPathLen: 0, MaxPathLenZero: true,
	}
	if mutate != nil {
		mutate(template)
	}
	if !template.IsCA {
		template.MaxPathLen = -1
		template.MaxPathLenZero = false
	}
	der, err := x509.CreateCertificate(rand.Reader, template, current.root, publicKey, current.signer)
	if err != nil {
		t.Fatalf("create rotation transition certificate: %v", err)
	}
	return der
}

func newRotationLeaf(
	t *testing.T,
	authority rotationCA,
	publicKey crypto.PublicKey,
	class store.CertificateClass,
	id string,
	dnsNames []string,
	now time.Time,
	serial int64,
) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	identityClass := identity.AgentClass
	if class == store.CertificateClassAgent {
		template.NotAfter = template.NotBefore.Add(agentCertificateLifetime)
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		identityClass = identity.GatewayClass
		template.NotAfter = template.NotBefore.Add(gatewayCertificateLifetime)
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		template.DNSNames = slices.Clone(dnsNames)
	}
	if err := identity.StampCertificateIdentity(template, identityClass, id); err != nil {
		t.Fatalf("stamp rotation leaf identity: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.root, publicKey, authority.signer)
	if err != nil {
		t.Fatalf("create rotation leaf: %v", err)
	}
	return der
}

func rotationRootFingerprints(roots ...[]byte) [][]byte {
	result := make([][]byte, len(roots))
	for index, root := range roots {
		fingerprint := sha256.Sum256(root)
		result[index] = bytes.Clone(fingerprint[:])
	}
	return result
}

func signRotationClaim(t *testing.T, signer crypto.Signer, claim sign.TrustStateClaim) []byte {
	t.Helper()
	signature, err := sign.SignTrustState(signer, claim)
	if err != nil {
		return []byte("intentionally invalid trust-state fixture")
	}
	return signature
}

func rotationConfirmationEventCount(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM events WHERE event_type LIKE '%TrustConfirmed'`,
	).Scan(&count); err != nil {
		t.Fatalf("count rotation confirmation events: %v", err)
	}
	return count
}

func cloneRotationDERList(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = bytes.Clone(values[index])
	}
	return result
}

func equalRotationDERLists(first, second [][]byte) bool {
	return len(first) == len(second) && slices.EqualFunc(first, second, bytes.Equal)
}

func containsRotationDER(values [][]byte, target []byte) bool {
	return slices.ContainsFunc(values, func(value []byte) bool { return bytes.Equal(value, target) })
}
