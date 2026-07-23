package gateway

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
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
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/gen/go/powermanage/v1/powermanagev1connect"
	"github.com/manchtools/power-manage/contract/identity"
	"github.com/manchtools/power-manage/contract/sign"
)

func TestGatewayClient_RenewsPublishesIdentityBeforeConfirmingTrustState(t *testing.T) {
	exerciseGatewayRenewalInvalidResponses(t)
	exerciseGatewayRenewalPublicationFailure(t)
	exerciseGatewayConfirmationClearReplay(t)

	fixture := newGatewayRenewalContinuityFixture(t)
	fixture.handler.confirmErr = connect.NewError(connect.CodeUnavailable, errors.New("confirmation response lost"))

	_, err := fixture.client.Renew(context.Background(), fixture.current)
	if connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("Renew error = %v; want confirmation unavailable after publication", err)
	}
	if !slices.Equal(*fixture.events, []string{"renew", "publish", "confirm-gateway", "confirm-agent"}) {
		t.Fatalf("gateway renewal order = %v; want renew, atomic publish, then both independent confirmations", *fixture.events)
	}
	published := fixture.publisher.current
	if !bytes.Equal(published.CertificateDER, fixture.handler.issuedCertificateDER) ||
		!bytes.Equal(published.CertificateAuthorityDER, fixture.successorGateway.root.Raw) ||
		published.PendingGatewayTrustConfirmation == nil || published.PendingAgentTrustConfirmation == nil {
		t.Fatalf("published gateway identity = %+v; want successor identity with gateway-leaf and agent-root/CRL claims", published)
	}
	if fixture.publisher.calls != 1 || fixture.publisher.rollbackCalls != 0 {
		t.Fatalf("publication effects = (%d publishes, %d rollbacks); want active successor without rollback",
			fixture.publisher.calls, fixture.publisher.rollbackCalls)
	}

	// A real TLS client must be able to use the identity that remained active
	// after confirmation failed. The transition proof is not sent in its chain.
	certificate := tlsCertificate(t, published.CertificateDER, published.PrivateKey)
	if len(certificate.Certificate) != 1 {
		t.Fatalf("published gateway TLS chain has %d certificates; want leaf only", len(certificate.Certificate))
	}
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	tlsServer.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	tlsServer.StartTLS()
	t.Cleanup(tlsServer.Close)
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(fixture.successorGateway.root)
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: serverRoots, ServerName: fixture.dnsName,
		Time: func() time.Time { return fixture.now },
	}}
	t.Cleanup(transport.CloseIdleConnections)
	response, err := (&http.Client{Transport: transport}).Get(tlsServer.URL)
	if err != nil {
		t.Fatalf("serve with successor gateway identity after confirmation failure: %v", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatalf("close successor gateway TLS response: %v", err)
	}

	if len(fixture.handler.confirmRequests) != 2 {
		t.Fatalf("gateway confirmation requests = %d; want independent same-class leaf and cross-class consumer claims", len(fixture.handler.confirmRequests))
	}
	assertExactGatewayReporterClaims(t, fixture.handler.confirmRequests, published, fixture.agentSuccessorFingerprint)
	wires := make(map[string][]byte, 2)
	for _, request := range fixture.handler.confirmRequests {
		claimedClass := request.GetClaimedClass()
		if claimedClass != "gateway" && claimedClass != "agent" {
			t.Fatalf("gateway reporter claimed unauthorized class %q", claimedClass)
		}
		if !bytes.Equal(request.GetCertificateDer(), published.CertificateDER) {
			t.Fatal("confirmation signature/request was not bound to the exact published reporter certificate")
		}
		if claimedClass == "gateway" && (len(request.GetCrlIssuerFingerprint()) != 0 || request.GetCrlSequence() != 0) {
			t.Fatal("same-class gateway leaf claim carried a forbidden CRL receipt")
		}
		if claimedClass == "agent" && (!bytes.Equal(request.GetCrlIssuerFingerprint(), fixture.agentSuccessorFingerprint) || request.GetCrlSequence() != 17) {
			t.Fatalf("agent-root claim CRL receipt = (%x,%d); want exact successor issuer sequence 17", request.GetCrlIssuerFingerprint(), request.GetCrlSequence())
		}
		wire, marshalErr := proto.Marshal(request)
		if marshalErr != nil {
			t.Fatalf("marshal pending gateway claim: %v", marshalErr)
		}
		wires[claimedClass] = wire
	}

	// A new process must replay both exact durable claims before asking for a
	// newer identity. Clearing either pending claim early can strand the other.
	fixture.handler.confirmErr = nil
	fixture.handler.confirmRequests = nil
	*fixture.events = nil
	restarted, err := NewEnrollmentClient(fixture.client.remote, []string{fixture.dnsName})
	if err != nil {
		t.Fatalf("restart gateway enrollment client: %v", err)
	}
	restarted.publisher = fixture.publisher
	restarted.now = func() time.Time { return fixture.now }
	if _, err := restarted.Renew(context.Background(), published); err != nil {
		t.Fatalf("restart gateway renewal: %v", err)
	}
	if len(*fixture.events) < 4 || (*fixture.events)[0] != "confirm-gateway" || (*fixture.events)[1] != "confirm-agent" ||
		(*fixture.events)[2] != "publish" || (*fixture.events)[3] != "renew" {
		t.Fatalf("gateway restart order = %v; want both pending confirmations, one atomic clear publication, then renewal", *fixture.events)
	}
	if len(fixture.handler.confirmRequests) < 2 {
		t.Fatalf("gateway restart confirmation requests = %d; want both exact replays", len(fixture.handler.confirmRequests))
	}
	for _, request := range fixture.handler.confirmRequests[:2] {
		wire, marshalErr := proto.Marshal(request)
		if marshalErr != nil || !bytes.Equal(wire, wires[request.GetClaimedClass()]) {
			t.Fatalf("restart changed durable %q claim: marshal=%v", request.GetClaimedClass(), marshalErr)
		}
	}
	if fixture.publisher.current.PendingGatewayTrustConfirmation != nil || fixture.publisher.current.PendingAgentTrustConfirmation != nil {
		t.Fatal("successful exact replay did not clear both durable gateway pending claims")
	}
}

func exerciseGatewayRenewalInvalidResponses(t *testing.T) {
	t.Helper()
	t.Run("trust dual bundle accepts current-issued and successor-issued gateway leaves", func(t *testing.T) {
		for _, test := range []struct {
			name      string
			authority func(*gatewayRenewalContinuityFixture) gatewayContinuityCA
		}{
			{name: "current-issued", authority: func(fixture *gatewayRenewalContinuityFixture) gatewayContinuityCA {
				return fixture.handler.currentGateway
			}},
			{name: "successor-issued", authority: func(fixture *gatewayRenewalContinuityFixture) gatewayContinuityCA {
				return fixture.handler.successor
			}},
		} {
			t.Run(test.name, func(t *testing.T) {
				fixture := newGatewayRenewalContinuityFixture(t)
				authority := test.authority(&fixture)
				var issued []byte
				fixture.handler.mutateResponse = func(response *powermanagev1.RenewGatewayResponse) {
					issued = newGatewayContinuityLeaf(
						t, authority, fixture.current.PrivateKey.Public(), fixture.dnsName, fixture.now, 90,
					)
					response.CertificateDer = bytes.Clone(issued)
				}
				if _, err := fixture.client.Renew(context.Background(), fixture.current); err != nil {
					t.Fatalf("dual-bundle %s gateway renewal: %v", test.name, err)
				}
				if !bytes.Equal(fixture.publisher.current.CertificateDER, issued) ||
					fixture.publisher.calls == 0 || len(fixture.handler.confirmRequests) != 2 {
					t.Fatalf("dual-bundle %s effects = (%d publications, %d confirmations); want accepted exact identity and two claims",
						test.name, fixture.publisher.calls, len(fixture.handler.confirmRequests))
				}
				certificate, err := x509.ParseCertificate(issued)
				if err != nil || certificate.CheckSignatureFrom(authority.root) != nil {
					t.Fatalf("dual-bundle %s leaf does not verify from selected overlap issuer: %v", test.name, err)
				}
				assertExactGatewayReporterClaims(t, fixture.handler.confirmRequests, fixture.publisher.current, fixture.agentSuccessorFingerprint)
			})
		}
	})

	t.Run("invalid response matrix has no publication or confirmation", func(t *testing.T) {
		tests := []struct {
			name    string
			wantErr string
			mutate  func(*testing.T, *gatewayRenewalContinuityFixture, *powermanagev1.RenewGatewayResponse)
		}{
			{name: "missing agent bundle", wantErr: "missing the agent trust bundle", mutate: func(_ *testing.T, _ *gatewayRenewalContinuityFixture, response *powermanagev1.RenewGatewayResponse) {
				response.AgentTrustBundle = nil
			}},
			{name: "missing gateway bundle", wantErr: "missing the gateway trust bundle", mutate: func(_ *testing.T, _ *gatewayRenewalContinuityFixture, response *powermanagev1.RenewGatewayResponse) {
				response.GatewayTrustBundle = nil
			}},
			{name: "missing issued leaf", wantErr: "certificate", mutate: func(_ *testing.T, _ *gatewayRenewalContinuityFixture, response *powermanagev1.RenewGatewayResponse) {
				response.CertificateDer = nil
			}},
			{name: "malformed issued leaf", wantErr: "certificate", mutate: func(_ *testing.T, _ *gatewayRenewalContinuityFixture, response *powermanagev1.RenewGatewayResponse) {
				response.CertificateDer = []byte("not DER")
			}},
			{name: "trailing issued leaf DER", wantErr: "certificate", mutate: func(_ *testing.T, _ *gatewayRenewalContinuityFixture, response *powermanagev1.RenewGatewayResponse) {
				response.CertificateDer = append(response.CertificateDer, 0)
			}},
			{name: "issued leaf has wrong key", wantErr: "public key", mutate: func(t *testing.T, fixture *gatewayRenewalContinuityFixture, response *powermanagev1.RenewGatewayResponse) {
				wrong, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("generate wrong gateway leaf key: %v", err)
				}
				response.CertificateDer = newGatewayContinuityLeaf(t, fixture.successorGateway, wrong.Public(), fixture.dnsName, fixture.now, 91)
			}},
			{name: "issued leaf has unrelated issuer outside dual bundle", wantErr: "issuer", mutate: func(t *testing.T, fixture *gatewayRenewalContinuityFixture, response *powermanagev1.RenewGatewayResponse) {
				unrelated := newGatewayContinuityCA(t, "unrelated gateway leaf issuer", fixture.now)
				response.CertificateDer = newGatewayContinuityLeaf(t, unrelated, fixture.current.PrivateKey.Public(), fixture.dnsName, fixture.now, 92)
			}},
			{name: "issued leaf has wrong DNS", wantErr: "DNS", mutate: func(t *testing.T, fixture *gatewayRenewalContinuityFixture, response *powermanagev1.RenewGatewayResponse) {
				response.CertificateDer = newGatewayContinuityLeaf(t, fixture.successorGateway, fixture.current.PrivateKey.Public(), "attacker.invalid", fixture.now, 93)
			}},
			{name: "issued leaf has agent identity", wantErr: "class", mutate: func(t *testing.T, fixture *gatewayRenewalContinuityFixture, response *powermanagev1.RenewGatewayResponse) {
				response.CertificateDer = newGatewayContinuityAgentLeaf(t, fixture.successorGateway, fixture.current.PrivateKey.Public(), fixture.now, 94)
			}},
			{name: "issued leaf has wrong gateway identity", wantErr: "identity", mutate: func(t *testing.T, fixture *gatewayRenewalContinuityFixture, response *powermanagev1.RenewGatewayResponse) {
				response.CertificateDer = newGatewayContinuityLeafWithProfile(t, fixture.successorGateway, fixture.current.PrivateKey.Public(), "01J00000000000000000000999", []string{fixture.dnsName}, fixture.now, 95, nil)
			}},
			{name: "issued leaf has extra DNS", wantErr: "DNS", mutate: func(t *testing.T, fixture *gatewayRenewalContinuityFixture, response *powermanagev1.RenewGatewayResponse) {
				response.CertificateDer = newGatewayContinuityLeafWithProfile(t, fixture.successorGateway, fixture.current.PrivateKey.Public(), gatewayClientFirstID, []string{fixture.dnsName, "attacker.invalid"}, fixture.now, 96, nil)
			}},
			{name: "issued leaf is expired", wantErr: "expired", mutate: func(t *testing.T, fixture *gatewayRenewalContinuityFixture, response *powermanagev1.RenewGatewayResponse) {
				response.CertificateDer = newGatewayContinuityLeafWithProfile(t, fixture.successorGateway, fixture.current.PrivateKey.Public(), gatewayClientFirstID, []string{fixture.dnsName}, fixture.now, 97, func(c *x509.Certificate) {
					c.NotBefore = fixture.now.Add(-2 * time.Hour)
					c.NotAfter = fixture.now.Add(-time.Hour)
				})
			}},
			{name: "issued leaf lacks client auth", wantErr: "usage", mutate: func(t *testing.T, fixture *gatewayRenewalContinuityFixture, response *powermanagev1.RenewGatewayResponse) {
				response.CertificateDer = newGatewayContinuityLeafWithProfile(t, fixture.successorGateway, fixture.current.PrivateKey.Public(), gatewayClientFirstID, []string{fixture.dnsName}, fixture.now, 98, func(c *x509.Certificate) {
					c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
				})
			}},
		}
		for _, class := range []string{"agent", "gateway"} {
			class := class
			bundleCase := func(name, wantErr string, mutate func(*testing.T, *gatewayRenewalContinuityFixture, *powermanagev1.CATrustBundle)) {
				tests = append(tests, struct {
					name    string
					wantErr string
					mutate  func(*testing.T, *gatewayRenewalContinuityFixture, *powermanagev1.RenewGatewayResponse)
				}{name: class + " " + name, wantErr: wantErr, mutate: func(t *testing.T, fixture *gatewayRenewalContinuityFixture, response *powermanagev1.RenewGatewayResponse) {
					mutate(t, fixture, gatewayResponseBundle(response, class))
				}})
			}
			bundleCase("zero generation", "generation", func(_ *testing.T, _ *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				bundle.Generation = 0
			})
			bundleCase("zero revision", "revision", func(_ *testing.T, _ *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				bundle.Revision = 0
			})
			bundleCase("lower generation", "generation", func(_ *testing.T, fixture *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				current := gatewayCurrentTrustBundle(fixture, class)
				bundle.Generation = current.Generation - 1
				bundle.Revision = current.Revision + 1
			})
			bundleCase("lower same-generation revision", "revision", func(_ *testing.T, fixture *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				current := gatewayCurrentTrustBundle(fixture, class)
				bundle.Generation = current.Generation
				bundle.Revision = current.Revision - 1
			})
			bundleCase("same tuple with different roots and proof", "version", func(_ *testing.T, fixture *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				current := gatewayCurrentTrustBundle(fixture, class)
				bundle.Generation = current.Generation
				bundle.Revision = current.Revision
			})
			bundleCase("empty roots", "root bundle", func(_ *testing.T, _ *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				bundle.RootCertificateDer = nil
			})
			bundleCase("duplicate roots", "duplicate", func(_ *testing.T, _ *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				bundle.RootCertificateDer[1] = bytes.Clone(bundle.RootCertificateDer[0])
			})
			bundleCase("reversed roots", "order", func(_ *testing.T, _ *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				bundle.RootCertificateDer[0], bundle.RootCertificateDer[1] = bundle.RootCertificateDer[1], bundle.RootCertificateDer[0]
			})
			bundleCase("three roots", "root bundle", func(t *testing.T, fixture *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				third := newGatewayContinuityCA(t, class+" third", fixture.now)
				bundle.RootCertificateDer = append(bundle.RootCertificateDer, third.root.Raw)
			})
			bundleCase("malformed successor root", "root", func(_ *testing.T, _ *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				bundle.RootCertificateDer[1] = []byte("not DER")
			})
			bundleCase("trailing successor root DER", "root", func(_ *testing.T, _ *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				bundle.RootCertificateDer[1] = append(bundle.RootCertificateDer[1], 0)
			})
			bundleCase("transition used as root", "self", func(_ *testing.T, _ *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				bundle.RootCertificateDer[1] = bytes.Clone(bundle.TransitionCertificateDer)
			})
			bundleCase("bad successor self signature", "self", func(_ *testing.T, _ *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				bundle.RootCertificateDer[1] = bytes.Clone(bundle.RootCertificateDer[1])
				bundle.RootCertificateDer[1][len(bundle.RootCertificateDer[1])-1] ^= 0xff
			})
			bundleCase("reused authority key", "reused", func(t *testing.T, fixture *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				current, _ := gatewayResponseAuthorities(fixture, class)
				reused := newGatewayContinuityCAWithSigner(t, class+" reused", fixture.now, current.signer)
				bundle.RootCertificateDer[1] = reused.root.Raw
				bundle.TransitionCertificateDer = crossSignGatewayContinuityCA(t, current, reused)
			})
			for _, rootCase := range []struct {
				name   string
				mutate func(*x509.Certificate)
			}{
				{name: "not a CA", mutate: func(c *x509.Certificate) {
					c.IsCA = false
					c.MaxPathLen = -1
					c.MaxPathLenZero = false
				}},
				{name: "basic constraints invalid", mutate: func(c *x509.Certificate) { c.BasicConstraintsValid = false }},
				{name: "path length drift", mutate: func(c *x509.Certificate) { c.MaxPathLen = 1; c.MaxPathLenZero = false }},
				{name: "key usage drift", mutate: func(c *x509.Certificate) { c.KeyUsage &^= x509.KeyUsageCRLSign }},
				{name: "unsupported critical extension", mutate: func(c *x509.Certificate) {
					c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 6007}, Critical: true, Value: []byte{5, 0}}}
				}},
				{name: "not yet valid", mutate: func(c *x509.Certificate) {
					c.NotBefore = c.NotAfter.Add(time.Hour)
					c.NotAfter = c.NotBefore.Add(time.Hour)
				}},
				{name: "expired", mutate: func(c *x509.Certificate) {
					c.NotBefore = c.NotBefore.Add(-2 * 365 * 24 * time.Hour)
					c.NotAfter = c.NotBefore.Add(time.Hour)
				}},
			} {
				rootCase := rootCase
				bundleCase("successor root "+rootCase.name, "root", func(t *testing.T, fixture *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
					current, _ := gatewayResponseAuthorities(fixture, class)
					signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					if err != nil {
						t.Fatalf("generate invalid successor root key: %v", err)
					}
					invalid := newGatewayContinuityCAWithSignerAndMutation(t, class+" invalid successor", fixture.now, signer, rootCase.mutate)
					bundle.RootCertificateDer[1] = invalid.root.Raw
					bundle.TransitionCertificateDer = crossSignGatewayContinuityCA(t, current, invalid)
				})
			}
			bundleCase("missing proof", "transition", func(_ *testing.T, _ *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				bundle.TransitionCertificateDer = nil
			})
			bundleCase("malformed proof", "transition", func(_ *testing.T, _ *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				bundle.TransitionCertificateDer = []byte("not DER")
			})
			bundleCase("trailing proof DER", "transition", func(_ *testing.T, _ *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				bundle.TransitionCertificateDer = append(bundle.TransitionCertificateDer, 0)
			})
			for _, proofCase := range []struct {
				name   string
				mutate func(*x509.Certificate)
			}{
				{name: "subject drift", mutate: func(c *x509.Certificate) { c.Subject.CommonName = "drift" }},
				{name: "SKI drift", mutate: func(c *x509.Certificate) { c.SubjectKeyId = []byte("drift") }},
				{name: "not a CA", mutate: func(c *x509.Certificate) {
					c.IsCA = false
					c.MaxPathLen = -1
					c.MaxPathLenZero = false
				}},
				{name: "basic constraints drift", mutate: func(c *x509.Certificate) { c.BasicConstraintsValid = false }},
				{name: "path length drift", mutate: func(c *x509.Certificate) { c.MaxPathLen = 1; c.MaxPathLenZero = false }},
				{name: "key usage drift", mutate: func(c *x509.Certificate) { c.KeyUsage &^= x509.KeyUsageCRLSign }},
				{name: "AKI drift", mutate: func(c *x509.Certificate) {
					c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{
						Id: asn1.ObjectIdentifier{2, 5, 29, 35}, Value: []byte{0x30, 0x07, 0x80, 0x05, 'd', 'r', 'i', 'f', 't'},
					})
				}},
				{name: "unsupported critical extension", mutate: func(c *x509.Certificate) {
					c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 6006}, Critical: true, Value: []byte{5, 0}}}
				}},
				{name: "not yet valid", mutate: func(c *x509.Certificate) {
					c.NotBefore = c.NotAfter.Add(time.Hour)
					c.NotAfter = c.NotBefore.Add(time.Hour)
				}},
				{name: "expired", mutate: func(c *x509.Certificate) {
					c.NotBefore = c.NotBefore.Add(-2 * 365 * 24 * time.Hour)
					c.NotAfter = c.NotBefore.Add(time.Hour)
				}},
			} {
				proofCase := proofCase
				bundleCase("proof "+proofCase.name, "transition", func(t *testing.T, fixture *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
					current, successor := gatewayResponseAuthorities(fixture, class)
					bundle.TransitionCertificateDer = crossSignGatewayContinuityCAWithMutation(t, current, successor, proofCase.mutate)
				})
			}
			bundleCase("proof public key drift", "public key", func(t *testing.T, fixture *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				current, successor := gatewayResponseAuthorities(fixture, class)
				wrong, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("generate proof drift key: %v", err)
				}
				bundle.TransitionCertificateDer = crossSignGatewayContinuityCAWithPublicKey(t, current, successor, wrong.Public(), nil)
			})
			bundleCase("proof wrong issuer", "issuer", func(t *testing.T, fixture *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				_, successor := gatewayResponseAuthorities(fixture, class)
				unrelated := newGatewayContinuityCA(t, class+" unrelated", fixture.now)
				bundle.TransitionCertificateDer = crossSignGatewayContinuityCA(t, unrelated, successor)
			})
			bundleCase("unchanged root with injected proof", "unchanged", func(_ *testing.T, _ *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				bundle.RootCertificateDer = bundle.RootCertificateDer[:1]
			})
			bundleCase("other class proof", "transition", func(_ *testing.T, fixture *gatewayRenewalContinuityFixture, bundle *powermanagev1.CATrustBundle) {
				if class == "agent" {
					bundle.TransitionCertificateDer = bytes.Clone(fixture.handler.gatewayTransitionDER)
				} else {
					bundle.TransitionCertificateDer = bytes.Clone(fixture.handler.agentTransitionDER)
				}
			})
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				fixture := newGatewayRenewalContinuityFixture(t)
				before := cloneGatewayIdentity(fixture.current)
				fixture.handler.mutateResponse = func(response *powermanagev1.RenewGatewayResponse) { test.mutate(t, &fixture, response) }
				_, err := fixture.client.Renew(context.Background(), fixture.current)
				if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.wantErr)) {
					t.Fatalf("invalid gateway renewal error = %v; want category %q", err, test.wantErr)
				}
				if fixture.publisher.calls != 0 || len(fixture.handler.confirmRequests) != 0 {
					t.Fatalf("invalid gateway renewal effects = (%d publications, %d confirmations); want none", fixture.publisher.calls, len(fixture.handler.confirmRequests))
				}
				assertGatewayIdentityEqual(t, fixture.publisher.current, before)
			})
		}
	})
}

func exerciseGatewayRenewalPublicationFailure(t *testing.T) {
	t.Helper()
	t.Run("publication failure leaves old identity active and sends no confirmation", func(t *testing.T) {
		fixture := newGatewayRenewalContinuityFixture(t)
		before := cloneGatewayIdentity(fixture.publisher.current)
		publishErr := errors.New("atomic serving identity publication failed")
		fixture.publisher.failCalls = map[int]error{1: publishErr}
		if _, err := fixture.client.Renew(context.Background(), fixture.current); err == nil || !strings.Contains(err.Error(), publishErr.Error()) {
			t.Fatalf("gateway renewal publication error = %v; want exact publication failure", err)
		}
		if fixture.publisher.calls != 1 || len(fixture.handler.confirmRequests) != 0 || fixture.publisher.rollbackCalls != 0 {
			t.Fatalf("failed publication effects = (%d publish attempts, %d confirmations, %d rollbacks); want old-active/no-confirm",
				fixture.publisher.calls, len(fixture.handler.confirmRequests), fixture.publisher.rollbackCalls)
		}
		assertGatewayIdentityEqual(t, fixture.publisher.current, before)
	})
}

func exerciseGatewayConfirmationClearReplay(t *testing.T) {
	t.Helper()
	t.Run("server-confirmed local-clear failure replays both exact claims after restart", func(t *testing.T) {
		fixture := newGatewayRenewalContinuityFixture(t)
		clearErr := errors.New("durable pending clear failed")
		fixture.publisher.failCalls = map[int]error{2: clearErr}
		if _, err := fixture.client.Renew(context.Background(), fixture.current); err == nil || !strings.Contains(err.Error(), clearErr.Error()) {
			t.Fatalf("gateway renewal clear error = %v; want exact local clear failure", err)
		}
		pending := cloneGatewayIdentity(fixture.publisher.current)
		if pending.PendingGatewayTrustConfirmation == nil || pending.PendingAgentTrustConfirmation == nil || len(fixture.handler.confirmRequests) != 2 {
			t.Fatalf("clear-failed active identity has pending gateway/agent = %v/%v and %d requests; want both server-confirmed claims still durable",
				pending.PendingGatewayTrustConfirmation != nil, pending.PendingAgentTrustConfirmation != nil, len(fixture.handler.confirmRequests))
		}
		assertExactGatewayReporterClaims(t, fixture.handler.confirmRequests, pending, fixture.agentSuccessorFingerprint)
		wires := gatewayConfirmationWires(t, fixture.handler.confirmRequests)
		fixture.publisher.failCalls = nil
		fixture.handler.confirmRequests = nil
		*fixture.events = nil
		restarted, err := NewEnrollmentClient(fixture.client.remote, []string{fixture.dnsName})
		if err != nil {
			t.Fatalf("restart gateway client after local clear failure: %v", err)
		}
		restarted.publisher = fixture.publisher
		restarted.now = func() time.Time { return fixture.now }
		if _, err := restarted.Renew(context.Background(), pending); err != nil {
			t.Fatalf("restart gateway renewal after local clear failure: %v", err)
		}
		if len(*fixture.events) < 3 || (*fixture.events)[0] != "confirm-gateway" || (*fixture.events)[1] != "confirm-agent" || (*fixture.events)[2] != "publish" {
			t.Fatalf("clear-failure restart order = %v; want both exact pending claims before one local clear", *fixture.events)
		}
		if len(fixture.handler.confirmRequests) < 2 {
			t.Fatalf("clear-failure restart confirmations = %d; want both exact replays", len(fixture.handler.confirmRequests))
		}
		for _, request := range fixture.handler.confirmRequests[:2] {
			wire, marshalErr := proto.Marshal(request)
			if marshalErr != nil || !bytes.Equal(wire, wires[request.GetClaimedClass()]) {
				t.Fatalf("clear-failure restart changed %q claim: marshal=%v", request.GetClaimedClass(), marshalErr)
			}
		}
		if fixture.publisher.current.PendingGatewayTrustConfirmation != nil || fixture.publisher.current.PendingAgentTrustConfirmation != nil {
			t.Fatal("clear-failure restart did not independently clear both replayed pending claims")
		}
	})
}

func gatewayResponseBundle(response *powermanagev1.RenewGatewayResponse, class string) *powermanagev1.CATrustBundle {
	if class == "agent" {
		return response.AgentTrustBundle
	}
	return response.GatewayTrustBundle
}

func gatewayCurrentTrustBundle(fixture *gatewayRenewalContinuityFixture, class string) GatewayTrustBundle {
	if class == "agent" {
		return fixture.current.AgentTrustBundle
	}
	return fixture.current.GatewayTrustBundle
}

func gatewayResponseAuthorities(fixture *gatewayRenewalContinuityFixture, class string) (gatewayContinuityCA, gatewayContinuityCA) {
	if class == "agent" {
		return fixture.handler.agentCurrent, fixture.handler.agentSuccessor
	}
	return fixture.handler.currentGateway, fixture.handler.successor
}

func gatewayConfirmationWires(t *testing.T, requests []*powermanagev1.ConfirmTrustStateRequest) map[string][]byte {
	t.Helper()
	if len(requests) != 2 {
		t.Fatalf("gateway confirmation claims = %d; want exact gateway-leaf and agent-consumer claims", len(requests))
	}
	wires := make(map[string][]byte, 2)
	for _, request := range requests {
		class := request.GetClaimedClass()
		if (class != "agent" && class != "gateway") || wires[class] != nil {
			t.Fatalf("gateway confirmation classes contain duplicate/unknown %q", class)
		}
		wire, err := proto.Marshal(request)
		if err != nil {
			t.Fatalf("marshal gateway confirmation %q: %v", class, err)
		}
		wires[class] = wire
	}
	return wires
}

func assertExactGatewayReporterClaims(
	t *testing.T,
	requests []*powermanagev1.ConfirmTrustStateRequest,
	identity Identity,
	agentCRLIssuerFingerprint []byte,
) {
	t.Helper()
	if len(requests) != 2 {
		t.Fatalf("gateway reporter claims = %d; want exact gateway-leaf and agent-consumer claims", len(requests))
	}
	seen := make(map[string]bool, 2)
	for _, request := range requests {
		claimedClass := request.GetClaimedClass()
		if err := verifyGatewayTrustStateRequest(request, identity.CertificateDER); err != nil {
			t.Fatalf("gateway procedure captured an invalid exact signed request: %v", err)
		}
		if !bytes.Equal(request.GetCertificateDer(), identity.CertificateDER) ||
			(claimedClass != "gateway" && claimedClass != "agent") || seen[claimedClass] {
			t.Fatalf("gateway reporter claim = class %q certificate %x; want exact independent claims bound to active identity",
				claimedClass, request.GetCertificateDer())
		}
		seen[claimedClass] = true
		bundle := identity.GatewayTrustBundle
		if claimedClass == "agent" {
			bundle = identity.AgentTrustBundle
		}
		if request.GetGeneration() != bundle.Generation || request.GetRevision() != bundle.Revision ||
			!equalGatewayDERLists(request.GetRootFingerprints(), gatewayRootFingerprints(bundle.RootCertificateDER...)) {
			t.Fatalf("gateway %s claim bundle = (%d,%d,%x); want exact active bundle (%d,%d,%x)", claimedClass,
				request.GetGeneration(), request.GetRevision(), request.GetRootFingerprints(), bundle.Generation, bundle.Revision, gatewayRootFingerprints(bundle.RootCertificateDER...))
		}
		if claimedClass == "gateway" && (len(request.GetCrlIssuerFingerprint()) != 0 || request.GetCrlSequence() != 0) {
			t.Fatal("gateway leaf claim carried a forbidden CRL receipt")
		}
		if claimedClass == "agent" && (!bytes.Equal(request.GetCrlIssuerFingerprint(), agentCRLIssuerFingerprint) || request.GetCrlSequence() != bundle.CRLSequence) {
			t.Fatalf("gateway agent-root claim CRL receipt = (%x,%d); want exact issuer %x sequence %d",
				request.GetCrlIssuerFingerprint(), request.GetCrlSequence(), agentCRLIssuerFingerprint, bundle.CRLSequence)
		}
	}
}

func verifyGatewayTrustStateRequest(
	request *powermanagev1.ConfirmTrustStateRequest,
	activeCertificateDER ...[]byte,
) error {
	if request == nil {
		return errors.New("nil gateway trust-state request")
	}
	certificate, err := x509.ParseCertificate(request.GetCertificateDer())
	if err != nil || !bytes.Equal(certificate.Raw, request.GetCertificateDer()) {
		return errors.New("gateway reporter certificate is not exact DER")
	}
	if len(activeCertificateDER) > 0 && !bytes.Equal(request.GetCertificateDer(), activeCertificateDER[0]) {
		return errors.New("gateway reporter certificate is not the active serving identity")
	}
	class, _, err := identity.ParseCertificateIdentity(certificate)
	if err != nil || class != identity.GatewayClass {
		return errors.New("gateway reporter certificate does not match the invoked gateway procedure")
	}
	reporterFingerprint := sha256.Sum256(request.GetCertificateDer())
	claim := sign.TrustStateClaim{
		ReporterClass: "gateway", ClaimedClass: request.GetClaimedClass(),
		Generation: request.GetGeneration(), Revision: request.GetRevision(),
		ReporterCertificateFingerprint: bytes.Clone(reporterFingerprint[:]),
		RootFingerprints:               cloneGatewayDERList(request.GetRootFingerprints()),
		CRLIssuerFingerprint:           bytes.Clone(request.GetCrlIssuerFingerprint()),
		CRLSequence:                    request.GetCrlSequence(),
	}
	if len(request.GetSignature()) == 0 {
		return errors.New("gateway trust-state signature is empty")
	}
	return sign.VerifyTrustState(certificate.PublicKey, claim, request.GetSignature())
}

func gatewayRootFingerprints(roots ...[]byte) [][]byte {
	result := make([][]byte, len(roots))
	for index, root := range roots {
		fingerprint := sha256.Sum256(root)
		result[index] = bytes.Clone(fingerprint[:])
	}
	return result
}

func equalGatewayDERLists(first, second [][]byte) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if !bytes.Equal(first[index], second[index]) {
			return false
		}
	}
	return true
}

func assertGatewayIdentityEqual(t *testing.T, got, want Identity) {
	t.Helper()
	if !reflect.DeepEqual(cloneGatewayIdentity(got), cloneGatewayIdentity(want)) {
		t.Fatalf("gateway identity changed:\n got %+v\nwant %+v", got, want)
	}
}

type gatewayRenewalContinuityFixture struct {
	client                    *EnrollmentClient
	handler                   *gatewayRenewalContinuityHandler
	publisher                 *recordingGatewayIdentityPublisher
	current                   Identity
	successorGateway          gatewayContinuityCA
	agentSuccessorFingerprint []byte
	dnsName                   string
	now                       time.Time
	events                    *[]string
}

type recordingGatewayIdentityPublisher struct {
	events        *[]string
	current       Identity
	calls         int
	rollbackCalls int
	failCalls     map[int]error
}

func (p *recordingGatewayIdentityPublisher) Publish(_ context.Context, identity Identity) error {
	*p.events = append(*p.events, "publish")
	p.calls++
	if err := p.failCalls[p.calls]; err != nil {
		return err
	}
	p.current = cloneGatewayIdentity(identity)
	return nil
}

func (p *recordingGatewayIdentityPublisher) Rollback(context.Context) error {
	p.rollbackCalls++
	return nil
}

type gatewayRenewalContinuityHandler struct {
	powermanagev1connect.UnimplementedPkiServiceHandler

	now                  time.Time
	dnsName              string
	successor            gatewayContinuityCA
	currentGateway       gatewayContinuityCA
	agentCurrent         gatewayContinuityCA
	agentSuccessor       gatewayContinuityCA
	gatewayTransitionDER []byte
	agentTransitionDER   []byte
	issuedCertificateDER []byte
	confirmErr           error
	events               *[]string
	confirmRequests      []*powermanagev1.ConfirmTrustStateRequest
	mutateResponse       func(*powermanagev1.RenewGatewayResponse)
	activeCertificateDER func() []byte
}

func newGatewayRenewalContinuityFixture(t *testing.T) gatewayRenewalContinuityFixture {
	t.Helper()
	now := time.Date(2026, time.July, 23, 10, 0, 0, 0, time.UTC)
	currentGateway := newGatewayContinuityCA(t, "gateway current", now)
	successorGateway := newGatewayContinuityCA(t, "gateway successor", now)
	agentCurrent := newGatewayContinuityCA(t, "agent current", now)
	agentSuccessor := newGatewayContinuityCA(t, "agent successor", now)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate current gateway key: %v", err)
	}
	const dnsName = "gateway.internal.example"
	currentDER := newGatewayContinuityLeaf(t, currentGateway, key.Public(), dnsName, now, 10)
	events := []string{}
	handler := &gatewayRenewalContinuityHandler{
		now: now, dnsName: dnsName, currentGateway: currentGateway, successor: successorGateway,
		agentCurrent: agentCurrent, agentSuccessor: agentSuccessor,
		gatewayTransitionDER: crossSignGatewayContinuityCA(t, currentGateway, successorGateway),
		agentTransitionDER:   crossSignGatewayContinuityCA(t, agentCurrent, agentSuccessor),
		events:               &events,
	}
	path, connectHandler := powermanagev1connect.NewPkiServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, connectHandler)
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	client, err := NewEnrollmentClient(
		powermanagev1connect.NewPkiServiceClient(server.Client(), server.URL), []string{dnsName},
	)
	if err != nil {
		t.Fatalf("NewEnrollmentClient: %v", err)
	}
	current := Identity{
		GatewayID: gatewayClientFirstID, CertificateDER: currentDER,
		CertificateAuthorityDER: currentGateway.root.Raw, DNSNames: []string{dnsName}, PrivateKey: key,
		AgentTrustBundle: GatewayTrustBundle{
			Generation: 4, Revision: 2, RootCertificateDER: [][]byte{agentCurrent.root.Raw},
			CRLIssuerFingerprint: sha256FingerprintBytes(agentSuccessor.root.Raw), CRLSequence: 17,
		},
		GatewayTrustBundle: GatewayTrustBundle{Generation: 8, Revision: 5, RootCertificateDER: [][]byte{currentGateway.root.Raw}},
	}
	publisher := &recordingGatewayIdentityPublisher{events: &events, current: cloneGatewayIdentity(current)}
	handler.activeCertificateDER = func() []byte {
		return bytes.Clone(publisher.current.CertificateDER)
	}
	client.publisher = publisher
	client.now = func() time.Time { return now }
	return gatewayRenewalContinuityFixture{
		client: client, handler: handler, publisher: publisher, current: current,
		successorGateway: successorGateway, agentSuccessorFingerprint: sha256FingerprintBytes(agentSuccessor.root.Raw),
		dnsName: dnsName, now: now, events: &events,
	}
}

func (h *gatewayRenewalContinuityHandler) RenewGateway(_ context.Context, request *connect.Request[powermanagev1.RenewGatewayRequest]) (*connect.Response[powermanagev1.RenewGatewayResponse], error) {
	*h.events = append(*h.events, "renew")
	csr, err := x509.ParseCertificateRequest(request.Msg.GetCertificateSigningRequestDer())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	h.issuedCertificateDER = newGatewayContinuityLeafWithoutTest(
		h.successor, csr.PublicKey, h.dnsName, h.now, 11,
	)
	if len(h.issuedCertificateDER) == 0 {
		return nil, connect.NewError(connect.CodeInternal, errors.New("create successor gateway identity"))
	}
	response := &powermanagev1.RenewGatewayResponse{
		CertificateDer: h.issuedCertificateDER,
		AgentTrustBundle: &powermanagev1.CATrustBundle{
			Generation: 5, Revision: 1,
			RootCertificateDer:       [][]byte{h.agentCurrent.root.Raw, h.agentSuccessor.root.Raw},
			TransitionCertificateDer: h.agentTransitionDER,
			CrlIssuerFingerprint:     sha256FingerprintBytes(h.agentSuccessor.root.Raw),
			CrlSequence:              17,
		},
		GatewayTrustBundle: &powermanagev1.CATrustBundle{
			Generation: 9, Revision: 1, RootCertificateDer: [][]byte{h.currentGateway.root.Raw, h.successor.root.Raw},
			TransitionCertificateDer: h.gatewayTransitionDER,
		},
	}
	if h.mutateResponse != nil {
		h.mutateResponse(response)
	}
	return connect.NewResponse(response), nil
}

func (h *gatewayRenewalContinuityHandler) ConfirmGatewayTrustState(_ context.Context, request *connect.Request[powermanagev1.ConfirmTrustStateRequest]) (*connect.Response[powermanagev1.ConfirmTrustStateResponse], error) {
	if h.activeCertificateDER == nil {
		return nil, connect.NewError(connect.CodeInternal, errors.New("active gateway identity is not wired"))
	}
	if err := verifyGatewayTrustStateRequest(request.Msg, h.activeCertificateDER()); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	h.confirmRequests = append(h.confirmRequests, proto.Clone(request.Msg).(*powermanagev1.ConfirmTrustStateRequest))
	*h.events = append(*h.events, "confirm-"+request.Msg.GetClaimedClass())
	if h.confirmErr != nil {
		return nil, h.confirmErr
	}
	return connect.NewResponse(&powermanagev1.ConfirmTrustStateResponse{}), nil
}

type gatewayContinuityCA struct {
	root   *x509.Certificate
	signer crypto.Signer
}

func newGatewayContinuityCA(t *testing.T, name string, now time.Time) gatewayContinuityCA {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate %s key: %v", name, err)
	}
	return newGatewayContinuityCAWithSigner(t, name, now, signer)
}

func newGatewayContinuityCAWithSigner(t *testing.T, name string, now time.Time, signer crypto.Signer) gatewayContinuityCA {
	t.Helper()
	return newGatewayContinuityCAWithSignerAndMutation(t, name, now, signer, nil)
}

func newGatewayContinuityCAWithSignerAndMutation(
	t *testing.T,
	name string,
	now time.Time,
	signer crypto.Signer,
	mutate func(*x509.Certificate),
) gatewayContinuityCA {
	t.Helper()
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatalf("marshal %s key: %v", name, err)
	}
	keyID := sha256.Sum256(publicDER)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: bytes.Clone(keyID[:20]), AuthorityKeyId: bytes.Clone(keyID[:20]),
		MaxPathLen: 0, MaxPathLenZero: true,
	}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return gatewayContinuityCA{root: root, signer: signer}
}

func crossSignGatewayContinuityCA(t *testing.T, current, successor gatewayContinuityCA) []byte {
	t.Helper()
	return crossSignGatewayContinuityCAWithPublicKey(t, current, successor, successor.signer.Public(), nil)
}

func crossSignGatewayContinuityCAWithMutation(t *testing.T, current, successor gatewayContinuityCA, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	return crossSignGatewayContinuityCAWithPublicKey(t, current, successor, successor.signer.Public(), mutate)
}

func crossSignGatewayContinuityCAWithPublicKey(
	t *testing.T,
	current, successor gatewayContinuityCA,
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
	der, err := x509.CreateCertificate(rand.Reader, template, current.root, publicKey, current.signer)
	if err != nil {
		t.Fatalf("create gateway transition certificate: %v", err)
	}
	return der
}

func newGatewayContinuityAgentLeaf(
	t *testing.T,
	authority gatewayContinuityCA,
	publicKey crypto.PublicKey,
	now time.Time,
	serial int64,
) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(-time.Minute).Add(gatewayCertificateLifetime), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if err := identity.StampCertificateIdentity(template, identity.AgentClass, gatewayClientFirstID); err != nil {
		t.Fatalf("stamp wrong-class gateway renewal leaf: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.root, publicKey, authority.signer)
	if err != nil {
		t.Fatalf("create wrong-class gateway renewal leaf: %v", err)
	}
	return der
}

func newGatewayContinuityLeaf(
	t *testing.T,
	authority gatewayContinuityCA,
	publicKey crypto.PublicKey,
	dnsName string,
	now time.Time,
	serial int64,
) []byte {
	t.Helper()
	der := newGatewayContinuityLeafWithoutTest(authority, publicKey, dnsName, now, serial)
	if len(der) == 0 {
		t.Fatal("create gateway continuity leaf")
	}
	return der
}

func newGatewayContinuityLeafWithProfile(
	t *testing.T,
	authority gatewayContinuityCA,
	publicKey crypto.PublicKey,
	gatewayID string,
	dnsNames []string,
	now time.Time,
	serial int64,
	mutate func(*x509.Certificate),
) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(-time.Minute).Add(gatewayCertificateLifetime), BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    slices.Clone(dnsNames),
	}
	if err := identity.StampCertificateIdentity(template, identity.GatewayClass, gatewayID); err != nil {
		t.Fatalf("stamp gateway continuity profile: %v", err)
	}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.root, publicKey, authority.signer)
	if err != nil {
		t.Fatalf("create gateway continuity profile: %v", err)
	}
	return der
}

func newGatewayContinuityLeafWithoutTest(
	authority gatewayContinuityCA,
	publicKey crypto.PublicKey,
	dnsName string,
	now time.Time,
	serial int64,
) []byte {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial), NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(-time.Minute).Add(gatewayCertificateLifetime), BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{dnsName},
	}
	if err := identity.StampCertificateIdentity(template, identity.GatewayClass, gatewayClientFirstID); err != nil {
		return nil
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.root, publicKey, authority.signer)
	if err != nil {
		return nil
	}
	return der
}

func cloneGatewayIdentity(value Identity) Identity {
	value.CertificateDER = bytes.Clone(value.CertificateDER)
	value.CertificateAuthorityDER = bytes.Clone(value.CertificateAuthorityDER)
	value.DNSNames = slices.Clone(value.DNSNames)
	value.AgentTrustBundle.RootCertificateDER = cloneGatewayDERList(value.AgentTrustBundle.RootCertificateDER)
	value.AgentTrustBundle.TransitionCertificateDER = bytes.Clone(value.AgentTrustBundle.TransitionCertificateDER)
	value.AgentTrustBundle.CRLIssuerFingerprint = bytes.Clone(value.AgentTrustBundle.CRLIssuerFingerprint)
	value.GatewayTrustBundle.RootCertificateDER = cloneGatewayDERList(value.GatewayTrustBundle.RootCertificateDER)
	value.GatewayTrustBundle.TransitionCertificateDER = bytes.Clone(value.GatewayTrustBundle.TransitionCertificateDER)
	if value.PendingAgentTrustConfirmation != nil {
		pending := *value.PendingAgentTrustConfirmation
		pending.RootFingerprints = cloneGatewayDERList(pending.RootFingerprints)
		pending.CRLIssuerFingerprint = bytes.Clone(pending.CRLIssuerFingerprint)
		pending.Signature = bytes.Clone(pending.Signature)
		value.PendingAgentTrustConfirmation = &pending
	}
	if value.PendingGatewayTrustConfirmation != nil {
		pending := *value.PendingGatewayTrustConfirmation
		pending.RootFingerprints = cloneGatewayDERList(pending.RootFingerprints)
		pending.CRLIssuerFingerprint = bytes.Clone(pending.CRLIssuerFingerprint)
		pending.Signature = bytes.Clone(pending.Signature)
		value.PendingGatewayTrustConfirmation = &pending
	}
	return value
}

func sha256FingerprintBytes(der []byte) []byte {
	fingerprint := sha256.Sum256(der)
	return bytes.Clone(fingerprint[:])
}

func cloneGatewayDERList(values [][]byte) [][]byte {
	copy := make([][]byte, len(values))
	for index := range values {
		copy[index] = bytes.Clone(values[index])
	}
	return copy
}

func tlsCertificate(t *testing.T, leafDER []byte, key crypto.Signer) tls.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse TLS certificate leaf: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{bytes.Clone(leafDER)}, PrivateKey: key, Leaf: leaf}
}
