package enroll

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
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

func TestClient_RenewAcceptsProofOnlyForNewOrExactPendingRoot(t *testing.T) {
	exerciseAgentTrustBundleRollbackAndForkRejection(t)

	tests := []struct {
		name            string
		configure       func(*testing.T, *continuityClientFixture)
		wantErr         string
		wantAgentRoots  func(*continuityClientFixture) [][]byte
		wantAgentIssuer func(*continuityClientFixture) *x509.Certificate
	}{
		{
			name: "stable exact root needs no proof",
			wantAgentRoots: func(fixture *continuityClientFixture) [][]byte {
				return [][]byte{fixture.currentAgent.root.Raw}
			},
		},
		{
			name: "trust dual bundle accepts current-issued agent leaf",
			configure: func(t *testing.T, fixture *continuityClientFixture) {
				fixture.rotateAgent(t)
				fixture.handler.agentRoot = fixture.currentAgent
			},
			wantAgentRoots: func(fixture *continuityClientFixture) [][]byte {
				return [][]byte{fixture.currentAgent.root.Raw, fixture.nextAgent.root.Raw}
			},
			wantAgentIssuer: func(fixture *continuityClientFixture) *x509.Certificate {
				return fixture.currentAgent.root
			},
		},
		{
			name: "trust dual bundle accepts successor-issued agent leaf",
			configure: func(t *testing.T, fixture *continuityClientFixture) {
				fixture.rotateAgent(t)
			},
			wantAgentRoots: func(fixture *continuityClientFixture) [][]byte {
				return [][]byte{fixture.currentAgent.root.Raw, fixture.nextAgent.root.Raw}
			},
			wantAgentIssuer: func(fixture *continuityClientFixture) *x509.Certificate {
				return fixture.nextAgent.root
			},
		},
		{
			name: "exact pending dual bundle retry",
			configure: func(t *testing.T, fixture *continuityClientFixture) {
				fixture.rotateAgent(t)
				fixture.store.bundle.AgentTrustBundle = cloneStoredTrustBundle(fixture.handler.agentBundle())
				fixture.store.roundTrip = true
				pending, wire := signedAgentPendingConfirmation(t, fixture.store.bundle, "agent")
				fixture.store.bundle.PendingAgentTrustConfirmation = pending
				fixture.expectedAgentPendingWire = wire
			},
			wantAgentRoots: func(fixture *continuityClientFixture) [][]byte {
				return [][]byte{fixture.currentAgent.root.Raw, fixture.nextAgent.root.Raw}
			},
		},
		{
			name: "retire prunes an already trusted predecessor without a new proof",
			configure: func(t *testing.T, fixture *continuityClientFixture) {
				fixture.rotateAgent(t)
				fixture.store.bundle.AgentTrustBundle = cloneStoredTrustBundle(fixture.handler.agentBundle())
				fixture.handler.agentGeneration = 2
				fixture.handler.agentRevision = 2
				fixture.handler.agentRoots = [][]byte{fixture.nextAgent.root.Raw}
				fixture.handler.agentTransitionDER = nil
			},
			wantAgentRoots: func(fixture *continuityClientFixture) [][]byte {
				return [][]byte{fixture.nextAgent.root.Raw}
			},
		},
		{
			name: "changed root without proof",
			configure: func(t *testing.T, fixture *continuityClientFixture) {
				fixture.rotateAgent(t)
				fixture.handler.agentTransitionDER = nil
			},
			wantErr: "transition proof",
		},
		{
			name: "changed root with proof from unrelated authority",
			configure: func(t *testing.T, fixture *continuityClientFixture) {
				fixture.rotateAgent(t)
				unrelated := newContinuityCA(t, "unrelated")
				fixture.handler.agentTransitionDER = crossSignContinuityCA(t, unrelated, fixture.nextAgent, nil)
			},
			wantErr: "transition proof",
		},
		{
			name: "unchanged root with injected proof",
			configure: func(t *testing.T, fixture *continuityClientFixture) {
				fixture.handler.agentTransitionDER = crossSignContinuityCA(t, fixture.currentAgent, fixture.nextAgent, nil)
			},
			wantErr: "unchanged",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newContinuityClientFixture(t)
			if test.configure != nil {
				test.configure(t, &fixture)
			}
			before := cloneCredentialBundle(fixture.store.bundle)

			err := fixture.client.Renew(context.Background())
			if test.wantErr != "" {
				if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.wantErr)) {
					t.Fatalf("Renew error = %v; want category %q", err, test.wantErr)
				}
				assertContinuityBundleEqual(t, fixture.store.bundle, before)
				if fixture.store.replaceCalls != 0 || fixture.handler.confirmAgentCalls != 0 || fixture.handler.confirmGatewayCalls != 0 {
					t.Fatalf("rejected continuity response effects = (%d replace, %d agent confirms, %d gateway confirms); want none",
						fixture.store.replaceCalls, fixture.handler.confirmAgentCalls, fixture.handler.confirmGatewayCalls)
				}
				return
			}
			if err != nil {
				t.Fatalf("Renew: %v", err)
			}
			wantRoots := test.wantAgentRoots(&fixture)
			if fixture.store.replaceCalls < 1 ||
				!equalDERLists(fixture.store.bundle.AgentTrustBundle.RootCertificateDER, wantRoots) {
				t.Fatalf("stored agent continuity = %+v after %d replacements; want exact adopted root",
					fixture.store.bundle.AgentTrustBundle, fixture.store.replaceCalls)
			}
			if test.wantAgentIssuer != nil {
				certificate, parseErr := x509.ParseCertificate(fixture.store.bundle.CertificateDER)
				if parseErr != nil || certificate.CheckSignatureFrom(test.wantAgentIssuer(&fixture)) != nil {
					t.Fatalf("accepted trust-overlap agent leaf did not verify from the expected current/successor issuer: parse=%v", parseErr)
				}
			}
			if len(fixture.expectedAgentPendingWire) != 0 {
				if len(fixture.handler.agentConfirmationWire) == 0 ||
					!bytes.Equal(fixture.handler.agentConfirmationWire[0], fixture.expectedAgentPendingWire) {
					t.Fatal("exact pending retry did not send the fully signed durable certificate/class/key-bound wire request")
				}
			}
		})
	}
}

func exerciseAgentTrustBundleRollbackAndForkRejection(t *testing.T) {
	t.Helper()
	for _, class := range []continuityClass{continuityClassAgent, continuityClassGateway} {
		for _, test := range []struct {
			name      string
			wantErr   string
			configure func(*testing.T, *continuityClientFixture, continuityClass)
		}{
			{name: "lower generation", wantErr: "generation", configure: func(_ *testing.T, fixture *continuityClientFixture, class continuityClass) {
				fixture.setHandlerVersion(class, 2, 99)
			}},
			{name: "lower same-generation revision", wantErr: "revision", configure: func(_ *testing.T, fixture *continuityClientFixture, class continuityClass) {
				fixture.setHandlerVersion(class, 3, 1)
			}},
			{name: "same tuple with different roots and proof", wantErr: "version", configure: func(t *testing.T, fixture *continuityClientFixture, class continuityClass) {
				fixture.rotateClass(t, class)
				fixture.setHandlerVersion(class, 3, 2)
			}},
		} {
			t.Run(string(class)+" rejects "+test.name, func(t *testing.T) {
				fixture := newContinuityClientFixture(t)
				fixture.setStoredVersion(class, 3, 2)
				fixture.setHandlerVersion(class, 3, 2)
				test.configure(t, &fixture, class)
				before := cloneCredentialBundle(fixture.store.bundle)

				err := fixture.client.Renew(context.Background())
				if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.wantErr)) {
					t.Fatalf("%s %s Renew error = %v; want category %q", class, test.name, err, test.wantErr)
				}
				assertContinuityBundleEqual(t, fixture.store.bundle, before)
				if fixture.store.replaceCalls != 0 || fixture.handler.confirmAgentCalls != 0 ||
					fixture.handler.confirmGatewayCalls != 0 ||
					len(fixture.handler.agentConfirmationWire) != 0 ||
					len(fixture.handler.gatewayConfirmationWire) != 0 ||
					!slices.Equal(fixture.handler.events, []string{"renew"}) {
					t.Fatalf("rejected %s %s effects = (%d replacements, %d/%d confirmations, events %v); want only response fetch",
						class, test.name, fixture.store.replaceCalls, fixture.handler.confirmAgentCalls,
						fixture.handler.confirmGatewayCalls, fixture.handler.events)
				}
			})
		}
	}
}

func TestClient_RenewAdoptsCrossSignedAgentAndGatewayCAsAtomically(t *testing.T) {
	for _, replaceErr := range []error{nil, errors.New("simulated atomic publication failure")} {
		name := "commit succeeds"
		if replaceErr != nil {
			name = "commit fails"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newContinuityClientFixture(t)
			fixture.rotateAgent(t)
			fixture.rotateGateway(t)
			fixture.store.replaceErr = replaceErr
			before := cloneCredentialBundle(fixture.store.bundle)

			err := fixture.client.Renew(context.Background())
			if replaceErr != nil {
				if err == nil || !strings.Contains(err.Error(), replaceErr.Error()) {
					t.Fatalf("Renew error = %v; want atomic publication failure", err)
				}
				assertContinuityBundleEqual(t, fixture.store.bundle, before)
				if fixture.handler.confirmAgentCalls != 0 || fixture.handler.confirmGatewayCalls != 0 {
					t.Fatal("confirmation escaped before the atomic local commit")
				}
				return
			}
			if err != nil {
				t.Fatalf("Renew: %v", err)
			}
			stored := fixture.store.bundle
			if stored.AgentTrustBundle.Generation != 2 || stored.AgentTrustBundle.Revision != 1 ||
				stored.GatewayTrustBundle.Generation != 2 || stored.GatewayTrustBundle.Revision != 1 ||
				!exactRoots(stored.AgentTrustBundle.RootCertificateDER, fixture.currentAgent.root.Raw, fixture.nextAgent.root.Raw) ||
				!exactRoots(stored.GatewayTrustBundle.RootCertificateDER, fixture.currentGateway.root.Raw, fixture.nextGateway.root.Raw) ||
				len(stored.AgentTrustBundle.TransitionCertificateDER) == 0 ||
				len(stored.GatewayTrustBundle.TransitionCertificateDER) == 0 {
				t.Fatalf("atomic continuity commit = %+v / %+v; want both exact generation-two bundles and proofs",
					stored.AgentTrustBundle, stored.GatewayTrustBundle)
			}
			if fixture.store.maxPendingAtReplace != 2 {
				t.Fatalf("maximum pending confirmations in one atomic Replace = %d; want both classes", fixture.store.maxPendingAtReplace)
			}
			if fixture.handler.confirmAgentCalls != 2 || fixture.handler.confirmGatewayCalls != 0 ||
				fixture.handler.confirmBeforeReplace {
				t.Fatalf("confirmation order = (%d agent-reporter, %d gateway-reporter, before replace %v); want two independent agent claims after replace",
					fixture.handler.confirmAgentCalls, fixture.handler.confirmGatewayCalls, fixture.handler.confirmBeforeReplace)
			}
			if stored.PendingAgentTrustConfirmation != nil || stored.PendingGatewayTrustConfirmation != nil {
				t.Fatal("successful renewal did not independently clear both pending trust claims")
			}
			assertAgentRenewalConfirmationSet(t, fixture.handler, stored)
			assertPendingConfirmationProgression(t, fixture.store.replaceHistory, 2, 1, 0)
		})
	}
}

func TestClient_EnrollReceivesExactDualGatewayBundleDuringOverlap(t *testing.T) {
	phases := []struct {
		name       string
		generation uint64
		revision   uint64
		roots      func(continuityEnrollmentFixture) [][]byte
		proof      func(continuityEnrollmentFixture) []byte
	}{
		{name: "stable current-only", generation: 10, revision: 1, roots: func(f continuityEnrollmentFixture) [][]byte { return [][]byte{f.gatewayCurrent.root.Raw} }},
		{name: "trust current-successor", generation: 11, revision: 1, roots: func(f continuityEnrollmentFixture) [][]byte {
			return [][]byte{f.gatewayCurrent.root.Raw, f.gatewayNext.root.Raw}
		}, proof: func(f continuityEnrollmentFixture) []byte { return f.handler.gatewayTransition }},
		{name: "migrate current-successor", generation: 11, revision: 1, roots: func(f continuityEnrollmentFixture) [][]byte {
			return [][]byte{f.gatewayCurrent.root.Raw, f.gatewayNext.root.Raw}
		}, proof: func(f continuityEnrollmentFixture) []byte { return f.handler.gatewayTransition }},
		{name: "abort current-only", generation: 11, revision: 2, roots: func(f continuityEnrollmentFixture) [][]byte { return [][]byte{f.gatewayCurrent.root.Raw} }},
		{name: "retire successor-only", generation: 11, revision: 2, roots: func(f continuityEnrollmentFixture) [][]byte { return [][]byte{f.gatewayNext.root.Raw} }},
	}
	for _, phase := range phases {
		t.Run(phase.name, func(t *testing.T) {
			fixture := newContinuityEnrollmentFixture(t)
			var transition []byte
			if phase.proof != nil {
				transition = phase.proof(fixture)
			}
			fixture.handler.gatewayGeneration = phase.generation
			fixture.handler.gatewayRevision = phase.revision
			fixture.handler.gatewayRoots = phase.roots(fixture)
			fixture.handler.gatewayTransition = transition
			deviceID, err := fixture.client.Enroll(context.Background(), "registration-token", fixture.pin())
			if err != nil {
				t.Fatalf("Enroll: %v", err)
			}
			if deviceID != enrolledClientDeviceID || fixture.store.calls != 1 || fixture.handler.enrollCalls != 1 {
				t.Fatalf("enrollment result = (%q, %d creates, %d RPCs); want one identity and token use", deviceID, fixture.store.calls, fixture.handler.enrollCalls)
			}
			bundle := fixture.store.bundle
			if bundle.AgentTrustBundle.Generation != 7 || bundle.AgentTrustBundle.Revision != 3 ||
				!exactRoots(bundle.AgentTrustBundle.RootCertificateDER, fixture.agentCurrent.root.Raw) ||
				bundle.GatewayTrustBundle.Generation != phase.generation || bundle.GatewayTrustBundle.Revision != phase.revision ||
				!equalDERLists(bundle.GatewayTrustBundle.RootCertificateDER, phase.roots(fixture)) {
				t.Fatalf("fresh enrollment bundles = %+v / %+v; want exact phase shape", bundle.AgentTrustBundle, bundle.GatewayTrustBundle)
			}
			if fixture.store.maxPendingAtCreate != 2 || fixture.handler.confirmBeforeCreate ||
				bundle.PendingAgentTrustConfirmation != nil || bundle.PendingGatewayTrustConfirmation != nil {
				t.Fatalf("confirmation durability = (max pending %d, before create %v, final pending %v/%v); want both pending before send and both cleared after success",
					fixture.store.maxPendingAtCreate, fixture.handler.confirmBeforeCreate,
					bundle.PendingAgentTrustConfirmation != nil, bundle.PendingGatewayTrustConfirmation != nil)
			}
			assertFreshAgentConfirmationSet(t, fixture.handler, bundle)
		})
	}

	t.Run("reject non-canonical fresh bundle shapes", func(t *testing.T) {
		for _, test := range []struct {
			name    string
			wantErr string
			roots   func(continuityEnrollmentFixture) [][]byte
		}{
			{name: "empty", wantErr: "root bundle", roots: func(continuityEnrollmentFixture) [][]byte { return nil }},
			{name: "duplicate", wantErr: "duplicate", roots: func(f continuityEnrollmentFixture) [][]byte {
				return [][]byte{f.gatewayCurrent.root.Raw, f.gatewayCurrent.root.Raw}
			}},
			{name: "reversed", wantErr: "order", roots: func(f continuityEnrollmentFixture) [][]byte {
				return [][]byte{f.gatewayNext.root.Raw, f.gatewayCurrent.root.Raw}
			}},
			{name: "three roots", wantErr: "root bundle", roots: func(f continuityEnrollmentFixture) [][]byte {
				return [][]byte{f.gatewayCurrent.root.Raw, f.gatewayNext.root.Raw, f.gatewayThird.root.Raw}
			}},
		} {
			t.Run(test.name, func(t *testing.T) {
				fixture := newContinuityEnrollmentFixture(t)
				fixture.handler.gatewayRoots = test.roots(fixture)
				if _, err := fixture.client.Enroll(context.Background(), "registration-token", fixture.pin()); err == nil ||
					!strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.wantErr)) {
					t.Fatalf("Enroll error = %v; want category %q", err, test.wantErr)
				}
				if fixture.store.calls != 0 || fixture.handler.confirmCalls != 0 {
					t.Fatalf("rejected fresh bundle effects = (%d creates, %d confirms); want none", fixture.store.calls, fixture.handler.confirmCalls)
				}
			})
		}
	})

	t.Run("partial confirmation restarts only failed class without token reuse", func(t *testing.T) {
		fixture := newContinuityEnrollmentFixture(t)
		fixture.store.roundTrip = true
		fixture.handler.failClaimedClass = "gateway"
		_, err := fixture.client.Enroll(context.Background(), "one-use-token", fixture.pin())
		if connect.CodeOf(err) != connect.CodeUnavailable {
			t.Fatalf("Enroll lost-confirmation error = %v; want unavailable", err)
		}
		committed := cloneCredentialBundle(fixture.store.bundle)
		if fixture.store.calls != 1 || committed.PendingAgentTrustConfirmation != nil || committed.PendingGatewayTrustConfirmation == nil {
			t.Fatalf("partial local enrollment commit = (%d creates, agent pending %v, gateway pending %v); want only failed gateway claim",
				fixture.store.calls, committed.PendingAgentTrustConfirmation != nil, committed.PendingGatewayTrustConfirmation != nil)
		}
		if len(fixture.handler.confirmationWire["agent"]) != 1 || len(fixture.handler.confirmationWire["gateway"]) != 1 {
			t.Fatalf("first enrollment confirmation attempts = agent %d gateway %d; want one independent attempt each",
				len(fixture.handler.confirmationWire["agent"]), len(fixture.handler.confirmationWire["gateway"]))
		}
		assertExactAgentReporterClaims(t, fixture.handler.confirmRequests, committed)
		failedWire := bytes.Clone(fixture.handler.confirmationWire["gateway"][0])
		fixture.handler.failClaimedClass = ""
		restarted, err := NewClient(fixture.client.remote, fixture.store)
		if err != nil {
			t.Fatalf("restart enrollment client: %v", err)
		}
		restarted.now = fixture.client.now
		deviceID, err := restarted.Enroll(context.Background(), "must-not-be-consumed", fixture.pin())
		if err != nil {
			t.Fatalf("resume locally committed enrollment: %v", err)
		}
		if deviceID != committed.DeviceID || fixture.handler.enrollCalls != 1 || fixture.store.calls != 1 ||
			!bytes.Equal(fixture.store.bundle.CertificateDER, committed.CertificateDER) ||
			!samePrivateKey(fixture.store.bundle.PrivateKey, committed.PrivateKey) || pendingConfirmationCount(fixture.store.bundle) != 0 {
			t.Fatalf("restart changed committed enrollment or consumed another token: id=%q enrollRPCs=%d creates=%d pending=%d",
				deviceID, fixture.handler.enrollCalls, fixture.store.calls, pendingConfirmationCount(fixture.store.bundle))
		}
		if len(fixture.handler.confirmationWire["agent"]) != 1 || len(fixture.handler.confirmationWire["gateway"]) != 2 ||
			!bytes.Equal(fixture.handler.confirmationWire["gateway"][1], failedWire) {
			t.Fatalf("partial restart confirmation attempts = agent %d gateway %d; want only exact failed gateway claim replay",
				len(fixture.handler.confirmationWire["agent"]), len(fixture.handler.confirmationWire["gateway"]))
		}
		assertPendingConfirmationProgression(t, fixture.store.replaceHistory, 1, 0)
	})

	assertRealTLSOverlapAndPrune(t)
}

func TestClient_RenewRejectsInvalidCATransitionWithoutReplacement(t *testing.T) {
	criticalOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55555, 6006}
	for _, class := range []continuityClass{continuityClassAgent, continuityClassGateway} {
		t.Run(string(class), func(t *testing.T) {
			tests := []struct {
				name    string
				wantErr string
				mutate  func(*testing.T, *continuityClientFixture, continuityClass)
			}{
				{name: "missing proof", wantErr: "transition proof", mutate: func(_ *testing.T, f *continuityClientFixture, c continuityClass) { f.setTransition(c, nil) }},
				{name: "malformed proof", wantErr: "transition proof", mutate: func(_ *testing.T, f *continuityClientFixture, c continuityClass) {
					f.setTransition(c, []byte("not DER"))
				}},
				{name: "trailing proof DER", wantErr: "transition proof", mutate: func(_ *testing.T, f *continuityClientFixture, c continuityClass) {
					f.setTransition(c, append(f.transition(c), 0))
				}},
				{name: "malformed successor root DER", wantErr: "root certificate", mutate: func(_ *testing.T, f *continuityClientFixture, c continuityClass) {
					f.replaceSuccessorRoot(c, []byte("not DER"))
				}},
				{name: "trailing successor root DER", wantErr: "root certificate", mutate: func(_ *testing.T, f *continuityClientFixture, c continuityClass) {
					f.replaceSuccessorRoot(c, append(f.successor(c).root.Raw, 0))
				}},
				{name: "non-self-issued successor root", wantErr: "self", mutate: func(_ *testing.T, f *continuityClientFixture, c continuityClass) {
					f.replaceSuccessorRoot(c, f.transition(c))
				}},
				{name: "bad successor self-signature", wantErr: "self", mutate: func(t *testing.T, f *continuityClientFixture, c continuityClass) {
					f.replaceSuccessorRoot(c, badSelfSignatureRoot(t, f.successor(c), newContinuityCA(t, "wrong root signer")))
				}},
				{name: "subject drift", wantErr: "subject", mutate: transitionMutationForClass(func(c *x509.Certificate) { c.Subject.CommonName = "drifted subject" })},
				{name: "public key drift", wantErr: "public key", mutate: func(t *testing.T, f *continuityClientFixture, c continuityClass) {
					other := newContinuityCA(t, "other key")
					f.setTransition(c, crossSignContinuityCAWithKey(t, f.current(c), f.successor(c), other.signer.Public(), nil))
				}},
				{name: "subject key identifier drift", wantErr: "subject key", mutate: transitionMutationForClass(func(c *x509.Certificate) { c.SubjectKeyId = []byte("wrong key id") })},
				{name: "not a CA", wantErr: "CA", mutate: transitionMutationForClass(func(c *x509.Certificate) {
					c.IsCA = false
					c.MaxPathLen = -1
					c.MaxPathLenZero = false
				})},
				{name: "basic constraints invalid", wantErr: "constraints", mutate: transitionMutationForClass(func(c *x509.Certificate) { c.BasicConstraintsValid = false })},
				{name: "path length drift", wantErr: "path length", mutate: transitionMutationForClass(func(c *x509.Certificate) { c.MaxPathLen = 1; c.MaxPathLenZero = false })},
				{name: "key usage drift", wantErr: "key usage", mutate: transitionMutationForClass(func(c *x509.Certificate) { c.KeyUsage &^= x509.KeyUsageCRLSign })},
				{name: "raw issuer drift", wantErr: "issuer", mutate: func(t *testing.T, f *continuityClientFixture, c continuityClass) {
					parent := f.current(c)
					certificate := *parent.root
					certificate.RawSubject = nil
					certificate.Subject = pkix.Name{CommonName: "not current"}
					parent.root = &certificate
					f.setTransition(c, crossSignContinuityCA(t, parent, f.successor(c), nil))
				}},
				{name: "authority key identifier drift", wantErr: "authority key", mutate: func(t *testing.T, f *continuityClientFixture, c continuityClass) {
					parent := f.current(c)
					certificate := *parent.root
					certificate.SubjectKeyId = []byte("wrong authority")
					parent.root = &certificate
					f.setTransition(c, crossSignContinuityCA(t, parent, f.successor(c), nil))
				}},
				{name: "unsupported critical extension", wantErr: "critical", mutate: transitionMutationForClass(func(c *x509.Certificate) {
					c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: criticalOID, Critical: true, Value: []byte{5, 0}})
				})},
				{name: "not yet valid", wantErr: "not yet valid", mutate: transitionMutationForClass(func(c *x509.Certificate) {
					c.NotBefore = time.Date(2026, time.July, 23, 10, 0, 0, 0, time.UTC)
					c.NotAfter = c.NotBefore.Add(time.Hour)
				})},
				{name: "expired", wantErr: "expired", mutate: transitionMutationForClass(func(c *x509.Certificate) {
					c.NotBefore = time.Date(2026, time.July, 23, 7, 0, 0, 0, time.UTC)
					c.NotAfter = c.NotBefore.Add(time.Hour)
				})},
				{name: "reused authority key", wantErr: "reused", mutate: func(t *testing.T, f *continuityClientFixture, c continuityClass) {
					f.replaceSuccessor(t, c, newContinuityCAWithSignerAt(t, "reused key successor", f.current(c).signer, f.handler.now))
				}},
				{name: "unchanged root proof injection", wantErr: "unchanged", mutate: func(t *testing.T, f *continuityClientFixture, c continuityClass) {
					f.setRoots(c, [][]byte{f.current(c).root.Raw})
					f.setTransition(c, crossSignContinuityCA(t, f.current(c), f.successor(c), nil))
				}},
				{name: "transition certificate substituted as trust anchor", wantErr: "self", mutate: func(_ *testing.T, f *continuityClientFixture, c continuityClass) {
					f.replaceSuccessorRoot(c, f.transition(c))
				}},
				{name: "other class transition proof swapped in", wantErr: "transition proof", mutate: func(t *testing.T, f *continuityClientFixture, c continuityClass) {
					f.rotateClass(t, c.other())
					f.setTransition(c, f.transition(c.other()))
				}},
			}
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					fixture := newContinuityClientFixture(t)
					fixture.rotateClass(t, class)
					before := cloneCredentialBundle(fixture.store.bundle)
					test.mutate(t, &fixture, class)
					err := fixture.client.Renew(context.Background())
					if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.wantErr)) {
						t.Fatalf("Renew error = %v; want category %q", err, test.wantErr)
					}
					if fixture.store.replaceCalls != 0 || fixture.handler.confirmAgentCalls != 0 || fixture.handler.confirmGatewayCalls != 0 {
						t.Fatalf("invalid transition effects = (%d replace, %d agent confirmations, %d gateway confirmations); want none", fixture.store.replaceCalls, fixture.handler.confirmAgentCalls, fixture.handler.confirmGatewayCalls)
					}
					assertContinuityBundleEqual(t, fixture.store.bundle, before)
				})
			}
		})
	}

	for _, class := range []continuityClass{continuityClassAgent, continuityClassGateway} {
		t.Run(string(class)+" transition proof cannot be a TLS intermediate", func(t *testing.T) {
			assertTransitionIntermediateRejectedByRealTLS(t, class)
		})
	}
}

func TestClient_RestartRetriesPendingConfirmationBeforeRenewal(t *testing.T) {
	t.Run("exact pending claim precedes renewal", func(t *testing.T) {
		fixture, firstClaim, firstCertificate := prepareLostAgentConfirmation(t)
		fixture.handler.failAgentConfirm = false
		fixture.handler.events = nil
		fixture.handler.gatewayRevision++
		restarted := restartContinuityClient(t, fixture)
		if err := restarted.Renew(context.Background()); err != nil {
			t.Fatalf("Renew after restart: %v", err)
		}
		if len(fixture.handler.events) < 2 || fixture.handler.events[0] != "confirm-agent" || fixture.handler.events[1] != "renew" {
			t.Fatalf("restart RPC order = %v; want pending confirmation before renewal", fixture.handler.events)
		}
		if len(fixture.handler.agentConfirmationWire) < 2 || !bytes.Equal(fixture.handler.agentConfirmationWire[1], firstClaim) {
			t.Fatal("restart did not replay the exact durable signed confirmation claim")
		}
		if !bytes.Equal(fixture.handler.presentedCertificates[len(fixture.handler.presentedCertificates)-1], firstCertificate) {
			t.Fatal("post-confirmation renewal did not present the exact committed certificate")
		}
	})

	for _, test := range []struct {
		name   string
		mutate func(*PendingTrustConfirmation)
	}{
		{name: "corrupt durable pending claim", mutate: func(pending *PendingTrustConfirmation) {
			pending.RootFingerprints[0] = []byte{1}
		}},
		{name: "unsigned durable pending claim", mutate: func(pending *PendingTrustConfirmation) {
			pending.Signature = nil
		}},
	} {
		t.Run(test.name+" fails before network", func(t *testing.T) {
			fixture, _, committedCertificate := prepareLostAgentConfirmation(t)
			fixture.handler.failAgentConfirm = false
			fixture.handler.events = nil
			fixture.store.roundTrip = false
			test.mutate(fixture.store.bundle.PendingAgentTrustConfirmation)
			restarted := restartContinuityClient(t, fixture)
			if err := restarted.Renew(context.Background()); err == nil || !strings.Contains(strings.ToLower(err.Error()), "pending") {
				t.Fatalf("Renew %s error = %v; want pending-state rejection", test.name, err)
			}
			if len(fixture.handler.events) != 0 || !bytes.Equal(fixture.store.bundle.CertificateDER, committedCertificate) {
				t.Fatalf("%s effects = (events %v, changed cert %v); want fail-local", test.name, fixture.handler.events, !bytes.Equal(fixture.store.bundle.CertificateDER, committedCertificate))
			}
		})
	}

	t.Run("invalid agent pending claim does not block valid gateway claim", func(t *testing.T) {
		fixture, _, committedCertificate := prepareLostAgentConfirmation(t)
		fixture.handler.failAgentConfirm = false
		fixture.handler.events = nil
		fixture.store.roundTrip = false
		gatewayPending, err := newPendingTrustConfirmation(
			fixture.store.bundle,
			"gateway",
			fixture.store.bundle.GatewayTrustBundle,
		)
		if err != nil {
			t.Fatalf("create valid gateway pending confirmation: %v", err)
		}
		fixture.store.bundle.PendingGatewayTrustConfirmation = gatewayPending
		fixture.store.bundle.PendingAgentTrustConfirmation.Signature = nil
		restarted := restartContinuityClient(t, fixture)
		if err := restarted.Renew(context.Background()); err == nil || !strings.Contains(strings.ToLower(err.Error()), "pending agent") {
			t.Fatalf("Renew with one invalid pending claim error = %v; want local agent rejection", err)
		}
		stored := fixture.store.bundle
		if !slices.Equal(fixture.handler.events, []string{"confirm-agent"}) ||
			stored.PendingAgentTrustConfirmation == nil || stored.PendingGatewayTrustConfirmation != nil ||
			!bytes.Equal(stored.CertificateDER, committedCertificate) {
			t.Fatalf("independent pending progress = (events %v, agent %v, gateway %v, changed cert %v); want only valid gateway claim cleared",
				fixture.handler.events,
				stored.PendingAgentTrustConfirmation != nil,
				stored.PendingGatewayTrustConfirmation != nil,
				!bytes.Equal(stored.CertificateDER, committedCertificate),
			)
		}
	})

	for _, test := range []struct {
		name      string
		configure func(*testing.T, *continuityClientFixture)
		wantGen   uint64
		wantRev   uint64
		wantRoots func(*continuityClientFixture) [][]byte
	}{
		{
			name: "newer same-class generation waits for old pending claim",
			configure: func(t *testing.T, f *continuityClientFixture) {
				third := newContinuityCAAt(t, "agent generation three", f.handler.now)
				f.handler.agentGeneration, f.handler.agentRevision = 3, 1
				f.handler.agentRoot = third
				f.handler.agentRoots = [][]byte{f.nextAgent.root.Raw, third.root.Raw}
				f.handler.agentTransitionDER = crossSignContinuityCA(t, f.nextAgent, third, nil)
			},
			wantGen: 3, wantRev: 1,
			wantRoots: func(f *continuityClientFixture) [][]byte { return f.handler.agentRoots },
		},
		{
			name: "higher revision supersedes only after old pending claim",
			configure: func(_ *testing.T, f *continuityClientFixture) {
				f.handler.agentGeneration, f.handler.agentRevision = 2, 2
				f.handler.agentRoot = f.currentAgent
				f.handler.agentRoots = [][]byte{f.currentAgent.root.Raw}
				f.handler.agentTransitionDER = nil
			},
			wantGen: 2, wantRev: 2,
			wantRoots: func(f *continuityClientFixture) [][]byte { return f.handler.agentRoots },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture, firstClaim, _ := prepareLostAgentConfirmation(t)
			fixture.handler.failAgentConfirm = false
			fixture.handler.events = nil
			test.configure(t, &fixture)
			restarted := restartContinuityClient(t, fixture)
			if err := restarted.Renew(context.Background()); err != nil {
				t.Fatalf("resume then renew: %v", err)
			}
			if len(fixture.handler.events) < 2 || fixture.handler.events[0] != "confirm-agent" || fixture.handler.events[1] != "renew" ||
				!bytes.Equal(fixture.handler.agentConfirmationWire[1], firstClaim) {
				t.Fatalf("supersession order/wire = %v; want exact older claim before renewal", fixture.handler.events)
			}
			stored := fixture.store.bundle.AgentTrustBundle
			if stored.Generation != test.wantGen || stored.Revision != test.wantRev || !equalDERLists(stored.RootCertificateDER, test.wantRoots(&fixture)) {
				t.Fatalf("post-retry bundle = %+v; want accepted superseding %d/%d bundle", stored, test.wantGen, test.wantRev)
			}
		})
	}
}

func TestContinuityValidation_RejectsZeroClock(t *testing.T) {
	fixture := newContinuityEnrollmentFixture(t)
	if _, err := parseContinuityRoot(fixture.gatewayCurrent.root.Raw, time.Time{}); err == nil || !strings.Contains(err.Error(), "clock") {
		t.Fatalf("parseContinuityRoot zero-clock error = %v; want fail-closed clock rejection", err)
	}
	current, err := parseContinuityRoot(fixture.gatewayCurrent.root.Raw, fixture.handler.now)
	if err != nil {
		t.Fatalf("parse current gateway root: %v", err)
	}
	successor, err := parseContinuityRoot(fixture.gatewayNext.root.Raw, fixture.handler.now)
	if err != nil {
		t.Fatalf("parse successor gateway root: %v", err)
	}
	proof := crossSignContinuityCA(t, fixture.gatewayCurrent, fixture.gatewayNext, nil)
	if err := validateTransitionProof(current, successor, proof, time.Time{}); err == nil || !strings.Contains(err.Error(), "clock") {
		t.Fatalf("validateTransitionProof zero-clock error = %v; want fail-closed clock rejection", err)
	}
}

func prepareLostAgentConfirmation(t *testing.T) (continuityClientFixture, []byte, []byte) {
	t.Helper()
	fixture := newContinuityClientFixture(t)
	fixture.store.roundTrip = true
	fixture.rotateAgent(t)
	fixture.handler.failAgentConfirm = true
	if err := fixture.client.Renew(context.Background()); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("first Renew error = %v; want lost-confirmation unavailable failure", err)
	}
	if fixture.store.replaceCalls != 1 || fixture.store.bundle.PendingAgentTrustConfirmation == nil || len(fixture.handler.agentConfirmationWire) != 1 {
		t.Fatalf("first renewal persistence = (%d replacements, pending %v, attempts %d); want committed identity and one pending claim",
			fixture.store.replaceCalls, fixture.store.bundle.PendingAgentTrustConfirmation != nil, len(fixture.handler.agentConfirmationWire))
	}
	return fixture, bytes.Clone(fixture.handler.agentConfirmationWire[0]), bytes.Clone(fixture.store.bundle.CertificateDER)
}

func restartContinuityClient(t *testing.T, fixture continuityClientFixture) *Client {
	t.Helper()
	restarted, err := NewClient(fixture.client.remote, fixture.store)
	if err != nil {
		t.Fatalf("NewClient after restart: %v", err)
	}
	restarted.now = fixture.client.now
	return restarted
}

type continuityClientFixture struct {
	client                   *Client
	store                    *continuityCredentialStore
	handler                  *continuityClientHandler
	currentAgent             continuityCA
	nextAgent                continuityCA
	currentGateway           continuityCA
	nextGateway              continuityCA
	expectedAgentPendingWire []byte
}

type continuityClass string

const (
	continuityClassAgent   continuityClass = "agent"
	continuityClassGateway continuityClass = "gateway"
)

func (c continuityClass) other() continuityClass {
	if c == continuityClassAgent {
		return continuityClassGateway
	}
	return continuityClassAgent
}

type continuityCredentialStore struct {
	bundle              CredentialBundle
	encoded             []byte
	createHistory       []CredentialBundle
	replaceHistory      []CredentialBundle
	calls               int
	replaceCalls        int
	maxPendingAtCreate  int
	maxPendingAtReplace int
	replaceErr          error
	roundTrip           bool
}

func (s *continuityCredentialStore) Create(_ context.Context, bundle CredentialBundle) error {
	s.calls++
	if pending := pendingConfirmationCount(bundle); pending > s.maxPendingAtCreate {
		s.maxPendingAtCreate = pending
	}
	if s.roundTrip {
		encoded, err := encodeCredentialBundle(bundle)
		if err != nil {
			return err
		}
		s.encoded = bytes.Clone(encoded)
	}
	s.bundle = cloneCredentialBundle(bundle)
	s.createHistory = append(s.createHistory, cloneCredentialBundle(bundle))
	return nil
}

func (s *continuityCredentialStore) Load(context.Context) (CredentialBundle, error) {
	if s.roundTrip {
		if len(s.encoded) == 0 {
			encoded, err := encodeCredentialBundle(s.bundle)
			if err != nil {
				return CredentialBundle{}, err
			}
			s.encoded = bytes.Clone(encoded)
		}
		return decodeStoredCredentialBundle(s.encoded)
	}
	return cloneCredentialBundle(s.bundle), nil
}

func (s *continuityCredentialStore) Replace(_ context.Context, bundle CredentialBundle) error {
	s.replaceCalls++
	if pending := pendingConfirmationCount(bundle); pending > s.maxPendingAtReplace {
		s.maxPendingAtReplace = pending
	}
	if s.replaceErr != nil {
		return s.replaceErr
	}
	if s.roundTrip {
		encoded, err := encodeCredentialBundle(bundle)
		if err != nil {
			return err
		}
		s.encoded = bytes.Clone(encoded)
		decoded, err := decodeStoredCredentialBundle(s.encoded)
		if err != nil {
			return err
		}
		s.bundle = decoded
		s.replaceHistory = append(s.replaceHistory, cloneCredentialBundle(decoded))
		return nil
	}
	s.bundle = cloneCredentialBundle(bundle)
	s.replaceHistory = append(s.replaceHistory, cloneCredentialBundle(bundle))
	return nil
}

type continuityClientHandler struct {
	powermanagev1connect.UnimplementedPkiServiceHandler

	now                     time.Time
	deviceID                string
	store                   *continuityCredentialStore
	currentAgent            continuityCA
	agentRoot               continuityCA
	agentRoots              [][]byte
	agentTransitionDER      []byte
	agentGeneration         uint64
	agentRevision           uint64
	currentGateway          continuityCA
	gatewayRoot             continuityCA
	gatewayRoots            [][]byte
	gatewayTransition       []byte
	gatewayGeneration       uint64
	gatewayRevision         uint64
	confirmAgentCalls       int
	confirmGatewayCalls     int
	confirmBeforeReplace    bool
	failAgentConfirm        bool
	failGatewayConfirm      bool
	agentConfirmationWire   [][]byte
	gatewayConfirmationWire [][]byte
	agentConfirmRequests    []*powermanagev1.ConfirmTrustStateRequest
	gatewayConfirmRequests  []*powermanagev1.ConfirmTrustStateRequest
	presentedCertificates   [][]byte
	events                  []string
}

func newContinuityClientFixture(t *testing.T) continuityClientFixture {
	t.Helper()
	now := time.Date(2026, time.July, 23, 9, 0, 0, 0, time.UTC)
	currentAgent := newContinuityCAAt(t, "agent current", now)
	nextAgent := newContinuityCAAt(t, "agent successor", now)
	currentGateway := newContinuityCAAt(t, "gateway current", now)
	nextGateway := newContinuityCAAt(t, "gateway successor", now)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate continuity client key: %v", err)
	}
	sealingKey := newEnrollmentSealingPrivateKey(t)
	certificateDER := newContinuityAgentLeaf(t, currentAgent, key.Public(), enrolledClientDeviceID)
	store := &continuityCredentialStore{bundle: CredentialBundle{
		DeviceID: enrolledClientDeviceID, CertificateDER: certificateDER,
		CertificateAuthorityDER:        currentAgent.root.Raw,
		GatewayCertificateAuthorityDER: currentGateway.root.Raw,
		PrivateKey:                     key, SealingPrivateKey: sealingKey,
		AgentTrustBundle:   StoredTrustBundle{Generation: 1, Revision: 1, RootCertificateDER: [][]byte{currentAgent.root.Raw}},
		GatewayTrustBundle: StoredTrustBundle{Generation: 1, Revision: 1, RootCertificateDER: [][]byte{currentGateway.root.Raw}},
	}}
	handler := &continuityClientHandler{
		now: now, deviceID: enrolledClientDeviceID, store: store,
		currentAgent: currentAgent, agentRoot: currentAgent, agentRoots: [][]byte{currentAgent.root.Raw}, agentGeneration: 1, agentRevision: 1,
		currentGateway: currentGateway, gatewayRoot: currentGateway, gatewayRoots: [][]byte{currentGateway.root.Raw}, gatewayGeneration: 1, gatewayRevision: 1,
	}
	path, connectHandler := powermanagev1connect.NewPkiServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, connectHandler)
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	client, err := NewClient(powermanagev1connect.NewPkiServiceClient(server.Client(), server.URL), store)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.now = func() time.Time { return now }
	return continuityClientFixture{
		client: client, store: store, handler: handler,
		currentAgent: currentAgent, nextAgent: nextAgent,
		currentGateway: currentGateway, nextGateway: nextGateway,
	}
}

func (f *continuityClientFixture) rotateAgent(t *testing.T) {
	t.Helper()
	f.handler.agentRoot = f.nextAgent
	f.handler.agentRoots = [][]byte{f.currentAgent.root.Raw, f.nextAgent.root.Raw}
	f.handler.agentGeneration = 2
	f.handler.agentRevision = 1
	f.handler.agentTransitionDER = crossSignContinuityCA(t, f.currentAgent, f.nextAgent, nil)
}

func (f *continuityClientFixture) rotateGateway(t *testing.T) {
	t.Helper()
	f.handler.gatewayRoot = f.nextGateway
	f.handler.gatewayRoots = [][]byte{f.currentGateway.root.Raw, f.nextGateway.root.Raw}
	f.handler.gatewayGeneration = 2
	f.handler.gatewayRevision = 1
	f.handler.gatewayTransition = crossSignContinuityCA(t, f.currentGateway, f.nextGateway, nil)
}

func (f *continuityClientFixture) rotateClass(t *testing.T, class continuityClass) {
	t.Helper()
	if class == continuityClassAgent {
		f.rotateAgent(t)
		return
	}
	f.rotateGateway(t)
}

func (f *continuityClientFixture) current(class continuityClass) continuityCA {
	if class == continuityClassAgent {
		return f.currentAgent
	}
	return f.currentGateway
}

func (f *continuityClientFixture) successor(class continuityClass) continuityCA {
	if class == continuityClassAgent {
		return f.nextAgent
	}
	return f.nextGateway
}

func (f *continuityClientFixture) transition(class continuityClass) []byte {
	if class == continuityClassAgent {
		return f.handler.agentTransitionDER
	}
	return f.handler.gatewayTransition
}

func (f *continuityClientFixture) setTransition(class continuityClass, der []byte) {
	if class == continuityClassAgent {
		f.handler.agentTransitionDER = bytes.Clone(der)
		return
	}
	f.handler.gatewayTransition = bytes.Clone(der)
}

func (f *continuityClientFixture) setRoots(class continuityClass, roots [][]byte) {
	if class == continuityClassAgent {
		f.handler.agentRoots = cloneDERList(roots)
		return
	}
	f.handler.gatewayRoots = cloneDERList(roots)
}

func (f *continuityClientFixture) setStoredVersion(class continuityClass, generation, revision uint64) {
	if class == continuityClassAgent {
		f.store.bundle.AgentTrustBundle.Generation = generation
		f.store.bundle.AgentTrustBundle.Revision = revision
		return
	}
	f.store.bundle.GatewayTrustBundle.Generation = generation
	f.store.bundle.GatewayTrustBundle.Revision = revision
}

func (f *continuityClientFixture) setHandlerVersion(class continuityClass, generation, revision uint64) {
	if class == continuityClassAgent {
		f.handler.agentGeneration = generation
		f.handler.agentRevision = revision
		return
	}
	f.handler.gatewayGeneration = generation
	f.handler.gatewayRevision = revision
}

func (f *continuityClientFixture) replaceSuccessorRoot(class continuityClass, der []byte) {
	roots := [][]byte{f.current(class).root.Raw, der}
	f.setRoots(class, roots)
}

func (f *continuityClientFixture) replaceSuccessor(t *testing.T, class continuityClass, successor continuityCA) {
	t.Helper()
	current := f.current(class)
	if class == continuityClassAgent {
		f.nextAgent = successor
		f.handler.agentRoot = successor
	} else {
		f.nextGateway = successor
		f.handler.gatewayRoot = successor
	}
	f.setRoots(class, [][]byte{current.root.Raw, successor.root.Raw})
	f.setTransition(class, crossSignContinuityCA(t, current, successor, nil))
}

func (h *continuityClientHandler) RenewAgent(_ context.Context, request *connect.Request[powermanagev1.RenewAgentRequest]) (*connect.Response[powermanagev1.RenewAgentResponse], error) {
	h.events = append(h.events, "renew")
	h.presentedCertificates = append(h.presentedCertificates, bytes.Clone(request.Msg.GetCertificateDer()))
	csr, err := x509.ParseCertificateRequest(request.Msg.GetCertificateSigningRequestDer())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	leaf := newContinuityAgentLeafWithoutTest(h.now, h.agentRoot, csr.PublicKey, h.deviceID)
	if leaf.err != nil {
		return nil, connect.NewError(connect.CodeInternal, leaf.err)
	}
	return connect.NewResponse(&powermanagev1.RenewAgentResponse{
		CertificateDer:     leaf.der,
		AgentTrustBundle:   h.agentBundle(),
		GatewayTrustBundle: h.gatewayBundle(),
	}), nil
}

func (h *continuityClientHandler) ConfirmAgentTrustState(_ context.Context, request *connect.Request[powermanagev1.ConfirmTrustStateRequest]) (*connect.Response[powermanagev1.ConfirmTrustStateResponse], error) {
	h.confirmAgentCalls++
	h.events = append(h.events, "confirm-agent")
	h.confirmBeforeReplace = h.confirmBeforeReplace || h.store.replaceCalls == 0
	if err := verifyCapturedTrustStateRequest("agent", request.Msg, h.store.bundle.CertificateDER); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	h.agentConfirmRequests = append(h.agentConfirmRequests, proto.Clone(request.Msg).(*powermanagev1.ConfirmTrustStateRequest))
	wire, err := proto.Marshal(request.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	h.agentConfirmationWire = append(h.agentConfirmationWire, wire)
	if h.failAgentConfirm {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("confirmation response lost"))
	}
	return connect.NewResponse(&powermanagev1.ConfirmTrustStateResponse{}), nil
}

func (h *continuityClientHandler) ConfirmGatewayTrustState(_ context.Context, request *connect.Request[powermanagev1.ConfirmTrustStateRequest]) (*connect.Response[powermanagev1.ConfirmTrustStateResponse], error) {
	h.confirmGatewayCalls++
	h.events = append(h.events, "confirm-gateway")
	h.confirmBeforeReplace = h.confirmBeforeReplace || h.store.replaceCalls == 0
	if err := verifyCapturedTrustStateRequest("gateway", request.Msg, h.store.bundle.CertificateDER); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	h.gatewayConfirmRequests = append(h.gatewayConfirmRequests, proto.Clone(request.Msg).(*powermanagev1.ConfirmTrustStateRequest))
	wire, err := proto.Marshal(request.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	h.gatewayConfirmationWire = append(h.gatewayConfirmationWire, wire)
	if h.failGatewayConfirm {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("gateway confirmation response lost"))
	}
	return connect.NewResponse(&powermanagev1.ConfirmTrustStateResponse{}), nil
}

func (h *continuityClientHandler) agentBundle() *powermanagev1.CATrustBundle {
	return &powermanagev1.CATrustBundle{
		Generation: h.agentGeneration, Revision: h.agentRevision,
		RootCertificateDer:       cloneDERList(h.agentRoots),
		TransitionCertificateDer: bytes.Clone(h.agentTransitionDER),
	}
}

func (h *continuityClientHandler) gatewayBundle() *powermanagev1.CATrustBundle {
	return &powermanagev1.CATrustBundle{
		Generation: h.gatewayGeneration, Revision: h.gatewayRevision,
		RootCertificateDer:       cloneDERList(h.gatewayRoots),
		TransitionCertificateDer: bytes.Clone(h.gatewayTransition),
	}
}

type continuityEnrollmentFixture struct {
	client         *Client
	store          *continuityCredentialStore
	handler        *continuityEnrollmentHandler
	agentCurrent   continuityCA
	gatewayCurrent continuityCA
	gatewayNext    continuityCA
	gatewayThird   continuityCA
}

func newContinuityEnrollmentFixture(t *testing.T) continuityEnrollmentFixture {
	t.Helper()
	now := time.Date(2026, time.July, 23, 9, 0, 0, 0, time.UTC)
	agentCurrent := newContinuityCAAt(t, "agent current", now)
	gatewayCurrent := newContinuityCAAt(t, "gateway current", now)
	gatewayNext := newContinuityCAAt(t, "gateway successor", now)
	gatewayThird := newContinuityCAAt(t, "gateway third", now)
	handler := &continuityEnrollmentHandler{
		now: now, agentCurrent: agentCurrent, gatewayCurrent: gatewayCurrent, gatewayNext: gatewayNext,
		gatewayGeneration: 11, gatewayRevision: 1,
		gatewayRoots:      [][]byte{gatewayCurrent.root.Raw, gatewayNext.root.Raw},
		gatewayTransition: crossSignContinuityCA(t, gatewayCurrent, gatewayNext, nil),
	}
	path, connectHandler := powermanagev1connect.NewPkiServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, connectHandler)
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	store := &continuityCredentialStore{}
	client, err := NewClient(powermanagev1connect.NewPkiServiceClient(server.Client(), server.URL), store)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.now = func() time.Time { return now }
	handler.store = store
	return continuityEnrollmentFixture{
		client: client, store: store, handler: handler, agentCurrent: agentCurrent,
		gatewayCurrent: gatewayCurrent, gatewayNext: gatewayNext, gatewayThird: gatewayThird,
	}
}

func (f continuityEnrollmentFixture) pin() string {
	fingerprint := sha256.Sum256(f.agentCurrent.root.Raw)
	return "sha256:" + strings.ToLower(stringHex(fingerprint[:]))
}

type continuityEnrollmentHandler struct {
	powermanagev1connect.UnimplementedPkiServiceHandler
	now                  time.Time
	agentCurrent         continuityCA
	gatewayCurrent       continuityCA
	gatewayNext          continuityCA
	gatewayGeneration    uint64
	gatewayRevision      uint64
	gatewayRoots         [][]byte
	gatewayTransition    []byte
	store                *continuityCredentialStore
	enrollCalls          int
	confirmCalls         int
	confirmBeforeCreate  bool
	confirmErr           error
	failClaimedClass     string
	confirmRequests      []*powermanagev1.ConfirmTrustStateRequest
	confirmationWire     map[string][][]byte
	gatewayReporterCalls int
}

func (h *continuityEnrollmentHandler) EnrollAgent(_ context.Context, request *connect.Request[powermanagev1.EnrollAgentRequest]) (*connect.Response[powermanagev1.EnrollAgentResponse], error) {
	h.enrollCalls++
	csr, err := x509.ParseCertificateRequest(request.Msg.GetCertificateSigningRequestDer())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	leaf := newContinuityAgentLeafWithoutTest(h.now, h.agentCurrent, csr.PublicKey, enrolledClientDeviceID)
	if leaf.err != nil {
		return nil, connect.NewError(connect.CodeInternal, leaf.err)
	}
	return connect.NewResponse(&powermanagev1.EnrollAgentResponse{
		CertificateDer: leaf.der,
		AgentTrustBundle: &powermanagev1.CATrustBundle{
			Generation: 7, Revision: 3, RootCertificateDer: [][]byte{h.agentCurrent.root.Raw},
		},
		GatewayTrustBundle: &powermanagev1.CATrustBundle{
			Generation: h.gatewayGeneration, Revision: h.gatewayRevision,
			RootCertificateDer:       cloneDERList(h.gatewayRoots),
			TransitionCertificateDer: h.gatewayTransition,
		},
	}), nil
}

func (h *continuityEnrollmentHandler) ConfirmAgentTrustState(_ context.Context, request *connect.Request[powermanagev1.ConfirmTrustStateRequest]) (*connect.Response[powermanagev1.ConfirmTrustStateResponse], error) {
	h.confirmCalls++
	h.confirmBeforeCreate = h.confirmBeforeCreate || h.store.calls == 0
	if err := verifyCapturedTrustStateRequest("agent", request.Msg, h.store.bundle.CertificateDER); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	h.confirmRequests = append(h.confirmRequests, proto.Clone(request.Msg).(*powermanagev1.ConfirmTrustStateRequest))
	wire, err := proto.Marshal(request.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	if h.confirmationWire == nil {
		h.confirmationWire = make(map[string][][]byte)
	}
	h.confirmationWire[request.Msg.GetClaimedClass()] = append(h.confirmationWire[request.Msg.GetClaimedClass()], wire)
	if h.failClaimedClass == request.Msg.GetClaimedClass() {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("class confirmation response lost"))
	}
	if h.confirmErr != nil {
		return nil, h.confirmErr
	}
	return connect.NewResponse(&powermanagev1.ConfirmTrustStateResponse{}), nil
}

func (h *continuityEnrollmentHandler) ConfirmGatewayTrustState(context.Context, *connect.Request[powermanagev1.ConfirmTrustStateRequest]) (*connect.Response[powermanagev1.ConfirmTrustStateResponse], error) {
	h.gatewayReporterCalls++
	return connect.NewResponse(&powermanagev1.ConfirmTrustStateResponse{}), nil
}

type continuityCA struct {
	root   *x509.Certificate
	signer crypto.Signer
}

func newContinuityCA(t *testing.T, name string) continuityCA {
	t.Helper()
	return newContinuityCAAt(t, name, time.Now().UTC())
}

func newContinuityCAAt(t *testing.T, name string, now time.Time) continuityCA {
	t.Helper()
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate %s key: %v", name, err)
	}
	return newContinuityCAWithSignerAt(t, name, signer, now)
}

func newContinuityCAWithSignerAt(t *testing.T, name string, signer crypto.Signer, now time.Time) continuityCA {
	t.Helper()
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		t.Fatalf("marshal %s public key: %v", name, err)
	}
	keyID := sha256.Sum256(publicDER)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, Issuer: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
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
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Fatalf("verify self-signed %s: %v", name, err)
	}
	return continuityCA{root: root, signer: signer}
}

func crossSignContinuityCA(t *testing.T, current, successor continuityCA, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	return crossSignContinuityCAWithKey(t, current, successor, successor.signer.Public(), mutate)
}

func crossSignContinuityCAWithKey(t *testing.T, current, successor continuityCA, publicKey crypto.PublicKey, mutate func(*x509.Certificate)) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: successor.root.Subject, Issuer: current.root.Subject,
		NotBefore: successor.root.NotBefore, NotAfter: successor.root.NotAfter,
		IsCA: successor.root.IsCA, BasicConstraintsValid: successor.root.BasicConstraintsValid,
		KeyUsage: successor.root.KeyUsage, SubjectKeyId: bytes.Clone(successor.root.SubjectKeyId),
		AuthorityKeyId: bytes.Clone(current.root.SubjectKeyId), MaxPathLen: successor.root.MaxPathLen,
		MaxPathLenZero: successor.root.MaxPathLenZero,
	}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, current.root, publicKey, current.signer)
	if err != nil {
		t.Fatalf("create transition certificate: %v", err)
	}
	return der
}

func transitionMutationForClass(mutate func(*x509.Certificate)) func(*testing.T, *continuityClientFixture, continuityClass) {
	return func(t *testing.T, fixture *continuityClientFixture, class continuityClass) {
		fixture.setTransition(class, crossSignContinuityCA(t, fixture.current(class), fixture.successor(class), mutate))
	}
}

func badSelfSignatureRoot(t *testing.T, successor, _ continuityCA) []byte {
	t.Helper()
	der := bytes.Clone(successor.root.Raw)
	der[len(der)-1] ^= 0xff
	return der
}

func assertTransitionIntermediateRejectedByRealTLS(t *testing.T, class continuityClass) {
	t.Helper()
	fixture := newContinuityClientFixture(t)
	fixture.rotateClass(t, class)
	const dnsName = "gateway.internal.example"
	gatewayKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate gateway TLS key: %v", err)
	}
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate agent TLS key: %v", err)
	}
	gatewayAuthority, agentAuthority := fixture.currentGateway, fixture.currentAgent
	if class == continuityClassGateway {
		gatewayAuthority = fixture.nextGateway
	} else {
		agentAuthority = fixture.nextAgent
	}
	gatewayLeaf := newContinuityGatewayLeaf(t, gatewayAuthority, gatewayKey.Public(), dnsName)
	agentLeaf := newContinuityAgentLeaf(t, agentAuthority, agentKey.Public(), enrolledClientDeviceID)
	agentRoots := x509.NewCertPool()
	agentRoots.AddCert(fixture.currentAgent.root)
	if class == continuityClassAgent {
		agentRoots.AddCert(fixture.nextAgent.root)
	}
	serverTLS, err := identity.ServerTLSConfig(
		tls.Certificate{Certificate: [][]byte{gatewayLeaf}, PrivateKey: gatewayKey}, agentRoots, identity.AgentClass,
	)
	if err != nil {
		t.Fatalf("build production gateway-server TLS boundary: %v", err)
	}
	gatewayRoots := x509.NewCertPool()
	gatewayRoots.AddCert(fixture.currentGateway.root)
	if class == continuityClassGateway {
		gatewayRoots.AddCert(fixture.nextGateway.root)
	}
	clientTLS, err := identity.ClientTLSConfig(
		tls.Certificate{Certificate: [][]byte{agentLeaf}, PrivateKey: agentKey}, gatewayRoots, dnsName, identity.GatewayClass,
	)
	if err != nil {
		t.Fatalf("build production agent-client TLS boundary: %v", err)
	}
	serverTLS.Time = func() time.Time { return fixture.handler.now }
	clientTLS.Time = func() time.Time { return fixture.handler.now }
	transitionDER := fixture.transition(class)
	if class == continuityClassGateway {
		if err := identity.RejectPeerIntermediates(clientTLS, transitionDER); err != nil {
			t.Fatalf("install production transition denylist on agent client: %v", err)
		}
	} else {
		if err := identity.RejectPeerIntermediates(serverTLS, transitionDER); err != nil {
			t.Fatalf("install production transition denylist on gateway server: %v", err)
		}
	}
	assertContinuityTLSExchange(t, serverTLS, clientTLS, true,
		"production TLS transition hook rejected an equivalent direct-root peer")
	if class == continuityClassGateway {
		serverTLS.Certificates[0].Certificate = [][]byte{gatewayLeaf, transitionDER}
	} else {
		clientTLS.Certificates[0].Certificate = [][]byte{agentLeaf, transitionDER}
	}
	assertContinuityTLSExchange(t, serverTLS, clientTLS, false,
		"production TLS boundary accepted a denylisted CA transition proof as a general peer-chain intermediate")
}

func assertContinuityTLSExchange(
	t *testing.T,
	serverTLS, clientTLS *tls.Config,
	wantSuccess bool,
	failureMessage string,
) {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = serverTLS
	server.StartTLS()
	t.Cleanup(server.Close)
	transport := &http.Transport{TLSClientConfig: clientTLS}
	t.Cleanup(transport.CloseIdleConnections)
	response, err := (&http.Client{Transport: transport}).Get(server.URL)
	if wantSuccess {
		if err != nil {
			t.Fatalf("%s: %v", failureMessage, err)
		}
		if err := response.Body.Close(); err != nil {
			t.Fatalf("close direct-root positive TLS response: %v", err)
		}
		return
	}
	if err == nil {
		_ = response.Body.Close()
		t.Fatal(failureMessage)
	}
}

func assertRealTLSOverlapAndPrune(t *testing.T) {
	t.Helper()
	now := time.Date(2026, time.July, 23, 9, 0, 0, 0, time.UTC)
	agentCurrent := newContinuityCAAt(t, "TLS agent current", now)
	agentSuccessor := newContinuityCAAt(t, "TLS agent successor", now)
	gatewayCurrent := newContinuityCAAt(t, "TLS gateway current", now)
	gatewaySuccessor := newContinuityCAAt(t, "TLS gateway successor", now)
	overlapAgents := []*x509.Certificate{agentCurrent.root, agentSuccessor.root}
	overlapGateways := []*x509.Certificate{gatewayCurrent.root, gatewaySuccessor.root}

	for _, test := range []struct {
		name             string
		agentAuthority   continuityCA
		gatewayAuthority continuityCA
		agentRoots       []*x509.Certificate
		gatewayRoots     []*x509.Certificate
		wantSuccess      bool
	}{
		{name: "overlap accepts old agent and old gateway", agentAuthority: agentCurrent, gatewayAuthority: gatewayCurrent, agentRoots: overlapAgents, gatewayRoots: overlapGateways, wantSuccess: true},
		{name: "overlap accepts successor agent", agentAuthority: agentSuccessor, gatewayAuthority: gatewayCurrent, agentRoots: overlapAgents, gatewayRoots: overlapGateways, wantSuccess: true},
		{name: "overlap accepts successor gateway", agentAuthority: agentCurrent, gatewayAuthority: gatewaySuccessor, agentRoots: overlapAgents, gatewayRoots: overlapGateways, wantSuccess: true},
		{name: "overlap accepts both successor-issued peers", agentAuthority: agentSuccessor, gatewayAuthority: gatewaySuccessor, agentRoots: overlapAgents, gatewayRoots: overlapGateways, wantSuccess: true},
		{name: "normalized successor-only accepts both successors", agentAuthority: agentSuccessor, gatewayAuthority: gatewaySuccessor, agentRoots: []*x509.Certificate{agentSuccessor.root}, gatewayRoots: []*x509.Certificate{gatewaySuccessor.root}, wantSuccess: true},
		{name: "normalized successor-only rejects old agent", agentAuthority: agentCurrent, gatewayAuthority: gatewaySuccessor, agentRoots: []*x509.Certificate{agentSuccessor.root}, gatewayRoots: []*x509.Certificate{gatewaySuccessor.root}},
		{name: "normalized successor-only rejects old gateway", agentAuthority: agentSuccessor, gatewayAuthority: gatewayCurrent, agentRoots: []*x509.Certificate{agentSuccessor.root}, gatewayRoots: []*x509.Certificate{gatewaySuccessor.root}},
	} {
		t.Run(test.name, func(t *testing.T) {
			assertContinuityMutualTLS(t, test.gatewayAuthority, test.agentAuthority, test.gatewayRoots, test.agentRoots, test.wantSuccess)
		})
	}
}

func assertContinuityMutualTLS(
	t *testing.T,
	gatewayAuthority, agentAuthority continuityCA,
	gatewayRoots, agentRoots []*x509.Certificate,
	wantSuccess bool,
) {
	t.Helper()
	const dnsName = "gateway.internal.example"
	gatewayKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate gateway overlap key: %v", err)
	}
	agentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate agent overlap key: %v", err)
	}
	gatewayLeaf := newContinuityGatewayLeaf(t, gatewayAuthority, gatewayKey.Public(), dnsName)
	agentLeaf := newContinuityAgentLeaf(t, agentAuthority, agentKey.Public(), enrolledClientDeviceID)
	agentPool := x509.NewCertPool()
	for _, root := range agentRoots {
		agentPool.AddCert(root)
	}
	gatewayPool := x509.NewCertPool()
	for _, root := range gatewayRoots {
		gatewayPool.AddCert(root)
	}
	serverTLS, err := identity.ServerTLSConfig(tls.Certificate{Certificate: [][]byte{gatewayLeaf}, PrivateKey: gatewayKey}, agentPool, identity.AgentClass)
	if err != nil {
		t.Fatalf("build overlap gateway TLS config: %v", err)
	}
	clientTLS, err := identity.ClientTLSConfig(tls.Certificate{Certificate: [][]byte{agentLeaf}, PrivateKey: agentKey}, gatewayPool, dnsName, identity.GatewayClass)
	if err != nil {
		t.Fatalf("build overlap agent TLS config: %v", err)
	}
	validationTime := gatewayAuthority.root.NotBefore.Add(time.Hour)
	serverTLS.Time = func() time.Time { return validationTime }
	clientTLS.Time = func() time.Time { return validationTime }
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = serverTLS
	server.StartTLS()
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: clientTLS}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Get(server.URL)
	if wantSuccess {
		if err != nil {
			t.Fatalf("real overlap mTLS failed: %v", err)
		}
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Fatalf("close overlap TLS response: %v", closeErr)
		}
		return
	}
	if err == nil {
		_ = response.Body.Close()
		t.Fatal("real successor-only mTLS accepted a predecessor-issued peer after prune/normalize")
	}
}

type continuityLeafResult struct {
	der []byte
	err error
}

func newContinuityAgentLeafWithoutTest(now time.Time, authority continuityCA, publicKey crypto.PublicKey, deviceID string) continuityLeafResult {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3), NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(-time.Minute).Add(agentCertificateLifetime), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if err := identity.StampCertificateIdentity(template, identity.AgentClass, deviceID); err != nil {
		return continuityLeafResult{err: err}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.root, publicKey, authority.signer)
	return continuityLeafResult{der: der, err: err}
}

func newContinuityAgentLeaf(t *testing.T, authority continuityCA, publicKey crypto.PublicKey, deviceID string) []byte {
	t.Helper()
	result := newContinuityAgentLeafWithoutTest(time.Now().UTC(), authority, publicKey, deviceID)
	if result.err != nil {
		t.Fatalf("create continuity agent leaf: %v", result.err)
	}
	return result.der
}

func newEnrollmentSealingPrivateKey(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate continuity sealing key: %v", err)
	}
	return key
}

func newContinuityGatewayLeaf(t *testing.T, authority continuityCA, publicKey crypto.PublicKey, dnsName string) []byte {
	t.Helper()
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(45*24*time.Hour - time.Minute),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, DNSNames: []string{dnsName},
	}
	if err := identity.StampCertificateIdentity(template, identity.GatewayClass, "01ARZ3NDEKTSV4RRFFQ69G5FB0"); err != nil {
		t.Fatalf("stamp gateway identity: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, authority.root, publicKey, authority.signer)
	if err != nil {
		t.Fatalf("create continuity gateway leaf: %v", err)
	}
	return der
}

func signedAgentPendingConfirmation(
	t *testing.T,
	bundle CredentialBundle,
	claimedClass string,
) (*PendingTrustConfirmation, []byte) {
	t.Helper()
	expected := bundle.AgentTrustBundle
	if claimedClass == "gateway" {
		expected = bundle.GatewayTrustBundle
	}
	reporterFingerprint := sha256.Sum256(bundle.CertificateDER)
	claim := sign.TrustStateClaim{
		ReporterClass: "agent", ClaimedClass: claimedClass,
		Generation: expected.Generation, Revision: expected.Revision,
		ReporterCertificateFingerprint: bytes.Clone(reporterFingerprint[:]),
		RootFingerprints:               rootFingerprints(expected.RootCertificateDER...),
	}
	signature, err := sign.SignTrustState(bundle.PrivateKey, claim)
	if err != nil {
		t.Fatalf("sign exact durable %s pending claim: %v", claimedClass, err)
	}
	pending := &PendingTrustConfirmation{
		Generation: claim.Generation, Revision: claim.Revision,
		RootFingerprints:     cloneDERList(claim.RootFingerprints),
		CRLIssuerFingerprint: bytes.Clone(claim.CRLIssuerFingerprint),
		CRLSequence:          claim.CRLSequence,
		Signature:            bytes.Clone(signature),
	}
	request := &powermanagev1.ConfirmTrustStateRequest{
		CertificateDer: bytes.Clone(bundle.CertificateDER), ClaimedClass: claimedClass,
		Generation: claim.Generation, Revision: claim.Revision,
		RootFingerprints:     cloneDERList(claim.RootFingerprints),
		CrlIssuerFingerprint: bytes.Clone(claim.CRLIssuerFingerprint),
		CrlSequence:          claim.CRLSequence,
		Signature:            bytes.Clone(signature),
	}
	if err := verifyCapturedTrustStateRequest("agent", request, bundle.CertificateDER); err != nil {
		t.Fatalf("constructed pending request is not certificate/class/key-bound: %v", err)
	}
	wire, err := proto.Marshal(request)
	if err != nil {
		t.Fatalf("marshal exact signed pending request: %v", err)
	}
	return pending, wire
}

func verifyCapturedTrustStateRequest(
	reporterClass string,
	request *powermanagev1.ConfirmTrustStateRequest,
	activeCertificateDER ...[]byte,
) error {
	if request == nil {
		return errors.New("nil captured trust-state request")
	}
	certificate, err := x509.ParseCertificate(request.GetCertificateDer())
	if err != nil || !bytes.Equal(certificate.Raw, request.GetCertificateDer()) {
		return errors.New("captured reporter certificate is not exact DER")
	}
	if len(activeCertificateDER) > 0 && !bytes.Equal(request.GetCertificateDer(), activeCertificateDER[0]) {
		return errors.New("captured reporter certificate is not the active local identity")
	}
	class, _, err := identity.ParseCertificateIdentity(certificate)
	if err != nil || string(class) != reporterClass {
		return errors.New("captured reporter certificate class does not match invoked procedure")
	}
	reporterFingerprint := sha256.Sum256(request.GetCertificateDer())
	claim := sign.TrustStateClaim{
		ReporterClass: reporterClass, ClaimedClass: request.GetClaimedClass(),
		Generation: request.GetGeneration(), Revision: request.GetRevision(),
		ReporterCertificateFingerprint: bytes.Clone(reporterFingerprint[:]),
		RootFingerprints:               cloneDERList(request.GetRootFingerprints()),
		CRLIssuerFingerprint:           bytes.Clone(request.GetCrlIssuerFingerprint()),
		CRLSequence:                    request.GetCrlSequence(),
	}
	if len(request.GetSignature()) == 0 {
		return errors.New("captured trust-state signature is empty")
	}
	if err := sign.VerifyTrustState(certificate.PublicKey, claim, request.GetSignature()); err != nil {
		return err
	}
	return nil
}

func rootFingerprints(roots ...[]byte) [][]byte {
	result := make([][]byte, 0, len(roots))
	for _, root := range roots {
		fingerprint := sha256.Sum256(root)
		result = append(result, bytes.Clone(fingerprint[:]))
	}
	return result
}

func exactRoots(got [][]byte, want ...[]byte) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if !bytes.Equal(got[index], want[index]) {
			return false
		}
	}
	return true
}

func cloneStoredTrustBundle(bundle *powermanagev1.CATrustBundle) StoredTrustBundle {
	if bundle == nil {
		return StoredTrustBundle{}
	}
	return StoredTrustBundle{
		Generation: bundle.GetGeneration(), Revision: bundle.GetRevision(),
		RootCertificateDER:       cloneDERList(bundle.GetRootCertificateDer()),
		TransitionCertificateDER: bytes.Clone(bundle.GetTransitionCertificateDer()),
	}
}

func cloneDERList(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = bytes.Clone(values[index])
	}
	return result
}

func cloneCredentialBundle(bundle CredentialBundle) CredentialBundle {
	bundle.CertificateDER = bytes.Clone(bundle.CertificateDER)
	bundle.CertificateAuthorityDER = bytes.Clone(bundle.CertificateAuthorityDER)
	bundle.GatewayCertificateAuthorityDER = bytes.Clone(bundle.GatewayCertificateAuthorityDER)
	bundle.AgentTrustBundle.RootCertificateDER = cloneDERList(bundle.AgentTrustBundle.RootCertificateDER)
	bundle.AgentTrustBundle.TransitionCertificateDER = bytes.Clone(bundle.AgentTrustBundle.TransitionCertificateDER)
	bundle.GatewayTrustBundle.RootCertificateDER = cloneDERList(bundle.GatewayTrustBundle.RootCertificateDER)
	bundle.GatewayTrustBundle.TransitionCertificateDER = bytes.Clone(bundle.GatewayTrustBundle.TransitionCertificateDER)
	if bundle.PendingAgentTrustConfirmation != nil {
		pending := *bundle.PendingAgentTrustConfirmation
		pending.RootFingerprints = cloneDERList(pending.RootFingerprints)
		pending.CRLIssuerFingerprint = bytes.Clone(pending.CRLIssuerFingerprint)
		pending.Signature = bytes.Clone(pending.Signature)
		bundle.PendingAgentTrustConfirmation = &pending
	}
	if bundle.PendingGatewayTrustConfirmation != nil {
		pending := *bundle.PendingGatewayTrustConfirmation
		pending.RootFingerprints = cloneDERList(pending.RootFingerprints)
		pending.CRLIssuerFingerprint = bytes.Clone(pending.CRLIssuerFingerprint)
		pending.Signature = bytes.Clone(pending.Signature)
		bundle.PendingGatewayTrustConfirmation = &pending
	}
	return bundle
}

func pendingConfirmationCount(bundle CredentialBundle) int {
	count := 0
	if bundle.PendingAgentTrustConfirmation != nil {
		count++
	}
	if bundle.PendingGatewayTrustConfirmation != nil {
		count++
	}
	return count
}

func assertPendingConfirmationProgression(t *testing.T, history []CredentialBundle, want ...int) {
	t.Helper()
	if len(history) < len(want) {
		t.Fatalf("pending-confirmation persistence history has %d states; want suffix %v", len(history), want)
	}
	history = history[len(history)-len(want):]
	for index, bundle := range history {
		if got := pendingConfirmationCount(bundle); got != want[index] {
			t.Fatalf("pending-confirmation persistence suffix[%d] = %d; want %d (full suffix %v)", index, got, want[index], want)
		}
	}
}

func assertAgentRenewalConfirmationSet(t *testing.T, handler *continuityClientHandler, bundle CredentialBundle) {
	t.Helper()
	if len(handler.agentConfirmationWire) != 2 || len(handler.gatewayConfirmationWire) != 0 {
		t.Fatalf("renewal confirmation RPC wires = (%d agent-reporter, %d gateway-reporter); want two independent agent-reporter claims",
			len(handler.agentConfirmationWire), len(handler.gatewayConfirmationWire))
	}
	requests := make([]*powermanagev1.ConfirmTrustStateRequest, 0, 2)
	for _, wire := range handler.agentConfirmationWire {
		request := new(powermanagev1.ConfirmTrustStateRequest)
		if err := proto.Unmarshal(wire, request); err != nil {
			t.Fatalf("unmarshal agent renewal confirmation: %v", err)
		}
		requests = append(requests, request)
	}
	assertExactAgentReporterClaims(t, requests, bundle)
}

func assertFreshAgentConfirmationSet(t *testing.T, handler *continuityEnrollmentHandler, bundle CredentialBundle) {
	t.Helper()
	if handler.gatewayReporterCalls != 0 {
		t.Fatalf("fresh agent enrollment used gateway-reporter confirmation RPC %d times", handler.gatewayReporterCalls)
	}
	assertExactAgentReporterClaims(t, handler.confirmRequests, bundle)
}

func assertExactAgentReporterClaims(t *testing.T, requests []*powermanagev1.ConfirmTrustStateRequest, bundle CredentialBundle) {
	t.Helper()
	if len(requests) != 2 {
		t.Fatalf("agent-reporter confirmation claims = %d; want exact independent agent and gateway claims", len(requests))
	}
	seen := make(map[string]bool, 2)
	for _, request := range requests {
		if err := verifyCapturedTrustStateRequest("agent", request, bundle.CertificateDER); err != nil {
			t.Fatalf("agent-reporter request does not carry a valid exact signed claim: %v", err)
		}
		if !bytes.Equal(request.GetCertificateDer(), bundle.CertificateDER) {
			t.Fatalf("agent-reporter claim certificate = %x; want exact locally committed agent identity",
				request.GetCertificateDer())
		}
		claimedClass := request.GetClaimedClass()
		if (claimedClass != "agent" && claimedClass != "gateway") || seen[claimedClass] {
			t.Fatalf("agent-reporter claimed classes are not the exact independent set: duplicate/unknown %q", claimedClass)
		}
		seen[claimedClass] = true
		expected := bundle.AgentTrustBundle
		if claimedClass == "gateway" {
			expected = bundle.GatewayTrustBundle
		}
		if request.GetGeneration() != expected.Generation || request.GetRevision() != expected.Revision ||
			!equalDERLists(request.GetRootFingerprints(), rootFingerprints(expected.RootCertificateDER...)) {
			t.Fatalf("agent-reporter %s claim bundle = (%d,%d,%x); want exact committed bundle (%d,%d,%x)", claimedClass,
				request.GetGeneration(), request.GetRevision(), request.GetRootFingerprints(), expected.Generation, expected.Revision, rootFingerprints(expected.RootCertificateDER...))
		}
		if len(request.GetCrlIssuerFingerprint()) != 0 || request.GetCrlSequence() != 0 {
			t.Fatalf("agent-reporter %s claim carried forbidden CRL receipt (%x,%d)", claimedClass, request.GetCrlIssuerFingerprint(), request.GetCrlSequence())
		}
	}
	if !seen["agent"] || !seen["gateway"] {
		t.Fatalf("agent-reporter claimed classes = %v; want agent and gateway", seen)
	}
}

func assertContinuityBundleEqual(t *testing.T, got, want CredentialBundle) {
	t.Helper()
	if got.DeviceID != want.DeviceID ||
		!bytes.Equal(got.CertificateDER, want.CertificateDER) ||
		!bytes.Equal(got.CertificateAuthorityDER, want.CertificateAuthorityDER) ||
		!bytes.Equal(got.GatewayCertificateAuthorityDER, want.GatewayCertificateAuthorityDER) ||
		!samePrivateKey(got.PrivateKey, want.PrivateKey) ||
		!sameSealingKey(got.SealingPrivateKey, want.SealingPrivateKey) ||
		got.AgentTrustBundle.Generation != want.AgentTrustBundle.Generation ||
		got.AgentTrustBundle.Revision != want.AgentTrustBundle.Revision ||
		!equalDERLists(got.AgentTrustBundle.RootCertificateDER, want.AgentTrustBundle.RootCertificateDER) ||
		!bytes.Equal(got.AgentTrustBundle.TransitionCertificateDER, want.AgentTrustBundle.TransitionCertificateDER) ||
		got.GatewayTrustBundle.Generation != want.GatewayTrustBundle.Generation ||
		got.GatewayTrustBundle.Revision != want.GatewayTrustBundle.Revision ||
		!equalDERLists(got.GatewayTrustBundle.RootCertificateDER, want.GatewayTrustBundle.RootCertificateDER) ||
		!bytes.Equal(got.GatewayTrustBundle.TransitionCertificateDER, want.GatewayTrustBundle.TransitionCertificateDER) ||
		!reflect.DeepEqual(got.PendingAgentTrustConfirmation, want.PendingAgentTrustConfirmation) ||
		!reflect.DeepEqual(got.PendingGatewayTrustConfirmation, want.PendingGatewayTrustConfirmation) {
		t.Fatalf("credential bundle changed on rejection:\n got %+v\nwant %+v", got, want)
	}
}

func samePrivateKey(first, second crypto.Signer) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	firstDER, firstErr := x509.MarshalPKCS8PrivateKey(first)
	secondDER, secondErr := x509.MarshalPKCS8PrivateKey(second)
	return firstErr == nil && secondErr == nil && bytes.Equal(firstDER, secondDER)
}

func sameSealingKey(first, second *ecdh.PrivateKey) bool {
	if first == nil || second == nil {
		return first == nil && second == nil
	}
	return bytes.Equal(first.Bytes(), second.Bytes())
}

func equalDERLists(first, second [][]byte) bool {
	return len(first) == len(second) && slices.EqualFunc(first, second, bytes.Equal)
}

func stringHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, len(value)*2)
	for index, octet := range value {
		encoded[index*2] = alphabet[octet>>4]
		encoded[index*2+1] = alphabet[octet&0x0f]
	}
	return string(encoded)
}
