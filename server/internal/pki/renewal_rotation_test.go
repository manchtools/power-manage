package pki

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/sign"
	"github.com/manchtools/power-manage/server/internal/store"
)

func TestRenewalHandler_MigrationPhaseIssuesFromSuccessorAndReturnsExactProofs(t *testing.T) {
	t.Run("stable retry survives the first rotation event", func(t *testing.T) {
		exerciseAgentStableRetryAfterFirstRotationEvent(t)
	})
	t.Run("agent current-issued retry survives trust to migrate", func(t *testing.T) {
		exerciseAgentRenewalRetryAcrossPhase(t, false)
	})
	t.Run("agent successor-issued retry is exact", func(t *testing.T) {
		exerciseAgentRenewalRetryAcrossPhase(t, true)
	})
	t.Run("gateway current-issued retry survives trust to migrate", func(t *testing.T) {
		exerciseGatewayRenewalRetryAcrossPhase(t, false)
	})
	t.Run("gateway successor-issued retry is exact", func(t *testing.T) {
		exerciseGatewayRenewalRetryAcrossPhase(t, true)
	})

	fixture := newEnrollmentHandlerFixture(t, 1)
	currentKey, currentCertificateDER, deviceID := enrollRenewalFixture(t, fixture)
	successor := newRotationCA(t, "agent migration successor", fixture.service.now())
	distributor := &recordingTrustBundleDistributor{}
	manager, err := NewRotationManager(RotationManagerConfig{
		EventStore: fixture.eventStore, Authorities: fixture.service.authorities, Distributor: distributor,
		SuccessorSigners: map[store.CertificateClass]crypto.Signer{store.CertificateClassAgent: successor.signer},
	})
	if err != nil {
		t.Fatalf("create rotation manager: %v", err)
	}
	manager.now = fixture.service.now
	fixture.service.rotationManager = manager
	transitionDER := crossSignRotationCA(t, rotationCA{
		root: fixture.agentCA, signer: fixture.service.authorities.agentCA.signer,
	}, successor)
	if err := manager.BeginTrust(
		context.Background(), store.CertificateClassAgent,
		successor.root.Raw, transitionDER, successor.signer,
	); err != nil {
		t.Fatalf("begin agent trust phase: %v", err)
	}
	trust, err := manager.Snapshot(context.Background(), store.CertificateClassAgent)
	if err != nil {
		t.Fatalf("read trust snapshot: %v", err)
	}
	confirmRenewalRootConsumers(t, fixture, manager, trust)
	if err := manager.Migrate(context.Background(), store.CertificateClassAgent); err != nil {
		t.Fatalf("enter agent migrate phase: %v", err)
	}

	request := &powermanagev1.RenewAgentRequest{
		CertificateDer:               currentCertificateDER,
		CertificateSigningRequestDer: newEnrollmentCSR(t, currentKey, pkix.Name{}, nil),
		SealingPublicKey:             newEnrollmentSealingKey(t),
	}
	response, err := fixture.client.RenewAgent(
		context.Background(), connect.NewRequest(proto.Clone(request).(*powermanagev1.RenewAgentRequest)),
	)
	if err != nil {
		t.Fatalf("RenewAgent in migrate: %v", err)
	}
	renewed, err := x509.ParseCertificate(response.Msg.GetCertificateDer())
	if err != nil {
		t.Fatalf("parse migration certificate: %v", err)
	}
	if err := renewed.CheckSignatureFrom(successor.root); err != nil {
		t.Fatalf("migration certificate is not successor-issued: %v", err)
	}
	agentBundle := response.Msg.GetAgentTrustBundle()
	if agentBundle.GetGeneration() != trust.Generation || agentBundle.GetRevision() != trust.Revision ||
		!equalRotationDERLists(agentBundle.GetRootCertificateDer(), trust.DesiredRootDER) ||
		!bytes.Equal(agentBundle.GetTransitionCertificateDer(), transitionDER) {
		t.Fatalf("migration agent bundle = %+v; want exact durable roots and old-root proof", agentBundle)
	}
	gatewaySnapshot, err := manager.Snapshot(context.Background(), store.CertificateClassGateway)
	if err != nil {
		t.Fatalf("read gateway snapshot returned with agent renewal: %v", err)
	}
	assertRenewalBundleExact(t, response.Msg.GetGatewayTrustBundle(), gatewaySnapshot)
	proof, err := x509.ParseCertificate(agentBundle.GetTransitionCertificateDer())
	if err != nil || !bytes.Equal(proof.RawSubject, successor.root.RawSubject) ||
		!bytes.Equal(proof.RawIssuer, fixture.agentCA.RawSubject) || proof.CheckSignatureFrom(fixture.agentCA) != nil {
		t.Fatalf("transition proof does not bind current to exact successor: %v", err)
	}
	if bytes.Equal(renewed.RawIssuer, proof.RawSubject) && bytes.Equal(renewed.AuthorityKeyId, proof.SubjectKeyId) {
		// This identity relation is expected; the important boundary is that the
		// response carries the proof as metadata rather than as a peer-chain DER.
	} else {
		t.Fatal("migration leaf issuer does not identify the successor root")
	}

	stored, err := fixture.eventStore.Device(context.Background(), deviceID)
	if err != nil {
		t.Fatalf("read migration-renewed device: %v", err)
	}
	reporter := rotationReporter{
		id: deviceID, class: store.CertificateClassAgent,
		certificateDER: stored.CertificateDER, signer: currentKey,
	}
	migrate, err := manager.Snapshot(context.Background(), store.CertificateClassAgent)
	if err != nil {
		t.Fatalf("read migrate snapshot: %v", err)
	}
	claim := leafClaim(migrate, reporter)
	signature, err := sign.SignTrustState(reporter.signer, claim)
	if err != nil {
		t.Fatalf("sign successor-leaf confirmation: %v", err)
	}
	if err := manager.ConfirmTrustState(context.Background(), TrustStateConfirmation{
		ReporterCertificateDER: reporter.certificateDER, Claim: claim, Signature: signature,
	}); err != nil {
		t.Fatalf("confirm successor-issued leaf: %v", err)
	}
	if err := manager.Retire(context.Background(), store.CertificateClassAgent); err != nil {
		t.Fatalf("advance phase after committed response was lost: %v", err)
	}

	retry := proto.Clone(request).(*powermanagev1.RenewAgentRequest)
	retry.CertificateSigningRequestDer = newEnrollmentCSR(t, currentKey, pkix.Name{}, nil)
	retried, err := fixture.client.RenewAgent(context.Background(), connect.NewRequest(retry))
	if err != nil {
		t.Fatalf("retry old renewal after phase advance: %v", err)
	}
	if !bytes.Equal(retried.Msg.GetCertificateDer(), response.Msg.GetCertificateDer()) {
		t.Fatal("lost-response retry minted or selected a different certificate after phase advance")
	}
	if !proto.Equal(retried.Msg, response.Msg) {
		t.Fatal("lost-response retry changed transition proof or either class trust bundle")
	}
	if got := certificateEventCount(t, fixture, deviceID); got != 2 {
		t.Fatalf("device event count after phase-advanced retry = %d; want enrollment plus one renewal", got)
	}
}

func exerciseAgentStableRetryAfterFirstRotationEvent(t *testing.T) {
	t.Helper()
	fixture := newEnrollmentHandlerFixture(t, 1)
	key, currentDER, deviceID := enrollRenewalFixture(t, fixture)
	successor := newRotationCA(t, "agent post-renewal successor", fixture.service.now())
	manager := attachRetryRotationManager(t, fixture, store.CertificateClassAgent, successor)
	request := &powermanagev1.RenewAgentRequest{
		CertificateDer: currentDER, CertificateSigningRequestDer: newEnrollmentCSR(t, key, pkix.Name{}, nil),
		SealingPublicKey: newEnrollmentSealingKey(t),
	}
	first, err := fixture.client.RenewAgent(
		context.Background(), connect.NewRequest(proto.Clone(request).(*powermanagev1.RenewAgentRequest)),
	)
	if err != nil {
		t.Fatalf("renew before first rotation event: %v", err)
	}
	beginRetryTrust(t, fixture, manager, store.CertificateClassAgent, successor)
	retry, err := fixture.client.RenewAgent(
		context.Background(), connect.NewRequest(proto.Clone(request).(*powermanagev1.RenewAgentRequest)),
	)
	if err != nil {
		t.Fatalf("retry renewal after first rotation event: %v", err)
	}
	if !proto.Equal(retry.Msg, first.Msg) || certificateEventCount(t, fixture, deviceID) != 2 {
		t.Fatal("pre-rotation renewal retry did not preserve its exact stable bundles and certificate")
	}
}

func exerciseAgentRenewalRetryAcrossPhase(t *testing.T, successorIssued bool) {
	t.Helper()
	fixture := newEnrollmentHandlerFixture(t, 1)
	key, currentDER, deviceID := enrollRenewalFixture(t, fixture)
	successor := newRotationCA(t, "agent retry successor", fixture.service.now())
	manager := attachRetryRotationManager(t, fixture, store.CertificateClassAgent, successor)
	trust := beginRetryTrust(t, fixture, manager, store.CertificateClassAgent, successor)
	if successorIssued {
		confirmRenewalRootConsumers(t, fixture, manager, trust)
		if err := manager.Migrate(context.Background(), store.CertificateClassAgent); err != nil {
			t.Fatalf("enter agent migrate before renewal: %v", err)
		}
	}
	request := &powermanagev1.RenewAgentRequest{
		CertificateDer: currentDER, CertificateSigningRequestDer: newEnrollmentCSR(t, key, pkix.Name{}, nil),
		SealingPublicKey: newEnrollmentSealingKey(t),
	}
	first, err := fixture.client.RenewAgent(context.Background(), connect.NewRequest(proto.Clone(request).(*powermanagev1.RenewAgentRequest)))
	if err != nil {
		t.Fatalf("first agent retry fixture renewal: %v", err)
	}
	wantIssuer := fixture.agentCA
	if successorIssued {
		wantIssuer = successor.root
	}
	if err := parseEnrollmentCertificate(t, first.Msg.GetCertificateDer()).CheckSignatureFrom(wantIssuer); err != nil {
		t.Fatalf("agent retry fixture used wrong phase issuer: %v", err)
	}
	assertBothRenewalBundlesExact(t, manager, first.Msg.GetAgentTrustBundle(), first.Msg.GetGatewayTrustBundle())
	if !successorIssued {
		confirmRenewalRootConsumers(t, fixture, manager, trust)
		if err := manager.Migrate(context.Background(), store.CertificateClassAgent); err != nil {
			t.Fatalf("advance agent class after committed old-issued renewal: %v", err)
		}
	}
	retry, err := fixture.client.RenewAgent(context.Background(), connect.NewRequest(proto.Clone(request).(*powermanagev1.RenewAgentRequest)))
	if err != nil {
		t.Fatalf("retry agent renewal: %v", err)
	}
	if !proto.Equal(retry.Msg, first.Msg) || certificateEventCount(t, fixture, deviceID) != 2 {
		t.Fatal("agent retry did not return exact committed DER, proofs, and both bundles without another event")
	}
}

func exerciseGatewayRenewalRetryAcrossPhase(t *testing.T, successorIssued bool) {
	t.Helper()
	fixture := newGatewayEnrollmentHandlerFixture(t, 1, []string{"gateway.internal.example"})
	key, currentDER, gatewayID := enrollGatewayFixture(t, fixture)
	successor := newRotationCA(t, "gateway retry successor", fixture.service.now())
	manager := attachRetryRotationManager(t, fixture, store.CertificateClassGateway, successor)
	trust := beginRetryTrust(t, fixture, manager, store.CertificateClassGateway, successor)
	if successorIssued {
		confirmRenewalRootConsumers(t, fixture, manager, trust)
		if err := manager.Migrate(context.Background(), store.CertificateClassGateway); err != nil {
			t.Fatalf("enter gateway migrate before renewal: %v", err)
		}
	}
	request := &powermanagev1.RenewGatewayRequest{
		CertificateDer: currentDER, CertificateSigningRequestDer: newEnrollmentCSR(t, key, pkix.Name{}, nil),
	}
	first, err := fixture.client.RenewGateway(context.Background(), connect.NewRequest(proto.Clone(request).(*powermanagev1.RenewGatewayRequest)))
	if err != nil {
		t.Fatalf("first gateway retry fixture renewal: %v", err)
	}
	wantIssuer := fixture.gatewayCA
	if successorIssued {
		wantIssuer = successor.root
	}
	if err := parseEnrollmentCertificate(t, first.Msg.GetCertificateDer()).CheckSignatureFrom(wantIssuer); err != nil {
		t.Fatalf("gateway retry fixture used wrong phase issuer: %v", err)
	}
	assertBothRenewalBundlesExact(t, manager, first.Msg.GetAgentTrustBundle(), first.Msg.GetGatewayTrustBundle())
	if !successorIssued {
		confirmRenewalRootConsumers(t, fixture, manager, trust)
		if err := manager.Migrate(context.Background(), store.CertificateClassGateway); err != nil {
			t.Fatalf("advance gateway class after committed old-issued renewal: %v", err)
		}
	}
	retry, err := fixture.client.RenewGateway(context.Background(), connect.NewRequest(proto.Clone(request).(*powermanagev1.RenewGatewayRequest)))
	if err != nil {
		t.Fatalf("retry gateway renewal: %v", err)
	}
	if !proto.Equal(retry.Msg, first.Msg) || pkiEventCountForStream(t, fixture, "gateway", gatewayID) != 2 {
		t.Fatal("gateway retry did not return exact committed DER, proofs, and both bundles without another event")
	}
}

func attachRetryRotationManager(t *testing.T, fixture enrollmentHandlerFixture, class store.CertificateClass, successor rotationCA) *RotationManager {
	t.Helper()
	agentSuccessor := newRotationCA(t, "unused agent retry successor", fixture.service.now())
	gatewaySuccessor := newRotationCA(t, "unused gateway retry successor", fixture.service.now())
	if class == store.CertificateClassAgent {
		agentSuccessor = successor
	} else {
		gatewaySuccessor = successor
	}
	manager, err := NewRotationManager(RotationManagerConfig{
		EventStore: fixture.eventStore, Authorities: fixture.service.authorities, Distributor: &recordingTrustBundleDistributor{},
		SuccessorSigners: map[store.CertificateClass]crypto.Signer{
			store.CertificateClassAgent: agentSuccessor.signer, store.CertificateClassGateway: gatewaySuccessor.signer,
		},
	})
	if err != nil {
		t.Fatalf("create retry rotation manager: %v", err)
	}
	manager.now = fixture.service.now
	fixture.service.rotationManager = manager
	return manager
}

func beginRetryTrust(t *testing.T, fixture enrollmentHandlerFixture, manager *RotationManager, class store.CertificateClass, successor rotationCA) AuthoritySnapshot {
	t.Helper()
	current := rotationCA{root: fixture.agentCA, signer: fixture.service.authorities.agentCA.signer}
	if class == store.CertificateClassGateway {
		current = rotationCA{root: fixture.gatewayCA, signer: fixture.service.authorities.gatewayCA.signer}
	}
	if err := manager.BeginTrust(context.Background(), class, successor.root.Raw, crossSignRotationCA(t, current, successor), successor.signer); err != nil {
		t.Fatalf("begin retry trust phase: %v", err)
	}
	state, err := manager.Snapshot(context.Background(), class)
	if err != nil {
		t.Fatalf("read retry trust snapshot: %v", err)
	}
	return state
}

func confirmRenewalRootConsumers(t *testing.T, fixture enrollmentHandlerFixture, manager *RotationManager, state AuthoritySnapshot) {
	t.Helper()
	rotationFixture := rotationManagerFixture{
		pool: fixture.pool, eventStore: fixture.eventStore, authorities: fixture.service.authorities, manager: manager,
		agentCurrent:   rotationCA{root: fixture.agentCA, signer: fixture.service.authorities.agentCA.signer},
		gatewayCurrent: rotationCA{root: fixture.gatewayCA, signer: fixture.service.authorities.gatewayCA.signer},
		now:            fixture.service.now(),
	}
	reporterID := "01J00000000000000000000073"
	if state.Class == store.CertificateClassGateway {
		reporterID = "01J00000000000000000000074"
	}
	reporter := rotationFixture.seedOppositeConsumer(t, state.Class, reporterID)
	rotationFixture.confirmRootConsumer(t, state, reporter)
}

func assertBothRenewalBundlesExact(t *testing.T, manager *RotationManager, agent, gateway *powermanagev1.CATrustBundle) {
	t.Helper()
	agentState, err := manager.Snapshot(context.Background(), store.CertificateClassAgent)
	if err != nil {
		t.Fatalf("read agent bundle snapshot: %v", err)
	}
	gatewayState, err := manager.Snapshot(context.Background(), store.CertificateClassGateway)
	if err != nil {
		t.Fatalf("read gateway bundle snapshot: %v", err)
	}
	assertRenewalBundleExact(t, agent, agentState)
	assertRenewalBundleExact(t, gateway, gatewayState)
}

func assertRenewalBundleExact(t *testing.T, bundle *powermanagev1.CATrustBundle, state AuthoritySnapshot) {
	t.Helper()
	if bundle == nil || bundle.GetGeneration() != state.Generation || bundle.GetRevision() != state.Revision ||
		!equalRotationDERLists(bundle.GetRootCertificateDer(), state.DesiredRootDER) ||
		!bytes.Equal(bundle.GetTransitionCertificateDer(), state.TransitionCertificateDER) {
		t.Fatalf("renewal bundle = %+v; want exact durable snapshot %+v", bundle, state)
	}
}

func certificateEventCount(t *testing.T, fixture enrollmentHandlerFixture, deviceID string) int {
	t.Helper()
	var count int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM events WHERE stream_type = 'device' AND stream_id = $1`, deviceID).Scan(&count); err != nil {
		t.Fatalf("count device certificate events: %v", err)
	}
	return count
}
