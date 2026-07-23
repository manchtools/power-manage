package pki

import (
	"context"
	"crypto"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/jackc/pgx/v5/pgxpool"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/store"
)

func TestRotationManagers_SharedPostgresFenceDrainsIssuanceThroughCommit(t *testing.T) {
	exerciseRealIssuanceRPCFences(t)

	fixture := newRotationManagerFixture(t)
	otherStore, err := store.NewProduction(fixture.pool)
	if err != nil {
		t.Fatalf("create independent production event store: %v", err)
	}
	otherAuthorities, err := NewAuthorities(
		fixture.agentCurrent.root.Raw, fixture.agentCurrent.signer,
		fixture.gatewayCurrent.root.Raw, fixture.gatewayCurrent.signer,
		fixture.authorities.commandSigner,
	)
	if err != nil {
		t.Fatalf("create independent authorities from the same configured key material: %v", err)
	}
	if otherAuthorities == fixture.authorities {
		t.Fatal("cross-process fence fixture reused the same mutable Authorities object")
	}
	otherDistributor := &recordingTrustBundleDistributor{}
	other, err := NewRotationManager(RotationManagerConfig{
		EventStore: otherStore, Authorities: otherAuthorities, Distributor: otherDistributor,
		SuccessorSigners: map[store.CertificateClass]crypto.Signer{
			store.CertificateClassAgent:   fixture.agentSuccessor.signer,
			store.CertificateClassGateway: fixture.gatewaySuccessor.signer,
		},
	})
	if err != nil {
		t.Fatalf("create independent rotation manager: %v", err)
	}
	other.now = fixture.manager.now

	issuanceEntered := make(chan AuthoritySnapshot, 1)
	releaseIssuance := make(chan struct{})
	issuanceDone := make(chan error, 1)
	go func() {
		issuanceDone <- fixture.manager.withIssuanceFences(context.Background(), func(agent, gateway AuthoritySnapshot) error {
			issuanceEntered <- agent
			<-releaseIssuance
			return nil
		})
	}()
	stable := <-issuanceEntered
	if stable.Phase != RotationPhaseStable || stable.Generation != 1 {
		t.Fatalf("fenced issuance snapshot = %+v; want durable stable generation one", stable)
	}

	transitionDone := make(chan error, 1)
	transitionStarted := make(chan struct{})
	transitionDER := crossSignRotationCA(t, fixture.agentCurrent, fixture.agentSuccessor)
	go func() {
		close(transitionStarted)
		transitionDone <- other.BeginTrust(
			context.Background(), store.CertificateClassAgent,
			fixture.agentSuccessor.root.Raw,
			transitionDER,
			fixture.agentSuccessor.signer,
		)
	}()
	<-transitionStarted
	waitForPostgresAdvisoryWaiters(t, fixture.pool, 1)
	close(releaseIssuance)
	if err := <-issuanceDone; err != nil {
		t.Fatalf("complete fenced issuance: %v", err)
	}
	if err := <-transitionDone; err != nil {
		t.Fatalf("transition after issuance commit: %v", err)
	}

	state, err := fixture.manager.Snapshot(context.Background(), store.CertificateClassAgent)
	if err != nil {
		t.Fatalf("stale manager reload after cross-process transition: %v", err)
	}
	if state.Phase != RotationPhaseTrust || state.Generation != 2 {
		t.Fatalf("reloaded cross-process state = %+v; want committed trust generation two", state)
	}
	var events int
	if err := fixture.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM events WHERE stream_type = 'ca-rotation' AND stream_id = 'agent'`,
	).Scan(&events); err != nil {
		t.Fatalf("count committed rotation events: %v", err)
	}
	if events == 0 || len(otherDistributor.publications) == 0 {
		t.Fatalf("transition effects = (%d durable events, %d publications); want committed event before immutable publication",
			events, len(otherDistributor.publications))
	}
}

func TestRotationManagers_CrossClassConsumerFencesBlockTransitionRaces(t *testing.T) {
	exerciseRealConfirmationAndCRLWorkFences(t)

	tests := []struct {
		name          string
		reporterClass store.CertificateClass
		claimedClass  store.CertificateClass
		targetClass   store.CertificateClass
		operation     func(context.Context, *RotationManager, func() error) error
	}{
		{
			name:          "agent reporter claiming gateway roots blocks agent transition",
			reporterClass: store.CertificateClassAgent, claimedClass: store.CertificateClassGateway,
			targetClass: store.CertificateClassAgent,
			operation: func(ctx context.Context, manager *RotationManager, action func() error) error {
				return manager.withTrustStateFences(ctx, store.CertificateClassAgent, store.CertificateClassGateway, action)
			},
		},
		{
			name:          "gateway reporter claiming agent roots blocks gateway transition",
			reporterClass: store.CertificateClassGateway, claimedClass: store.CertificateClassAgent,
			targetClass: store.CertificateClassGateway,
			operation: func(ctx context.Context, manager *RotationManager, action func() error) error {
				return manager.withTrustStateFences(ctx, store.CertificateClassGateway, store.CertificateClassAgent, action)
			},
		},
		{
			name:          "same-class leaf confirmation deduplicates its shared fence",
			reporterClass: store.CertificateClassAgent, claimedClass: store.CertificateClassAgent,
			targetClass: store.CertificateClassAgent,
			operation: func(ctx context.Context, manager *RotationManager, action func() error) error {
				return manager.withTrustStateFences(ctx, store.CertificateClassAgent, store.CertificateClassAgent, action)
			},
		},
		{
			name:          "issuer CRL work blocks its class transition",
			reporterClass: store.CertificateClassAgent, claimedClass: store.CertificateClassAgent,
			targetClass: store.CertificateClassAgent,
			operation: func(ctx context.Context, manager *RotationManager, action func() error) error {
				return manager.withCRLIssuerFence(ctx, store.CertificateClassAgent, action)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRotationManagerFixture(t)
			entered := make(chan struct{})
			release := make(chan struct{})
			operationDone := make(chan error, 1)
			go func() {
				operationDone <- test.operation(context.Background(), fixture.manager, func() error {
					close(entered)
					<-release
					return nil
				})
			}()
			<-entered
			successor := fixture.successor(test.targetClass)
			transitionDER := crossSignRotationCA(t, fixture.current(test.targetClass), successor)
			transitionDone := make(chan error, 1)
			transitionStarted := make(chan struct{})
			go func() {
				close(transitionStarted)
				transitionDone <- fixture.manager.BeginTrust(
					context.Background(), test.targetClass, successor.root.Raw,
					transitionDER, successor.signer,
				)
			}()
			<-transitionStarted
			waitForPostgresAdvisoryWaiters(t, fixture.pool, 1)
			close(release)
			if err := <-operationDone; err != nil {
				t.Fatalf("complete shared operation: %v", err)
			}
			if err := <-transitionDone; err != nil {
				t.Fatalf("transition after shared operation commit: %v", err)
			}
		})
	}
}

func exerciseRealConfirmationAndCRLWorkFences(t *testing.T) {
	t.Helper()
	t.Run("real confirmation holds reporter and claimed class fences through commit", func(t *testing.T) {
		fixture := newRotationManagerFixture(t)
		reporter := fixture.seedGatewayConsumer(t, "01J00000000000000000000091")
		fixture.beginTrust(t, store.CertificateClassAgent, fixture.agentSuccessor)
		state := fixture.snapshot(t, store.CertificateClassAgent)
		claim := consumerClaim(state, reporter)
		confirmation := TrustStateConfirmation{
			ReporterCertificateDER: reporter.certificateDER, Claim: claim,
			Signature: signRotationClaim(t, reporter.signer, claim),
		}
		release := installBlockingCommitTrigger(t, fixture.pool, "events", 6006001)
		confirmDone := make(chan error, 1)
		go func() { confirmDone <- fixture.manager.ConfirmTrustState(context.Background(), confirmation) }()
		waitForPostgresAdvisoryWaiters(t, fixture.pool, 1)
		transitionDone := make(chan error, 2)
		go func() { transitionDone <- fixture.manager.Abort(context.Background(), store.CertificateClassAgent) }()
		go func() {
			transitionDone <- fixture.manager.BeginTrust(context.Background(), store.CertificateClassGateway,
				fixture.gatewaySuccessor.root.Raw, crossSignRotationCA(t, fixture.gatewayCurrent, fixture.gatewaySuccessor), fixture.gatewaySuccessor.signer)
		}()
		waitForPostgresAdvisoryWaiters(t, fixture.pool, 3)
		release()
		if err := <-confirmDone; err != nil {
			t.Fatalf("commit real confirmation: %v", err)
		}
		for range 2 {
			if err := <-transitionDone; err != nil {
				t.Fatalf("transition after confirmation commit: %v", err)
			}
		}
		if got := rotationConfirmationEventCount(t, fixture.pool); got != 1 {
			t.Fatalf("durable confirmation events = %d; want exactly one before both transitions", got)
		}
	})

	t.Run("real issuer work holds class fence through CRL state and receipt commit", func(t *testing.T) {
		fixture := newRotationManagerFixture(t)
		reporter := fixture.seedAgent(t, "01J00000000000000000000092", fixture.agentCurrent)
		fixture.revokeLeaf(t, reporter)
		issuer, err := NewCRLIssuer(fixture.eventStore, fixture.authorities, &crlPublisherStub{})
		if err != nil {
			t.Fatalf("create fenced CRL issuer: %v", err)
		}
		issuer.rotationManager = fixture.manager
		issuer.now = fixture.manager.now
		item := store.WorkItem{
			Work:             store.Work{Kind: store.PublishAgentCRLWorkKind, PayloadVersion: 1, Payload: []byte(`{}`)},
			SourceStreamType: "device", SourceStreamID: reporter.id, SourceStreamVersion: 2,
		}
		release := installBlockingCommitTrigger(t, fixture.pool, "crl_state", 6006001)
		workDone := make(chan error, 1)
		go func() { workDone <- issuer.HandleAgentCRLWork(context.Background(), item) }()
		waitForPostgresAdvisoryWaiters(t, fixture.pool, 1)
		transitionDone := make(chan error, 1)
		go func() {
			transitionDone <- fixture.manager.BeginTrust(context.Background(), store.CertificateClassAgent,
				fixture.agentSuccessor.root.Raw, crossSignRotationCA(t, fixture.agentCurrent, fixture.agentSuccessor), fixture.agentSuccessor.signer)
		}()
		waitForPostgresAdvisoryWaiters(t, fixture.pool, 2)
		release()
		if err := <-workDone; err != nil {
			t.Fatalf("commit real issuer work: %v", err)
		}
		if err := <-transitionDone; err != nil {
			t.Fatalf("transition after CRL commit: %v", err)
		}
		fingerprint := sha256Fingerprint(fixture.agentCurrent.root.Raw)
		state, err := fixture.eventStore.LatestCRL(context.Background(), store.CertificateClassAgent, fingerprint)
		if err != nil || state.Sequence == 0 {
			t.Fatalf("fenced issuer state = (%+v,%v); want committed CRL", state, err)
		}
		if sequence, found, err := fixture.eventStore.CRLWorkReceipt(context.Background(), store.CertificateClassAgent, fingerprint, state.Source); err != nil || !found || sequence != state.Sequence {
			t.Fatalf("fenced issuer receipt = (%d,%v,%v); want same transaction sequence %d", sequence, found, err, state.Sequence)
		}
	})
}

func exerciseRealIssuanceRPCFences(t *testing.T) {
	t.Helper()
	for _, renewal := range []bool{false, true} {
		name := "fresh enrollment"
		if renewal {
			name = "renewal"
		}
		t.Run(name+" holds both class fences through event commit", func(t *testing.T) {
			fixture := newEnrollmentHandlerFixture(t, 1)
			key := newEnrollmentSigningKey(t)
			var currentDER []byte
			if renewal {
				key, currentDER, _ = enrollRenewalFixture(t, fixture)
			}
			agentSuccessor := newRotationCA(t, "fenced agent successor", fixture.service.now())
			gatewaySuccessor := newRotationCA(t, "fenced gateway successor", fixture.service.now())
			manager, err := NewRotationManager(RotationManagerConfig{
				EventStore: fixture.eventStore, Authorities: fixture.service.authorities, Distributor: &recordingTrustBundleDistributor{},
				SuccessorSigners: map[store.CertificateClass]crypto.Signer{
					store.CertificateClassAgent: agentSuccessor.signer, store.CertificateClassGateway: gatewaySuccessor.signer,
				},
			})
			if err != nil {
				t.Fatalf("create real-RPC rotation manager: %v", err)
			}
			manager.now = fixture.service.now
			fixture.service.rotationManager = manager
			release := installBlockingCommitTrigger(t, fixture.pool, "events", 6006001)
			workDone := make(chan error, 1)
			go func() {
				if renewal {
					_, callErr := fixture.client.RenewAgent(context.Background(), connect.NewRequest(&powermanagev1.RenewAgentRequest{
						CertificateDer: currentDER, CertificateSigningRequestDer: newEnrollmentCSR(t, key, pkix.Name{}, nil),
						SealingPublicKey: newEnrollmentSealingKey(t),
					}))
					workDone <- callErr
					return
				}
				_, callErr := fixture.client.EnrollAgent(context.Background(), connect.NewRequest(&powermanagev1.EnrollAgentRequest{
					RegistrationToken: fixture.token, CertificateSigningRequestDer: newEnrollmentCSR(t, key, pkix.Name{}, nil),
					SealingPublicKey: newEnrollmentSealingKey(t),
				}))
				workDone <- callErr
			}()
			waitForPostgresAdvisoryWaiters(t, fixture.pool, 1)
			transitionDone := make(chan error, 2)
			go func() {
				transitionDone <- manager.BeginTrust(context.Background(), store.CertificateClassAgent, agentSuccessor.root.Raw,
					crossSignRotationCA(t, rotationCA{root: fixture.agentCA, signer: fixture.service.authorities.agentCA.signer}, agentSuccessor), agentSuccessor.signer)
			}()
			go func() {
				transitionDone <- manager.BeginTrust(context.Background(), store.CertificateClassGateway, gatewaySuccessor.root.Raw,
					crossSignRotationCA(t, rotationCA{root: fixture.gatewayCA, signer: fixture.service.authorities.gatewayCA.signer}, gatewaySuccessor), gatewaySuccessor.signer)
			}()
			// One waiter is the real handler stopped at its event commit. Two more
			// are the class transitions blocked by the handler's shared fences.
			waitForPostgresAdvisoryWaiters(t, fixture.pool, 3)
			release()
			if err := <-workDone; err != nil {
				t.Fatalf("real %s work: %v", name, err)
			}
			for range 2 {
				if err := <-transitionDone; err != nil {
					t.Fatalf("transition after %s commit: %v", name, err)
				}
			}
			assertLifecycleCommittedBeforeRotations(t, fixture.pool)
			assertRotationState(t, mustRotationSnapshot(t, manager, store.CertificateClassAgent), RotationPhaseTrust, 2, 1, fixture.agentCA.Raw, agentSuccessor.root.Raw)
			assertRotationState(t, mustRotationSnapshot(t, manager, store.CertificateClassGateway), RotationPhaseTrust, 2, 1, fixture.gatewayCA.Raw, gatewaySuccessor.root.Raw)
		})
	}

	t.Run("issuance commit failure releases fences without partial identity", func(t *testing.T) {
		fixture := newEnrollmentHandlerFixture(t, 1)
		manager, successor := attachFenceManager(t, fixture, store.CertificateClassAgent)
		if _, err := fixture.pool.Exec(context.Background(), `
			CREATE FUNCTION fail_spec006_event_commit() RETURNS trigger LANGUAGE plpgsql AS $$
			BEGIN RAISE EXCEPTION 'forced issuance commit failure'; END $$;
			CREATE TRIGGER fail_spec006_event_commit BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION fail_spec006_event_commit()`); err != nil {
			t.Fatalf("install issuance commit-failure trigger: %v", err)
		}
		key := newEnrollmentSigningKey(t)
		if _, err := fixture.client.EnrollAgent(context.Background(), connect.NewRequest(&powermanagev1.EnrollAgentRequest{
			RegistrationToken: fixture.token, CertificateSigningRequestDer: newEnrollmentCSR(t, key, pkix.Name{}, nil),
			SealingPublicKey: newEnrollmentSealingKey(t),
		})); err == nil || err.Error() != "internal: enrollment temporarily unavailable" ||
			strings.Contains(err.Error(), "forced issuance commit failure") {
			t.Fatalf("real enrollment commit error = %v; want generic internal error without database details", err)
		}
		if err := manager.BeginTrust(context.Background(), store.CertificateClassAgent, successor.root.Raw,
			crossSignRotationCA(t, rotationCA{root: fixture.agentCA, signer: fixture.service.authorities.agentCA.signer}, successor), successor.signer); err == nil ||
			!strings.Contains(err.Error(), "forced issuance commit failure") {
			t.Fatalf("transition error = %v; want same forced commit failure after shared fence release", err)
		}
		var identities int
		if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM devices`).Scan(&identities); err != nil || identities != 0 {
			t.Fatalf("failed issuance identities = (%d,%v); want no partial row", identities, err)
		}
	})
}

func attachFenceManager(t *testing.T, fixture enrollmentHandlerFixture, class store.CertificateClass) (*RotationManager, rotationCA) {
	t.Helper()
	successor := newRotationCA(t, "fence target successor", fixture.service.now())
	agentSuccessor := newRotationCA(t, "fence agent successor", fixture.service.now())
	gatewaySuccessor := newRotationCA(t, "fence gateway successor", fixture.service.now())
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
		t.Fatalf("create fence manager: %v", err)
	}
	manager.now = fixture.service.now
	fixture.service.rotationManager = manager
	return manager, successor
}

func installBlockingCommitTrigger(t *testing.T, pool *pgxpool.Pool, table string, key int64) func() {
	t.Helper()
	if table != "events" && table != "crl_state" {
		t.Fatalf("unsupported blocking-trigger table %q", table)
	}
	connection, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire blocking lock connection: %v", err)
	}
	if _, err := connection.Exec(context.Background(), `SELECT pg_advisory_lock($1)`, key); err != nil {
		connection.Release()
		t.Fatalf("acquire blocking advisory lock: %v", err)
	}
	statement := `
		CREATE FUNCTION block_spec006_commit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN PERFORM pg_advisory_xact_lock(` + "6006001" + `); RETURN NEW; END $$;
		CREATE TRIGGER block_spec006_commit BEFORE INSERT OR UPDATE ON ` + table + `
		FOR EACH ROW EXECUTE FUNCTION block_spec006_commit()`
	if key != 6006001 {
		t.Fatalf("blocking trigger key %d must use explicit audited fixture key", key)
	}
	if _, err := pool.Exec(context.Background(), statement); err != nil {
		_, _ = connection.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key)
		connection.Release()
		t.Fatalf("install blocking commit trigger: %v", err)
	}
	return func() {
		if _, err := connection.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, key); err != nil {
			t.Errorf("release blocking advisory lock: %v", err)
		}
		connection.Release()
	}
}

func waitForPostgresAdvisoryWaiters(t *testing.T, pool *pgxpool.Pool, minimum int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiters int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND NOT granted`).Scan(&waiters); err != nil {
			t.Fatalf("read Postgres advisory waiters: %v", err)
		}
		if waiters >= minimum {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Postgres advisory waiters = %d; want positive proof of at least %d", waiters, minimum)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertLifecycleCommittedBeforeRotations(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	var lifecycle, firstRotation int64
	if err := pool.QueryRow(context.Background(), `SELECT MAX(global_position) FROM events WHERE stream_type = 'device'`).Scan(&lifecycle); err != nil {
		t.Fatalf("read lifecycle commit position: %v", err)
	}
	if err := pool.QueryRow(context.Background(), `SELECT MIN(global_position) FROM events WHERE stream_type = 'ca-rotation'`).Scan(&firstRotation); err != nil {
		t.Fatalf("read rotation commit position: %v", err)
	}
	if lifecycle == 0 || firstRotation <= lifecycle {
		t.Fatalf("commit positions = lifecycle %d rotation %d; want real handler commit before transitions", lifecycle, firstRotation)
	}
}

func mustRotationSnapshot(t *testing.T, manager *RotationManager, class store.CertificateClass) AuthoritySnapshot {
	t.Helper()
	state, err := manager.Snapshot(context.Background(), class)
	if err != nil {
		t.Fatalf("snapshot %s: %v", class, err)
	}
	return state
}
