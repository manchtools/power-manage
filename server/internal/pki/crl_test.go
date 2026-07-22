package pki

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/server/internal/control"
	"github.com/manchtools/power-manage/server/internal/store"
)

func TestCRLIssuer_SignsProjectedRevocationsAndIgnoresStaleWork(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	_, certificateDER, deviceID := enrollRenewalFixture(t, fixture)
	force := connect.NewRequest(&powermanagev1.ForceRenewAgentRequest{CertificateDer: certificateDER})
	force.Header().Set("Authorization", "Bearer operator-proof")
	if _, err := fixture.client.ForceRenewAgent(context.Background(), force); err != nil {
		t.Fatalf("force certificate renewal: %v", err)
	}
	publisher := &crlPublisherStub{}
	issuer, err := NewCRLIssuer(fixture.eventStore, fixture.service.authorities, publisher)
	if err != nil {
		t.Fatalf("create CRL issuer: %v", err)
	}
	issuedAt := time.Now().UTC().Add(time.Minute).Truncate(time.Second)
	issuer.now = func() time.Time { return issuedAt }
	if err := issuer.HandleAgentCRLWork(context.Background(), validAgentCRLWork(deviceID, 2)); err != nil {
		t.Fatalf("handle first CRL work: %v", err)
	}
	assertIssuedAgentCRL(t, fixture, publisher, certificateDER, deviceID, 1, issuedAt, 4)

	if _, err := fixture.client.RevokeAgent(context.Background(), authorizedRevokeRequest(certificateDER)); err != nil {
		t.Fatalf("terminally revoke forced-renewal certificate: %v", err)
	}
	issuer.now = func() time.Time { return issuedAt.Add(time.Second) }
	if err := issuer.HandleAgentCRLWork(context.Background(), validAgentCRLWork(deviceID, 3)); err != nil {
		t.Fatalf("handle second CRL work: %v", err)
	}
	assertIssuedAgentCRL(t, fixture, publisher, certificateDER, deviceID, 2, issuedAt.Add(time.Second), 4)

	if err := issuer.HandleAgentCRLWork(context.Background(), validAgentCRLWork(deviceID, 2)); err != nil {
		t.Fatalf("redeliver older CRL work: %v", err)
	}
	if len(publisher.published) != 2 {
		t.Fatalf("publications after stale redelivery = %d; want unchanged two", len(publisher.published))
	}
	durable, err := fixture.eventStore.LatestCRL(context.Background(), store.CertificateClassAgent)
	if err != nil || durable.Sequence != 2 {
		t.Fatalf("durable CRL after stale redelivery = (%+v, %v); want sequence two", durable, err)
	}
}

func TestCRLIssuer_EnsureCurrentIssuesClassSeparatedEmptyLists(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	publisher := &crlPublisherStub{}
	issuer, err := NewCRLIssuer(fixture.eventStore, fixture.service.authorities, publisher)
	if err != nil {
		t.Fatalf("create CRL issuer: %v", err)
	}
	issuedAt := time.Now().UTC().Truncate(time.Second)
	issuer.now = func() time.Time { return issuedAt }
	for _, class := range []store.CertificateClass{store.CertificateClassAgent, store.CertificateClassGateway} {
		state, err := issuer.EnsureCurrent(context.Background(), class)
		if err != nil {
			t.Fatalf("ensure %s CRL: %v", class, err)
		}
		list, err := parseExactRevocationList(state.DER)
		if err != nil {
			t.Fatalf("parse %s CRL: %v", class, err)
		}
		authority := fixture.service.authorities.agentCA.certificate
		if class == store.CertificateClassGateway {
			authority = fixture.service.authorities.gatewayCA.certificate
		}
		if state.Sequence != 1 || len(list.RevokedCertificateEntries) != 0 || list.CheckSignatureFrom(authority) != nil {
			t.Fatalf("initial %s CRL = %+v / %+v; want signed empty sequence one", class, state, list)
		}
		again, err := issuer.EnsureCurrent(context.Background(), class)
		if err != nil || again.Sequence != 1 || !bytes.Equal(again.DER, state.DER) {
			t.Fatalf("second ensure %s = (%+v, %v); want unchanged sequence one", class, again, err)
		}
		contended, err := issuer.issue(context.Background(), class, store.CRLSource{})
		if err != nil || contended.Sequence != 1 || !bytes.Equal(contended.DER, state.DER) {
			t.Fatalf("stale initial issue %s = (%+v, %v); want unchanged sequence one", class, contended, err)
		}
	}
	if len(publisher.published) != 2 {
		t.Fatalf("initial CRL publications = %d; want one per class", len(publisher.published))
	}
}

func TestNewCRLIssuer_RequiresStoreAuthoritiesAndPublisher(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	var typedNil *crlPublisherStub
	tests := []struct {
		name        string
		eventStore  *store.Store
		authorities *Authorities
		publisher   CRLPublisher
		want        string
	}{
		{name: "nil store", authorities: fixture.service.authorities, publisher: &crlPublisherStub{}, want: "pki: nil CRL event store"},
		{name: "nil authorities", eventStore: fixture.eventStore, publisher: &crlPublisherStub{}, want: "pki: CRL authorities are not wired"},
		{name: "nil publisher", eventStore: fixture.eventStore, authorities: fixture.service.authorities, want: "pki: CRL publisher is not wired"},
		{name: "typed-nil publisher", eventStore: fixture.eventStore, authorities: fixture.service.authorities, publisher: typedNil, want: "pki: CRL publisher is not wired"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			issuer, err := NewCRLIssuer(test.eventStore, test.authorities, test.publisher)
			if issuer != nil || err == nil || err.Error() != test.want {
				t.Fatalf("NewCRLIssuer = (%v, %v); want exact rejection %q", issuer, err, test.want)
			}
		})
	}
}

func TestCRLIssuer_RejectsInvalidWorkWithoutPublishing(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	publisher := &crlPublisherStub{}
	issuer, err := NewCRLIssuer(fixture.eventStore, fixture.service.authorities, publisher)
	if err != nil {
		t.Fatalf("create CRL issuer: %v", err)
	}
	tests := []store.WorkItem{
		{},
		{Work: store.Work{Kind: store.PublishAgentCRLWorkKind, PayloadVersion: 2, Payload: []byte(`{}`)}},
		{Work: store.Work{Kind: store.PublishAgentCRLWorkKind, PayloadVersion: 1, Payload: []byte(`{"class":"gateway"}`)}},
	}
	for _, item := range tests {
		if err := issuer.HandleAgentCRLWork(context.Background(), item); err == nil || err.Error() != "pki: invalid agent CRL work item" {
			t.Fatalf("invalid CRL work error = %v; want exact work rejection", err)
		}
	}
	if len(publisher.published) != 0 {
		t.Fatalf("invalid work published %d CRLs; want zero", len(publisher.published))
	}
	state, err := fixture.eventStore.LatestCRL(context.Background(), store.CertificateClassAgent)
	if err != nil {
		t.Fatalf("read CRL state: %v", err)
	}
	if state.Sequence != 0 {
		t.Fatalf("invalid work advanced CRL sequence to %d", state.Sequence)
	}
}

func TestCRLIssuer_PublishFailureLeavesDurableRetry(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	_, certificateDER, _ := enrollRenewalFixture(t, fixture)
	if _, err := fixture.client.RevokeAgent(context.Background(), authorizedRevokeRequest(certificateDER)); err != nil {
		t.Fatalf("revoke certificate: %v", err)
	}
	publisher := &crlPublisherStub{err: errors.New("gateway stream unavailable")}
	issuer, err := NewCRLIssuer(fixture.eventStore, fixture.service.authorities, publisher)
	if err != nil {
		t.Fatalf("create CRL issuer: %v", err)
	}
	issuer.now = func() time.Time { return time.Now().UTC().Add(time.Minute).Truncate(time.Second) }
	queue, err := store.NewWorkQueue(fixture.pool, issuer.WorkHandlers())
	if err != nil {
		t.Fatalf("create CRL work queue: %v", err)
	}
	processed, err := queue.RunOnce(context.Background())
	if !processed || err == nil || !strings.Contains(err.Error(), "pki: publish agent CRL: gateway stream unavailable") {
		t.Fatalf("first CRL work run = (%v, %v); want exact processed publication failure", processed, err)
	}
	if got := pkiCRLWorkCount(t, fixture); got != 1 {
		t.Fatalf("CRL work after publish failure = %d; want one", got)
	}
	publisher.err = nil
	if _, err := fixture.pool.Exec(
		context.Background(),
		`UPDATE work_items SET next_attempt_at = clock_timestamp() WHERE work_kind = $1`,
		store.PublishAgentCRLWorkKind,
	); err != nil {
		t.Fatalf("make CRL retry due: %v", err)
	}
	processed, err = queue.RunOnce(context.Background())
	if !processed || err != nil {
		t.Fatalf("CRL retry = (%v, %v); want success", processed, err)
	}
	if got := pkiCRLWorkCount(t, fixture); got != 0 {
		t.Fatalf("CRL work after retry = %d; want zero", got)
	}
	state, err := fixture.eventStore.LatestCRL(context.Background(), store.CertificateClassAgent)
	if err != nil {
		t.Fatalf("read retried CRL state: %v", err)
	}
	if state.Sequence != 1 {
		t.Fatalf("retried CRL sequence = %d; want idempotent sequence one", state.Sequence)
	}
	if len(publisher.published) != 2 || publisher.published[0].Sequence != 1 ||
		publisher.published[1].Sequence != 1 || !bytes.Equal(publisher.published[0].DER, publisher.published[1].DER) {
		t.Fatalf("retried publications = %+v; want exact sequence-one redelivery", publisher.published)
	}
}

func TestRevocationHandlers_PushCRLToConnectedSubscriber(t *testing.T) {
	fixture := newEnrollmentHandlerFixture(t, 1)
	_, certificateDER, _ := enrollRenewalFixture(t, fixture)
	distributor, err := control.NewCRLDistributor(fixture.eventStore)
	if err != nil {
		t.Fatalf("create CRL distributor: %v", err)
	}
	issuer, err := NewCRLIssuer(fixture.eventStore, fixture.service.authorities, distributor)
	if err != nil {
		t.Fatalf("create CRL issuer: %v", err)
	}
	issuer.now = func() time.Time { return time.Now().UTC().Add(time.Minute).Truncate(time.Second) }
	if _, err := issuer.EnsureCurrent(context.Background(), store.CertificateClassAgent); err != nil {
		t.Fatalf("ensure initial agent CRL: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates, err := distributor.Subscribe(ctx, store.CertificateClassAgent)
	if err != nil {
		t.Fatalf("subscribe to agent CRLs: %v", err)
	}
	awaitAgentCRLSequence(t, updates, 1)
	queue, err := store.NewWorkQueue(fixture.pool, issuer.WorkHandlers())
	if err != nil {
		t.Fatalf("create CRL work queue: %v", err)
	}

	force := connect.NewRequest(&powermanagev1.ForceRenewAgentRequest{CertificateDer: bytes.Clone(certificateDER)})
	force.Header().Set("Authorization", "Bearer operator-proof")
	if _, err := fixture.client.ForceRenewAgent(context.Background(), force); err != nil {
		t.Fatalf("force agent renewal: %v", err)
	}
	if processed, err := queue.RunOnce(context.Background()); !processed || err != nil {
		t.Fatalf("publish force-renewal CRL = (%v, %v); want success", processed, err)
	}
	awaitAgentCRLSequence(t, updates, 2)

	if _, err := fixture.client.RevokeAgent(context.Background(), authorizedRevokeRequest(certificateDER)); err != nil {
		t.Fatalf("terminally revoke agent: %v", err)
	}
	if processed, err := queue.RunOnce(context.Background()); !processed || err != nil {
		t.Fatalf("publish terminal-revocation CRL = (%v, %v); want success", processed, err)
	}
	awaitAgentCRLSequence(t, updates, 3)
}

type crlPublisherStub struct {
	published []store.SignedCRL
	err       error
}

func (p *crlPublisherStub) Publish(_ context.Context, state store.SignedCRL) error {
	if p == nil {
		return errors.New("nil CRL publisher")
	}
	p.published = append(p.published, state)
	return p.err
}

func validAgentCRLWork(deviceID string, version int64) store.WorkItem {
	return store.WorkItem{
		Work: store.Work{
			Kind: store.PublishAgentCRLWorkKind, PayloadVersion: 1, Payload: []byte(`{}`),
		},
		SourceStreamType: "device", SourceStreamID: deviceID, SourceStreamVersion: version,
	}
}

func assertIssuedAgentCRL(
	t *testing.T,
	fixture enrollmentHandlerFixture,
	publisher *crlPublisherStub,
	certificateDER []byte,
	deviceID string,
	sequence int64,
	issuedAt time.Time,
	reasonCode int,
) {
	t.Helper()
	if len(publisher.published) != int(sequence) {
		t.Fatalf("published CRL count = %d; want %d", len(publisher.published), sequence)
	}
	state := publisher.published[len(publisher.published)-1]
	list, err := parseExactRevocationList(state.DER)
	if err != nil {
		t.Fatalf("parse issued CRL: %v", err)
	}
	if err := list.CheckSignatureFrom(fixture.agentCA); err != nil {
		t.Fatalf("verify issued CRL: %v", err)
	}
	certificate := parseEnrollmentCertificate(t, certificateDER)
	wantSource := store.CRLSource{
		StreamType: "device", StreamID: deviceID, StreamVersion: sequence + 1,
	}
	if state.Class != store.CertificateClassAgent || state.Sequence != sequence || state.Source != wantSource || !state.IssuedAt.Equal(issuedAt) ||
		list.Number.Cmp(big.NewInt(sequence)) != 0 || !list.ThisUpdate.Equal(issuedAt) ||
		len(list.RevokedCertificateEntries) != 1 ||
		list.RevokedCertificateEntries[0].SerialNumber.Cmp(certificate.SerialNumber) != 0 ||
		list.RevokedCertificateEntries[0].ReasonCode != reasonCode {
		t.Fatalf("issued CRL state/list = %+v / %+v; want sequence %d and exact revoked serial", state, list, sequence)
	}
	durable, err := fixture.eventStore.LatestCRL(context.Background(), store.CertificateClassAgent)
	if err != nil {
		t.Fatalf("read durable CRL: %v", err)
	}
	if durable.Sequence != sequence || durable.Source != wantSource || !bytes.Equal(durable.DER, state.DER) || !durable.IssuedAt.Equal(issuedAt) {
		t.Fatalf("durable CRL = %+v; want published state %+v", durable, state)
	}
}

func pkiCRLWorkCount(t *testing.T, fixture enrollmentHandlerFixture) int {
	t.Helper()
	var count int
	if err := fixture.pool.QueryRow(context.Background(), `SELECT count(*) FROM work_items WHERE work_kind = $1`, store.PublishAgentCRLWorkKind).Scan(&count); err != nil {
		t.Fatalf("count CRL work: %v", err)
	}
	return count
}

func awaitAgentCRLSequence(t *testing.T, updates <-chan store.SignedCRL, want int64) {
	t.Helper()
	select {
	case update := <-updates:
		if update.Class != store.CertificateClassAgent || update.Sequence != want {
			t.Fatalf("agent CRL update = %+v; want sequence %d", update, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("agent CRL sequence %d was not pushed", want)
	}
}
