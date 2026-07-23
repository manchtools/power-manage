package control

import (
	"context"
	"crypto/sha256"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/manchtools/power-manage/server/internal/store"
	"github.com/manchtools/power-manage/server/internal/testpostgres"
)

var crlRotationPostgres testpostgres.Harness

func TestMain(m *testing.M) {
	os.Exit(crlRotationPostgres.Run(m))
}

func TestCRLDistributor_OverlapSeedsAndPreservesBothIssuers(t *testing.T) {
	issuedAt := time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)
	oldCA, oldSigner := crlDistributorCA(t)
	newCA, newSigner := crlDistributorCA(t)
	oldFingerprint := sha256.Sum256(oldCA.Raw)
	newFingerprint := sha256.Sum256(newCA.Raw)
	oldState := store.SignedCRL{
		Class: store.CertificateClassAgent, IssuerFingerprint: oldFingerprint, Sequence: 1,
		DER: signedCRLFixture(t, oldCA, oldSigner, 1, issuedAt), IssuedAt: issuedAt,
	}
	newState := store.SignedCRL{
		Class: store.CertificateClassAgent, IssuerFingerprint: newFingerprint, Sequence: 1,
		DER: signedCRLFixture(t, newCA, newSigner, 1, issuedAt), IssuedAt: issuedAt,
	}
	pool := crlRotationPostgres.Database(t, store.Migrate)
	eventStore, err := store.NewProduction(pool)
	if err != nil {
		t.Fatalf("create real CRL state store: %v", err)
	}
	persistDistributorCRL(t, eventStore, oldState, 0)
	persistDistributorCRL(t, eventStore, newState, 0)
	distributor, err := NewCRLDistributor(eventStore)
	if err != nil {
		t.Fatalf("create issuer-scoped distributor: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates, err := distributor.Subscribe(ctx, store.CertificateClassAgent)
	if err != nil {
		t.Fatalf("subscribe during overlap: %v", err)
	}
	seeded := []store.SignedCRL{awaitIssuerCRL(t, updates), awaitIssuerCRL(t, updates)}
	slices.SortFunc(seeded, func(first, second store.SignedCRL) int {
		return slices.Compare(first.IssuerFingerprint[:], second.IssuerFingerprint[:])
	})
	want := []store.SignedCRL{oldState, newState}
	slices.SortFunc(want, func(first, second store.SignedCRL) int {
		return slices.Compare(first.IssuerFingerprint[:], second.IssuerFingerprint[:])
	})
	for index := range want {
		if !sameSignedCRL(seeded[index], want[index]) {
			t.Fatalf("overlap seed[%d] = %+v; want exact durable %+v", index, seeded[index], want[index])
		}
	}

	oldNext := store.SignedCRL{
		Class: store.CertificateClassAgent, IssuerFingerprint: oldFingerprint, Sequence: 2,
		DER: signedCRLFixture(t, oldCA, oldSigner, 2, issuedAt.Add(time.Second)), IssuedAt: issuedAt.Add(time.Second),
	}
	persistDistributorCRL(t, eventStore, oldNext, 1)
	if err := distributor.Publish(context.Background(), oldNext); err != nil {
		t.Fatalf("publish old-issuer sequence two: %v", err)
	}
	if update := awaitIssuerCRL(t, updates); update.IssuerFingerprint != oldFingerprint || update.Sequence != 2 {
		t.Fatalf("old-issuer update = %+v; want exact issuer and sequence two", update)
	}

	// A new subscriber must still receive both issuer states. Advancing one
	// issuer cannot evict the other or collide on its identical sequence.
	secondCtx, secondCancel := context.WithCancel(context.Background())
	defer secondCancel()
	secondUpdates, err := distributor.Subscribe(secondCtx, store.CertificateClassAgent)
	if err != nil {
		t.Fatalf("subscribe after one issuer advances: %v", err)
	}
	got := map[[sha256.Size]byte]int64{}
	for range 2 {
		state := awaitIssuerCRL(t, secondUpdates)
		got[state.IssuerFingerprint] = state.Sequence
	}
	if got[oldFingerprint] != 2 || got[newFingerprint] != 1 || len(got) != 2 {
		t.Fatalf("preserved overlap state = %v; want old=2 and successor=1", got)
	}

	newNext := store.SignedCRL{
		Class: store.CertificateClassAgent, IssuerFingerprint: newFingerprint, Sequence: 2,
		DER: signedCRLFixture(t, newCA, newSigner, 2, issuedAt.Add(2*time.Second)), IssuedAt: issuedAt.Add(2 * time.Second),
	}
	slowCtx, slowCancel := context.WithCancel(context.Background())
	defer slowCancel()
	slow, err := distributor.Subscribe(slowCtx, store.CertificateClassAgent)
	if err != nil {
		t.Fatalf("subscribe slow overlap consumer: %v", err)
	}
	_ = awaitIssuerCRL(t, slow)
	_ = awaitIssuerCRL(t, slow)
	persistDistributorCRL(t, eventStore, newNext, 1)
	if err := distributor.Publish(context.Background(), newNext); err != nil {
		t.Fatalf("publish successor sequence two: %v", err)
	}
	// Do not read between issuer publications: one slow subscriber must retain
	// the newest state for each issuer instead of one class-wide slot.
	oldThird := oldNext
	oldThird.Sequence = 3
	oldThird.IssuedAt = issuedAt.Add(3 * time.Second)
	oldThird.DER = signedCRLFixture(t, oldCA, oldSigner, 3, oldThird.IssuedAt)
	persistDistributorCRL(t, eventStore, oldThird, 2)
	if err := distributor.Publish(context.Background(), oldThird); err != nil {
		t.Fatalf("publish old sequence three: %v", err)
	}
	thirdCA, thirdSigner := crlDistributorCA(t)
	thirdFingerprint := sha256.Sum256(thirdCA.Raw)
	thirdState := store.SignedCRL{
		Class: store.CertificateClassAgent, IssuerFingerprint: thirdFingerprint, Sequence: 1,
		DER: signedCRLFixture(t, thirdCA, thirdSigner, 1, issuedAt.Add(4*time.Second)), IssuedAt: issuedAt.Add(4 * time.Second),
	}
	persistDistributorCRL(t, eventStore, thirdState, 0)
	published := make(chan error, 1)
	go func() { published <- distributor.Publish(context.Background(), thirdState) }()
	select {
	case err := <-published:
		if err != nil {
			t.Fatalf("publish third issuer to slow subscriber: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("third issuer publication blocked behind a slow subscriber")
	}
	slowUpdates := []store.SignedCRL{awaitIssuerCRL(t, slow), awaitIssuerCRL(t, slow), awaitIssuerCRL(t, slow)}
	if !containsIssuerSequence(slowUpdates, newFingerprint, 2) || !containsIssuerSequence(slowUpdates, oldFingerprint, 3) {
		t.Fatalf("slow subscriber updates = %+v; want each issuer's latest state", slowUpdates)
	}
	if !containsIssuerSequence(slowUpdates, thirdFingerprint, 1) {
		t.Fatalf("slow subscriber updates = %+v; want dynamically added third issuer", slowUpdates)
	}

	for _, test := range []struct {
		name    string
		wantErr string
		state   store.SignedCRL
	}{
		{name: "positive stale", wantErr: "stale", state: oldNext},
		{name: "same sequence fork", wantErr: "fork", state: store.SignedCRL{Class: store.CertificateClassAgent, IssuerFingerprint: newFingerprint, Sequence: 2, DER: signedCRLFixture(t, newCA, newSigner, 2, issuedAt.Add(4*time.Second)), IssuedAt: issuedAt.Add(4 * time.Second)}},
		{name: "cross class substitution", wantErr: "class", state: store.SignedCRL{Class: store.CertificateClassGateway, IssuerFingerprint: newFingerprint, Sequence: 2, DER: newNext.DER, IssuedAt: newNext.IssuedAt}},
		{name: "cross issuer substitution", wantErr: "issuer", state: store.SignedCRL{Class: store.CertificateClassAgent, IssuerFingerprint: oldFingerprint, Sequence: 4, DER: newNext.DER, IssuedAt: newNext.IssuedAt}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := distributor.Publish(context.Background(), test.state); err == nil ||
				!strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.wantErr)) {
				t.Fatalf("Publish error = %v; want %q rejection", err, test.wantErr)
			}
		})
	}
	if err := distributor.Publish(context.Background(), oldThird); err != nil {
		t.Fatalf("exact durable replay should be idempotent: %v", err)
	}
}

func persistDistributorCRL(t *testing.T, eventStore *store.Store, state store.SignedCRL, expected int64) {
	t.Helper()
	stored, err := eventStore.CompareAndSwapCRL(
		context.Background(), state.Class, state.IssuerFingerprint, expected,
		state.DER, state.IssuedAt, state.Source,
	)
	if err != nil || !stored {
		t.Fatalf("persist CRL %s/%x/%d = (%v,%v)", state.Class, state.IssuerFingerprint, state.Sequence, stored, err)
	}
}

func containsIssuerSequence(states []store.SignedCRL, issuer [sha256.Size]byte, sequence int64) bool {
	return slices.ContainsFunc(states, func(state store.SignedCRL) bool {
		return state.IssuerFingerprint == issuer && state.Sequence == sequence
	})
}

func awaitIssuerCRL(t *testing.T, updates <-chan store.SignedCRL) store.SignedCRL {
	t.Helper()
	select {
	case state := <-updates:
		return state
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for issuer-scoped CRL")
		return store.SignedCRL{}
	}
}
