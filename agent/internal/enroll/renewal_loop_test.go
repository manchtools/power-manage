package enroll

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"
)

func TestRenewalDelay_UsesExactEightyPercentAndRenewsOverdueImmediately(t *testing.T) {
	notBefore := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(100 * time.Hour)
	certificate := &x509.Certificate{NotBefore: notBefore, NotAfter: notAfter}
	if got := renewalDelay(certificate, notBefore.Add(25*time.Hour)); got != 55*time.Hour {
		t.Fatalf("renewal delay = %v; want exact 80%% instant in 55h", got)
	}
	if got := renewalDelay(certificate, notBefore.Add(80*time.Hour)); got != 0 {
		t.Fatalf("due renewal delay = %v; want immediate", got)
	}
	if got := renewalDelay(certificate, notAfter.Add(time.Hour)); got != 0 {
		t.Fatalf("expired renewal delay = %v; want immediate", got)
	}
}

func TestRenewalLoop_RetriesHourlyThenReschedulesFromReplacement(t *testing.T) {
	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	current := renewalLoopBundleFixture(t, start, start.Add(100*time.Hour), 1)
	replacementStart := start.Add(81 * time.Hour)
	replacement := renewalLoopBundleFixture(t, replacementStart, replacementStart.Add(100*time.Hour), 2)
	loader := &sequenceCredentialLoader{bundles: []CredentialBundle{current, replacement}}
	retryCause := errors.New("control unavailable")
	renewer := &sequenceRenewer{errors: []error{retryCause, nil}}
	var reports []error
	loop, err := NewRenewalLoop(renewer, loader, func(err error) { reports = append(reports, err) })
	if err != nil {
		t.Fatalf("NewRenewalLoop: %v", err)
	}
	now := start
	loop.now = func() time.Time { return now }
	ctx, cancel := context.WithCancel(context.Background())
	var delays []time.Duration
	loop.wait = func(waitCtx context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		now = now.Add(delay)
		if len(delays) == 3 {
			cancel()
			return waitCtx.Err()
		}
		return nil
	}
	if err := loop.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Run error = %v; want cancellation", err)
	}
	want := []time.Duration{80 * time.Hour, time.Hour, 80 * time.Hour}
	if len(delays) != len(want) {
		t.Fatalf("renewal delays = %v; want %v", delays, want)
	}
	for index := range want {
		if delays[index] != want[index] {
			t.Fatalf("renewal delays = %v; want %v", delays, want)
		}
	}
	if renewer.calls != 2 || renewer.maxInFlight != 1 || loader.calls != 2 {
		t.Fatalf("loop effects = %d renewals, max %d in flight, %d loads; want 2, 1, 2", renewer.calls, renewer.maxInFlight, loader.calls)
	}
	if len(reports) != 1 || !errors.Is(reports[0], retryCause) {
		t.Fatalf("renewal failure reports = %v; want one observable retry cause", reports)
	}
}

func TestRenewalLoop_CancellationInterruptsInFlightRenewal(t *testing.T) {
	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	loader := &sequenceCredentialLoader{bundles: []CredentialBundle{renewalLoopBundleFixture(t, start, start.Add(time.Hour), 3)}}
	renewer := &cancelAwareRenewer{entered: make(chan struct{})}
	loop, err := NewRenewalLoop(renewer, loader, func(error) {})
	if err != nil {
		t.Fatalf("NewRenewalLoop: %v", err)
	}
	loop.now = func() time.Time { return start.Add(time.Hour) }
	loop.wait = func(context.Context, time.Duration) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- loop.Run(ctx) }()
	awaitRenewalEntered(t, renewer.entered)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run error = %v; want cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("renewal loop did not propagate cancellation to in-flight renewal")
	}
}

func TestRenewalLoop_RejectsConcurrentRunExactly(t *testing.T) {
	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	loader := &sequenceCredentialLoader{bundles: []CredentialBundle{renewalLoopBundleFixture(t, start, start.Add(time.Hour), 4)}}
	renewer := &cancelAwareRenewer{entered: make(chan struct{})}
	loop, err := NewRenewalLoop(renewer, loader, func(error) {})
	if err != nil {
		t.Fatalf("NewRenewalLoop: %v", err)
	}
	loop.now = func() time.Time { return start.Add(time.Hour) }
	loop.wait = func(context.Context, time.Duration) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan error, 1)
	go func() { firstDone <- loop.Run(ctx) }()
	awaitRenewalEntered(t, renewer.entered)

	if err := loop.Run(context.Background()); err == nil || err.Error() != "enroll: renewal loop is already running" {
		t.Fatalf("concurrent Run error = %v; want exact already-running rejection", err)
	}
	cancel()
	select {
	case err := <-firstDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first Run error = %v; want cancellation", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first renewal loop did not stop after cancellation")
	}
}

func awaitRenewalEntered(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("renewal did not begin")
	}
}

type sequenceCredentialLoader struct {
	bundles []CredentialBundle
	calls   int
}

func (l *sequenceCredentialLoader) Load(context.Context) (CredentialBundle, error) {
	if l.calls >= len(l.bundles) {
		return CredentialBundle{}, errors.New("unexpected credential load")
	}
	bundle := l.bundles[l.calls]
	l.calls++
	return bundle, nil
}

type sequenceRenewer struct {
	mu          sync.Mutex
	errors      []error
	calls       int
	inFlight    int
	maxInFlight int
}

func (r *sequenceRenewer) Renew(context.Context) error {
	r.mu.Lock()
	r.inFlight++
	if r.inFlight > r.maxInFlight {
		r.maxInFlight = r.inFlight
	}
	index := r.calls
	r.calls++
	r.mu.Unlock()

	r.mu.Lock()
	r.inFlight--
	r.mu.Unlock()
	if index >= len(r.errors) {
		return errors.New("unexpected renewal")
	}
	return r.errors[index]
}

type cancelAwareRenewer struct{ entered chan struct{} }

func (r *cancelAwareRenewer) Renew(ctx context.Context) error {
	close(r.entered)
	<-ctx.Done()
	return ctx.Err()
}

func renewalLoopBundleFixture(t *testing.T, notBefore, notAfter time.Time, serial int64) CredentialBundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate renewal loop certificate key: %v", err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create renewal loop certificate: %v", err)
	}
	return CredentialBundle{CertificateDER: der}
}
