package enroll

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"
)

const renewalRetryDelay = time.Hour

// Renewer performs one context-bounded credential renewal.
type Renewer interface {
	Renew(context.Context) error
}

// CredentialLoader returns the currently published credential bundle.
type CredentialLoader interface {
	Load(context.Context) (CredentialBundle, error)
}

// RenewalLoop serially schedules agent renewal and reports every retry cause.
type RenewalLoop struct {
	mu          sync.Mutex
	running     bool
	renewer     Renewer
	credentials CredentialLoader
	report      func(error)
	now         func() time.Time
	wait        func(context.Context, time.Duration) error
}

// NewRenewalLoop validates the renewal, custody, and observability wiring.
func NewRenewalLoop(renewer Renewer, credentials CredentialLoader, report func(error)) (*RenewalLoop, error) {
	if isNilEnrollmentDependency(renewer) {
		return nil, errors.New("enroll: nil renewal client")
	}
	if isNilEnrollmentDependency(credentials) {
		return nil, errors.New("enroll: nil credential loader")
	}
	if report == nil {
		return nil, errors.New("enroll: nil renewal failure reporter")
	}
	return &RenewalLoop{
		renewer: renewer, credentials: credentials, report: report,
		now: time.Now, wait: waitForRenewal,
	}, nil
}

// Run renews at 80% of certificate lifetime, retries failures hourly, and
// remains single-flight until its context is canceled.
func (l *RenewalLoop) Run(ctx context.Context) error {
	if l == nil || isNilEnrollmentDependency(l.renewer) || isNilEnrollmentDependency(l.credentials) ||
		l.report == nil || l.now == nil || l.wait == nil {
		return errors.New("enroll: renewal loop is not wired")
	}
	if ctx == nil {
		return errors.New("enroll: nil renewal-loop context")
	}
	l.mu.Lock()
	if l.running {
		l.mu.Unlock()
		return errors.New("enroll: renewal loop is already running")
	}
	l.running = true
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		l.running = false
		l.mu.Unlock()
	}()
	certificate, err := l.loadCertificate(ctx)
	if err != nil {
		return err
	}
	for {
		if err := l.wait(ctx, renewalDelay(certificate, l.now())); err != nil {
			return err
		}
		for {
			if err := l.renewer.Renew(ctx); err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return ctxErr
				}
				l.report(fmt.Errorf("enroll: agent certificate renewal failed: %w", err))
				if err := l.wait(ctx, renewalRetryDelay); err != nil {
					return err
				}
				continue
			}
			certificate, err = l.loadCertificate(ctx)
			if err != nil {
				return err
			}
			break
		}
	}
}

func (l *RenewalLoop) loadCertificate(ctx context.Context) (*x509.Certificate, error) {
	bundle, err := l.credentials.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("enroll: load credentials for renewal schedule: %w", err)
	}
	certificate, err := parseExactCertificate(bundle.CertificateDER)
	if err != nil {
		return nil, fmt.Errorf("enroll: parse certificate for renewal schedule: %w", err)
	}
	if !certificate.NotAfter.After(certificate.NotBefore) {
		return nil, errors.New("enroll: certificate has an invalid renewal lifetime")
	}
	return certificate, nil
}

func renewalDelay(certificate *x509.Certificate, now time.Time) time.Duration {
	if certificate == nil || !certificate.NotAfter.After(certificate.NotBefore) {
		return 0
	}
	lifetime := certificate.NotAfter.Sub(certificate.NotBefore)
	eightyPercent := lifetime/5*4 + lifetime%5*4/5
	renewAt := certificate.NotBefore.Add(eightyPercent)
	if !renewAt.After(now) {
		return 0
	}
	return renewAt.Sub(now)
}

func waitForRenewal(ctx context.Context, delay time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
