package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitRefreshRevocationBackoff_IsBoundedByDelayAndContext(t *testing.T) {
	started := time.Now()
	if err := waitRefreshRevocationBackoff(t.Context(), 2*time.Millisecond); err != nil {
		t.Fatalf("wait refresh revocation backoff: %v", err)
	}
	if elapsed := time.Since(started); elapsed < 2*time.Millisecond {
		t.Fatalf("refresh revocation backoff elapsed = %s; want at least 2ms", elapsed)
	} else if elapsed > 250*time.Millisecond {
		t.Fatalf("refresh revocation backoff elapsed = %s; want no more than 250ms", elapsed)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	started = time.Now()
	if err := waitRefreshRevocationBackoff(ctx, 250*time.Millisecond); !errors.Is(err, ErrRefreshUnavailable) {
		t.Fatalf("cancelled refresh revocation backoff error = %v; want %v", err, ErrRefreshUnavailable)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("cancelled refresh revocation backoff elapsed = %s; want no more than 100ms", elapsed)
	}
}
