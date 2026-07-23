package auth

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/manchtools/power-manage/server/internal/store"
)

func TestPATService_RejectsMalformedBeforeStoreLookup(t *testing.T) {
	now := time.Date(2026, time.July, 23, 12, 0, 0, 0, time.UTC)
	service, err := NewPATService(&store.Store{}, bytes.NewReader(nil), func() time.Time {
		return now
	})
	if err != nil {
		t.Fatalf("create PAT service with deliberately unwired store: %v", err)
	}

	startedAt := time.Now()
	principal, err := service.Authenticate(t.Context(), "not-a-pat")
	if !errors.Is(err, ErrPATRejected) ||
		principal.Subject != "" ||
		principal.TokenID != "" ||
		principal.AuditIdentity != "" ||
		len(principal.Scopes) != 0 {
		t.Fatalf("malformed PAT result = (%+v, %v); want empty principal and %v",
			principal, err, ErrPATRejected)
	}
	if elapsed := time.Since(startedAt); elapsed < minimumPATRejectionDuration {
		t.Fatalf("malformed PAT rejection took %s; want at least %s",
			elapsed, minimumPATRejectionDuration)
	}

	validShape := "pm_pat_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := service.Authenticate(t.Context(), validShape); !errors.Is(err, ErrPATUnavailable) {
		t.Fatalf("valid-shape PAT with unwired store error = %v; want %v", err, ErrPATUnavailable)
	}
}
