package store

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestControlTrustConfirmationLookup_RejectsForbiddenCRLReceipt(t *testing.T) {
	pool := testPostgres(t)
	eventStore, err := NewProduction(pool)
	if err != nil {
		t.Fatalf("create production event store: %v", err)
	}
	confirmation := ControlTrustConfirmation{
		ClaimedClass:     CertificateClassGateway,
		Generation:       2,
		Revision:         1,
		RootFingerprints: [][sha256.Size]byte{sha256.Sum256([]byte("gateway root"))},
	}
	if err := eventStore.RecordControlTrustConfirmation(context.Background(), confirmation); err != nil {
		t.Fatalf("record valid control trust confirmation: %v", err)
	}
	found, err := eventStore.HasControlTrustConfirmation(context.Background(), confirmation)
	if err != nil || !found {
		t.Fatalf("valid control trust confirmation lookup = (%v, %v); want found", found, err)
	}

	tests := []struct {
		name   string
		mutate func(*ControlTrustConfirmation)
	}{
		{name: "missing roots", mutate: func(value *ControlTrustConfirmation) { value.RootFingerprints = nil }},
		{name: "CRL issuer", mutate: func(value *ControlTrustConfirmation) {
			value.CRLIssuerFingerprint = sha256.Sum256([]byte("forbidden issuer"))
		}},
		{name: "CRL sequence", mutate: func(value *ControlTrustConfirmation) { value.CRLSequence = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invalid := confirmation
			test.mutate(&invalid)
			found, err := eventStore.HasControlTrustConfirmation(context.Background(), invalid)
			if err == nil || found || !strings.Contains(err.Error(), "invalid control trust confirmation lookup") {
				t.Fatalf("invalid control trust confirmation lookup = (%v, %v); want exact rejection", found, err)
			}
		})
	}
}
