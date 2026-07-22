package pki

import (
	"encoding/json"
	"testing"
)

type durableRenewalEvent struct {
	CertificateDER           []byte `json:"certificate_der"`
	SealingPublicKey         []byte `json:"sealing_public_key"`
	SupersededCertificateDER []byte `json:"superseded_certificate_der"`
}

func decodeDurableRenewalEvent(t *testing.T, payload []byte) durableRenewalEvent {
	t.Helper()
	var event durableRenewalEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatalf("decode renewal event: %v", err)
	}
	return event
}
