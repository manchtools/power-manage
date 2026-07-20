package identity_test

// SPEC-003 M4 certificate-profile constant tests ([WIRE-18], choice 6). The
// contract fixes only the SPIFFE identity PROFILE — the trust domain and the
// three class URIs (URI SAN = class, CN = instance ULID, DNS SAN = server
// name). Parsing and enforcement are SPEC-006/007; here we pin the constants
// and, crucially, that each class URI is DERIVED from the trust domain by the
// [WIRE-18] formula, not an independent literal that could drift from it.

import (
	"testing"

	"github.com/manchtools/power-manage/contract/identity"
)

// TestSPIFFETrustDomain pins the trust domain to "power-manage" — the sole
// authority namespace every class URI is built under. ([WIRE-18], choice 6)
func TestSPIFFETrustDomain(t *testing.T) {
	if got, want := identity.SPIFFETrustDomain, "power-manage"; got != want {
		t.Errorf("identity.SPIFFETrustDomain = %q, want %q ([WIRE-18])", got, want)
	}
}

// TestClassSPIFFEURIs pins each class URI to its literal AND proves it equals
// the trust-domain-prefixed formula "spiffe://<trust-domain>/<class>". Binding
// both ways means a change to the trust domain that forgets a class URI, or a
// class URI hand-edited off the formula, is loud. ([WIRE-18], choice 6)
func TestClassSPIFFEURIs(t *testing.T) {
	cases := []struct {
		class string
		got   string
		want  string
	}{
		{"agent", identity.AgentSPIFFEURI, "spiffe://power-manage/agent"},
		{"gateway", identity.GatewaySPIFFEURI, "spiffe://power-manage/gateway"},
		{"control", identity.ControlSPIFFEURI, "spiffe://power-manage/control"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s class URI = %q, want %q ([WIRE-18])", c.class, c.got, c.want)
		}
		// Formula, not just literal: the URI must be the trust-domain prefix +
		// class, so the class constants can never drift from SPIFFETrustDomain.
		formula := "spiffe://" + identity.SPIFFETrustDomain + "/" + c.class
		if c.got != formula {
			t.Errorf("%s class URI = %q, want the derived %q — class URIs are built from SPIFFETrustDomain ([WIRE-18])", c.class, c.got, formula)
		}
	}
}
