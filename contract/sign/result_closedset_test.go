package sign_test

// SPEC-003 M5 closes the result-type set ([WIRE-20a], operator commit e9b8c29,
// resolving issue #18): the §3.6 result `<type>` token set is CLOSED to exactly
// {execution, compliance, inventory, alert, osquery, logquery}. This arms the
// choice-3 ceiling recorded in result_test.go's TestResultDomain_GrammarViolations
// — the grammar was the WHOLE gate at M4; at M5 membership is an additional gate.
//
// A grammar-VALID but non-member token (e.g. "diagnostics") must now fail
// closed at every seam: ResultDomain, ResultPreimage (the framing chokepoint),
// SignResult (mint), and VerifyResult. Grammar violations still reject — the
// existing M4 grammar tests stay valid. Escrowed device secrets (LPS, LUKS,
// USER temp passwords) mint NO result type ([WIRE-20a]); the sealed blob rides
// the `execution` result, so no lps/luks result token is tested for here.
//
// Same sign_test package as sign_test.go / result_test.go: reuses
// goldenResultEnvelope, newECDSAKey, goldenTarget, and assertRejected.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/manchtools/power-manage/contract/sign"
)

// resultTypeMembers is the closed [WIRE-20a] set. It is written out here (not
// derived) so the closed set is pinned against an independent literal — the
// mirror of how TestGuard_SignatureDomains pins it from the constants.
var resultTypeMembers = []string{
	"execution", "compliance", "inventory", "alert", "osquery", "logquery",
}

// resultTypeNonMembers are grammar-valid [a-z0-9-]+ tokens that are NOT in the
// closed set — each must fail closed, distinguishing membership from grammar.
var resultTypeNonMembers = []string{
	"diagnostics",  // plausible but unregistered
	"backup",       // ditto
	"log-query",    // hyphen variant is NOT the "logquery" member
	"execution-v2", // a versioned look-alike of a member
	"healthcheck",  // unregistered
	"lps",          // escrow mints NO result type ([WIRE-20a])
	"luks",         // ditto
}

// TestResultDomain_ClosedSet pins [WIRE-20a] at the ResultDomain seam, both
// directions: every member maps to "power-manage:result:"+type+":v1", and every
// grammar-valid non-member is a structured reject (empty string on error).
func TestResultDomain_ClosedSet(t *testing.T) {
	for _, m := range resultTypeMembers {
		got, err := sign.ResultDomain(m)
		if err != nil {
			t.Errorf("ResultDomain(%q) errored for a closed-set member: %v ([WIRE-20a])", m, err)
			continue
		}
		if want := "power-manage:result:" + m + ":v1"; got != want {
			t.Errorf("ResultDomain(%q) = %q, want %q ([WIRE-20a] formula)", m, got, want)
		}
	}
	for _, nm := range resultTypeNonMembers {
		got, err := sign.ResultDomain(nm)
		if err == nil {
			t.Errorf("ResultDomain(%q) returned no error — a grammar-valid token outside the closed [WIRE-20a] set is a structured reject; a new result type is a spec change, never an ad-hoc token", nm)
		}
		if got != "" {
			t.Errorf("ResultDomain(%q) = %q, want empty string on rejection (fail-closed)", nm, got)
		}
	}
}

// TestResultPreimage_RejectsNonMemberType: the framing chokepoint refuses a
// non-member result_type, so neither SignResult nor VerifyResult (both call
// ResultPreimage first) can ever cover an unregistered type ([WIRE-20a]).
func TestResultPreimage_RejectsNonMemberType(t *testing.T) {
	for _, nm := range resultTypeNonMembers {
		env := goldenResultEnvelope()
		env.ResultType = nm
		got, err := sign.ResultPreimage(env)
		if err == nil {
			t.Errorf("ResultPreimage accepted non-member result_type %q — an unregistered type is never framed ([WIRE-20a])", nm)
		}
		if got != nil {
			t.Errorf("ResultPreimage returned bytes for non-member result_type %q, want nil on error", nm)
		}
	}
}

// TestSignResult_RejectsNonMemberType: the signing seam inherits the chokepoint
// — a report of an unregistered type cannot be signed into existence
// ([WIRE-20a] fail-closed at mint).
func TestSignResult_RejectsNonMemberType(t *testing.T) {
	priv := newECDSAKey(t)
	env := goldenResultEnvelope()
	env.ResultType = "diagnostics" // grammar-valid, not in the closed set
	if err := sign.SignResult(priv, env); err == nil {
		t.Fatalf("SignResult signed a report with non-member result_type %q — the mint seam must fail closed ([WIRE-20a])", env.ResultType)
	}
}

// TestVerifyResult_RejectsNonMemberType: VerifyResult fails closed on an
// unregistered result_type, returning a nil payload — independently of
// SignResult's own mint gate. The envelope carries a cryptographically
// VALID signature over exactly the preimage an open-world framing would
// produce (hand-minted with the test-local lp/tsBytes replicas, never
// SignResult), so the rejection can only come from the [WIRE-20a]
// membership gate — never from a missing or invalid signature
// (review finding, PR #19 round 2).
func TestVerifyResult_RejectsNonMemberType(t *testing.T) {
	priv := newECDSAKey(t)
	env := goldenResultEnvelope()
	env.ResultType = "diagnostics" // grammar-valid, not in the closed set
	var pre bytes.Buffer
	lp(&pre, []byte("power-manage:result:diagnostics:v1"))
	lp(&pre, []byte(env.GetResultType()))
	lp(&pre, []byte(env.GetDeviceId()))
	lp(&pre, tsBytes(env.GetIssuedAt().GetSeconds(), env.GetIssuedAt().GetNanos()))
	lp(&pre, env.GetPayload())
	digest := sha256.Sum256(pre.Bytes())
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("hand-signing the open-world preimage: %v", err)
	}
	env.Signature = sig
	got, err := sign.VerifyResult(&priv.PublicKey, env, sign.ResultVerifyOptions{DeviceID: goldenTarget})
	assertRejected(t, got, err, "[WIRE-20a] non-member result_type must fail closed at verify")
}
