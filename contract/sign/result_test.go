package sign_test

// SPEC-003 M4 (DeviceSigned result envelope) trust-boundary tests: golden
// result-preimage framing ([WIRE-20], plan-003-m4 choice 4), ECDSA/RSA
// round-trip (AC-7), the forged-key / cross-device / covered-field tamper
// matrix (AC-7, §5 "DeviceSigned report: bad signature" and "resolves to a
// different device"), result_type grammar fail-closed (choice 3), and the
// shared Ed25519 boot refusal (AC-14). Results carry NO expiry
// (ResultVerifyOptions has no clock, choice 2) — no freshness rows here.
//
// This file lives in the same sign_test package as sign_test.go and reuses
// its lp/tsBytes framing mirrors, newECDSAKey/newRSAKey, assertRejected, and
// the goldenTarget/altTarget ULID constants — the result framing IS the M3
// command framing with a result domain, so a divergent second mirror would be
// its own bug.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/sign"
)

const (
	goldenResultType    = "execution"             // a plausible open-set token (choice 3)
	goldenResultPayload = "golden-result-payload" // fixed golden payload bytes

	// goldenResultDigestHex is SHA-256 over the plan-choice-4 result preimage of
	// goldenResultEnvelope(), computed independently. Pinned as a literal so a
	// framing change is loud even if the in-test mirror below drifts in lockstep
	// with the implementation ([WIRE-20]). Cross-checked against the mirror
	// construction in both directions, as TestCommandPreimage_GoldenFraming does.
	goldenResultDigestHex = "4f7765428df61d43f01cdb5d049d1ecc5848e81a556965569aa80142ee0829bd"
)

// goldenResultEnvelope is the fixed envelope the golden result preimage is
// pinned against: fixed result_type, the canonical ULID device_id, an
// issued_at with non-zero nanos, and fixed payload bytes. Results carry no
// expires_at — they are records, not commands (choice 2).
func goldenResultEnvelope() *powermanagev1.DeviceSigned {
	return &powermanagev1.DeviceSigned{
		Payload:    []byte(goldenResultPayload),
		ResultType: goldenResultType,
		DeviceId:   goldenTarget,
		IssuedAt:   &timestamppb.Timestamp{Seconds: 1700000000, Nanos: 123000000},
	}
}

// signedResultEnvelope returns a fresh ECDSA key and a validly signed result
// envelope reporting from goldenTarget — the base for the AC-7 tamper rows.
func signedResultEnvelope(t *testing.T) (*ecdsa.PrivateKey, *powermanagev1.DeviceSigned) {
	t.Helper()
	priv := newECDSAKey(t)
	env := &powermanagev1.DeviceSigned{
		Payload:    []byte("tamper-base-result-payload"),
		ResultType: "execution",
		DeviceId:   goldenTarget,
		IssuedAt:   &timestamppb.Timestamp{Seconds: 1700000000},
	}
	if err := sign.SignResult(priv, env); err != nil {
		t.Fatalf("SignResult base envelope: %v", err)
	}
	return priv, env
}

// TestResultPreimage_GoldenFraming pins the [WIRE-20] result preimage:
// length-prefixed, domain-separated covered fields in the plan-choice-4 order
// lp(domain) || lp(result_type) || lp(device_id) || lp(ts(issued_at)) ||
// lp(payload), domain "power-manage:result:execution:v1". Both the exact bytes
// (against an independent construction) and the digest (against a hex literal)
// are pinned. (AC-7, choice 4)
func TestResultPreimage_GoldenFraming(t *testing.T) {
	env := goldenResultEnvelope()

	var want bytes.Buffer
	lp(&want, []byte("power-manage:result:execution:v1"))
	lp(&want, []byte("execution"))
	lp(&want, []byte(goldenTarget))
	lp(&want, tsBytes(1700000000, 123000000))
	lp(&want, []byte(goldenResultPayload))

	got, err := sign.ResultPreimage(env)
	if err != nil {
		t.Fatalf("ResultPreimage returned error for a fully-populated envelope: %v", err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Errorf("result preimage framing drifted from plan choice 4 ([WIRE-20]):\n got  %x\n want %x", got, want.Bytes())
	}
	implDigest := sha256.Sum256(got)
	if hex.EncodeToString(implDigest[:]) != goldenResultDigestHex {
		t.Errorf("implementation result preimage digest = %x, want the pinned %s — the result signing preimage changed [WIRE-20]", implDigest[:], goldenResultDigestHex)
	}
	// Mirror check: the independent construction must itself hash to the pin, so
	// the literal and the construction can never silently agree on a wrong value.
	mirrorDigest := sha256.Sum256(want.Bytes())
	if hex.EncodeToString(mirrorDigest[:]) != goldenResultDigestHex {
		t.Fatalf("in-test result mirror digest = %x, want %s — recompute the golden pin", mirrorDigest[:], goldenResultDigestHex)
	}
}

// TestSignResult_ECDSARoundTrip: sign with ECDSA P-256, verify against the same
// device ULID, and the returned payload is byte-identical to the signed input.
// (AC-7)
func TestSignResult_ECDSARoundTrip(t *testing.T) {
	priv := newECDSAKey(t)
	env := goldenResultEnvelope()
	orig := append([]byte(nil), env.Payload...)
	if err := sign.SignResult(priv, env); err != nil {
		t.Fatalf("SignResult (ECDSA P-256): %v", err)
	}
	got, err := sign.VerifyResult(&priv.PublicKey, env, sign.ResultVerifyOptions{DeviceID: goldenTarget})
	if err != nil {
		t.Fatalf("VerifyResult rejected a valid ECDSA result envelope: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Errorf("verified result payload = %q, want byte-identical to the signed input %q (AC-7, [WIRE-20])", got, orig)
	}
}

// TestSignResult_RSARoundTrip: the same round-trip under RSA PKCS#1 v1.5 over
// the SHA-256 result digest. (AC-7)
func TestSignResult_RSARoundTrip(t *testing.T) {
	priv := newRSAKey(t)
	env := &powermanagev1.DeviceSigned{
		Payload:    []byte("rsa-result-round-trip-payload"),
		ResultType: "execution",
		DeviceId:   goldenTarget,
		IssuedAt:   &timestamppb.Timestamp{Seconds: 1700000000},
	}
	orig := append([]byte(nil), env.Payload...)
	if err := sign.SignResult(priv, env); err != nil {
		t.Fatalf("SignResult (RSA 2048): %v", err)
	}
	got, err := sign.VerifyResult(&priv.PublicKey, env, sign.ResultVerifyOptions{DeviceID: goldenTarget})
	if err != nil {
		t.Fatalf("VerifyResult rejected a valid RSA result envelope: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Errorf("verified result payload = %q, want byte-identical to the signed input %q (AC-7)", got, orig)
	}
}

// TestVerifyResult_ForgedKey: a report verified against a DIFFERENT enrolled
// device's key is rejected before recording — the signature proves origin.
// (AC-7; §5 "DeviceSigned report: bad signature")
func TestVerifyResult_ForgedKey(t *testing.T) {
	_, env := signedResultEnvelope(t)
	forger := newECDSAKey(t) // a different enrolled device's key
	got, err := sign.VerifyResult(&forger.PublicKey, env, sign.ResultVerifyOptions{DeviceID: goldenTarget})
	assertRejected(t, got, err, "AC-7 report verified under a different device's key (forged origin)")
}

// TestVerifyResult_TamperDeviceID: signing under goldenTarget then re-stamping
// the envelope's device_id to altTarget AND pointing opts at altTarget lets the
// addressing check pass — so the SIGNATURE is what must reject, proving
// device_id is a signature-covered field, not merely addressing. This is the
// cross-device signature-covered row. (AC-7)
func TestVerifyResult_TamperDeviceID(t *testing.T) {
	priv, env := signedResultEnvelope(t)
	env.DeviceId = altTarget
	got, err := sign.VerifyResult(&priv.PublicKey, env, sign.ResultVerifyOptions{DeviceID: altTarget})
	assertRejected(t, got, err, "AC-7 device_id re-stamped to another ULID with opts following (covered field, not addressing)")
}

// TestVerifyResult_CrossDeviceAddressing: a validly-signed report from
// goldenTarget is rejected when the caller expects a different device
// (opts.DeviceID = altTarget) — control states which device it expects and the
// envelope device_id must equal it, even though the signature itself is valid.
// (AC-7; §5 "resolves to a different device's work")
func TestVerifyResult_CrossDeviceAddressing(t *testing.T) {
	priv, env := signedResultEnvelope(t) // device_id goldenTarget, valid signature
	got, err := sign.VerifyResult(&priv.PublicKey, env, sign.ResultVerifyOptions{DeviceID: altTarget})
	assertRejected(t, got, err, "AC-7 valid signature but opts.DeviceID != envelope device_id (addressing mismatch)")
}

// TestVerifyResult_TamperPayload: flipping a payload byte breaks verification —
// payload is a signature-covered field. (AC-7)
func TestVerifyResult_TamperPayload(t *testing.T) {
	priv, env := signedResultEnvelope(t)
	env.Payload[0] ^= 0xFF
	got, err := sign.VerifyResult(&priv.PublicKey, env, sign.ResultVerifyOptions{DeviceID: goldenTarget})
	assertRejected(t, got, err, "AC-7 payload byte flip (covered field)")
}

// TestVerifyResult_TamperResultType: swapping result_type to another valid
// grammar token breaks verification — it is covered AND drives the result
// domain "power-manage:result:<type>:v1". (AC-7)
func TestVerifyResult_TamperResultType(t *testing.T) {
	priv, env := signedResultEnvelope(t)
	env.ResultType = "compliance" // valid grammar token; signature was over the execution domain
	got, err := sign.VerifyResult(&priv.PublicKey, env, sign.ResultVerifyOptions{DeviceID: goldenTarget})
	assertRejected(t, got, err, "AC-7 result_type swap execution->compliance (covered field + domain separation)")
}

// TestVerifyResult_TamperIssuedAt: shifting issued_at by 1 s breaks
// verification — issued_at is covered. (AC-7)
func TestVerifyResult_TamperIssuedAt(t *testing.T) {
	priv, env := signedResultEnvelope(t)
	env.IssuedAt.Seconds++
	got, err := sign.VerifyResult(&priv.PublicKey, env, sign.ResultVerifyOptions{DeviceID: goldenTarget})
	assertRejected(t, got, err, "AC-7 issued_at shifted +1s (covered field)")
}

// TestVerifyResult_TamperSignature: flipping a signature byte breaks
// verification. (AC-7)
func TestVerifyResult_TamperSignature(t *testing.T) {
	priv, env := signedResultEnvelope(t)
	env.Signature[len(env.Signature)-1] ^= 0xFF
	got, err := sign.VerifyResult(&priv.PublicKey, env, sign.ResultVerifyOptions{DeviceID: goldenTarget})
	assertRejected(t, got, err, "AC-7 signature byte flip")
}

// TestVerifyResult_EmptyPayload: a report with an empty payload never verifies
// — empty inputs are rejected symmetrically ([WIRE-25]). (AC-7)
func TestVerifyResult_EmptyPayload(t *testing.T) {
	priv, env := signedResultEnvelope(t)
	env.Payload = []byte{} // blanked after signing
	got, err := sign.VerifyResult(&priv.PublicKey, env, sign.ResultVerifyOptions{DeviceID: goldenTarget})
	assertRejected(t, got, err, "AC-7 empty payload ([WIRE-25] symmetric empty-input rejection)")
}

// TestVerifyResult_MalformedDeviceID: a non-ULID device_id, even when
// opts.DeviceID matches it exactly, is refused at the preimage chokepoint —
// a malformed address is never framed, signed, or verified ([WIRE-18]/ULID
// rule). (AC-7)
func TestVerifyResult_MalformedDeviceID(t *testing.T) {
	priv := newECDSAKey(t)
	env := goldenResultEnvelope()
	env.DeviceId = "not-a-ulid"
	env.Signature = []byte{0x01} // must be refused before/at the preimage, never examined
	got, err := sign.VerifyResult(&priv.PublicKey, env, sign.ResultVerifyOptions{DeviceID: "not-a-ulid"})
	assertRejected(t, got, err, "AC-7 non-ULID device_id with matching opts (preimage chokepoint refuses)")
}

// TestResultPreimage_RejectsMalformedDeviceID: the framing chokepoint refuses a
// non-ULID device_id, so neither signing nor verification can ever cover a
// malformed reporter identity — defense in depth beneath the proto ULID tag
// ([WIRE-18], ULID rule).
func TestResultPreimage_RejectsMalformedDeviceID(t *testing.T) {
	for name, id := range map[string]string{
		"empty":     "",
		"lowercase": "01arz3ndektsv4rrffq69g5fav",
		"too short": "01ARZ3NDEKTSV4RRFFQ69G5FA",
		"uuid":      "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
		"bad char":  "01ARZ3NDEKTSV4RRFFQ69G5FIL",
	} {
		t.Run(name, func(t *testing.T) {
			env := goldenResultEnvelope()
			env.DeviceId = id
			got, err := sign.ResultPreimage(env)
			if err == nil {
				t.Errorf("ResultPreimage accepted device_id %q — a non-ULID reporter is never framed ([WIRE-18], ULID rule)", id)
			}
			if got != nil {
				t.Errorf("ResultPreimage returned bytes for device_id %q, want nil on error", id)
			}
		})
	}
}

// TestSignResult_RejectsMalformedDeviceID: the signing seam inherits the
// chokepoint — a malformed reporter identity cannot be signed into existence.
func TestSignResult_RejectsMalformedDeviceID(t *testing.T) {
	priv := newECDSAKey(t)
	env := goldenResultEnvelope()
	env.DeviceId = "not-a-ulid"
	if err := sign.SignResult(priv, env); err == nil {
		t.Fatalf("SignResult signed an envelope with a non-ULID device_id — the mint seam must fail closed ([WIRE-18])")
	}
}

// TestResultDomain_Execution: "execution" maps to the [WIRE-20] result domain
// "power-manage:result:execution:v1" (choice 4 formula).
func TestResultDomain_Execution(t *testing.T) {
	got, err := sign.ResultDomain("execution")
	if err != nil {
		t.Fatalf("ResultDomain(\"execution\") errored: %v", err)
	}
	if want := "power-manage:result:execution:v1"; got != want {
		t.Errorf("ResultDomain(\"execution\") = %q, want %q ([WIRE-20] formula)", got, want)
	}
}

// TestResultDomain_GrammarViolations: result_type is a grammar-checked token
// ([a-z0-9-]+, non-empty) at M4 (choice 3); anything else fails closed so a
// malformed type can never frame a preimage. The CLOSED result-type set (with
// per-type constants + G-5-style exact-set registration) arms at M5 — until
// then the grammar is the whole gate (choice 3 ceiling).
func TestResultDomain_GrammarViolations(t *testing.T) {
	for name, rt := range map[string]string{
		"empty":         "",
		"uppercase":     "Bad-Type",
		"space":         "has space",
		"non-ascii":     "über",
		"underscore":    "snake_case",
		"colon":         "power:manage",
		"leading space": " execution",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := sign.ResultDomain(rt)
			if err == nil {
				t.Errorf("ResultDomain(%q) returned no error — result_type must satisfy [a-z0-9-]+ and fail closed otherwise (choice 3)", rt)
			}
			if got != "" {
				t.Errorf("ResultDomain(%q) = %q, want empty string on error (fail-closed)", rt, got)
			}
		})
	}
}

// TestSignResult_GrammarViolationRejected: a grammar-violating result_type is
// refused at the signing seam, so an unframable report never gets a signature.
func TestSignResult_GrammarViolationRejected(t *testing.T) {
	priv := newECDSAKey(t)
	env := goldenResultEnvelope()
	env.ResultType = "Bad-Type" // uppercase violates [a-z0-9-]+
	if err := sign.SignResult(priv, env); err == nil {
		t.Fatalf("SignResult signed a report with a grammar-violating result_type — the mint seam must fail closed (choice 3)")
	}
}

// TestSignResult_RejectsEd25519: SignResult routes through the shared
// ValidateSigningKey, so an Ed25519 key can never sign a result. (AC-14)
func TestSignResult_RejectsEd25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}
	env := goldenResultEnvelope()
	err = sign.SignResult(priv, env)
	if err == nil {
		t.Fatalf("SignResult signed a result with an Ed25519 key — it must be refused (AC-14, shared ValidateSigningKey)")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "ed25519") {
		t.Errorf("SignResult error = %q, want it to name ed25519 (AC-14)", err)
	}
}

// TestVerifyResult_RejectsEd25519: VerifyResult refuses an Ed25519 verifying
// key before any content check, returning a nil payload. (AC-14)
func TestVerifyResult_RejectsEd25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}
	env := goldenResultEnvelope()
	env.Signature = []byte{0x01} // key is rejected before the signature is examined
	got, err := sign.VerifyResult(pub, env, sign.ResultVerifyOptions{DeviceID: goldenTarget})
	if err == nil {
		t.Fatalf("VerifyResult accepted an Ed25519 verifying key (AC-14)")
	}
	if got != nil {
		t.Errorf("VerifyResult returned payload %q on an Ed25519 key, want nil", got)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "ed25519") {
		t.Errorf("VerifyResult error = %q, want it to name ed25519 (AC-14)", err)
	}
}
