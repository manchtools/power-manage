package sign_test

// SPEC-003 M3 (SignedCommand) trust-boundary tests: golden preimage framing
// ([WIRE-14], plan choice 5), ECDSA/RSA round-trip + covered-field tamper
// matrix (AC-4), the freshness/target rejection matrix (AC-6, [WIRE-15/16]),
// and Ed25519 boot refusal on all three key paths (AC-14). Every time value
// is fixed and passed through VerifyOptions.Now — the clock seam — so no test
// reads the wall clock.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/sign"
)

const (
	goldenTarget = "01ARZ3NDEKTSV4RRFFQ69G5FAV" // canonical spec-example ULID
	altTarget    = "01BX5ZZKBKACTAV9WEVGEMMVRZ" // a second valid ULID for the tamper rows

	// goldenDigestHex is SHA-256 over the plan-choice-5 preimage of
	// goldenEnvelope(), computed independently. Pinned as a literal so a
	// framing change is loud even if the in-test mirror construction below
	// drifts in lockstep with the implementation ([WIRE-14]).
	goldenDigestHex = "557b99b30bfdf3efc571fc443781a49fabf4e8315ab5da2d4d36e472fb6f6919"
)

// catalogCommandTypes is the closed §3.4 set; CommandDomain must map each and
// only these.
var catalogCommandTypes = []string{
	"action", "osquery", "logquery", "inventory",
	"luks-revoke", "lps-pubkey", "terminal-grant", "sync-manifest",
}

// lp mirrors plan choice 5's length prefix: u64be(len(x)) || x.
func lp(buf *bytes.Buffer, x []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(x)))
	buf.Write(n[:])
	buf.Write(x)
}

// tsBytes mirrors plan choice 5's 12-byte timestamp framing:
// s64be(seconds) || u32be(nanos).
func tsBytes(sec int64, nanos int32) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint64(b[0:8], uint64(sec))
	binary.BigEndian.PutUint32(b[8:12], uint32(nanos))
	return b
}

func newECDSAKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ECDSA P-256 key: %v", err)
	}
	return priv
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA 2048 key: %v", err)
	}
	return priv
}

// goldenEnvelope is the fixed envelope the golden preimage is pinned against:
// fixed command_type, ULID target, issued_at/expires_at with non-zero nanos,
// and fixed payload bytes.
func goldenEnvelope() *powermanagev1.SignedCommand {
	return &powermanagev1.SignedCommand{
		Payload:        []byte("golden-cmd-payload"),
		CommandType:    "action",
		TargetDeviceId: goldenTarget,
		IssuedAt:       &timestamppb.Timestamp{Seconds: 1700000000, Nanos: 123000000},
		ExpiresAt:      &timestamppb.Timestamp{Seconds: 1700000600, Nanos: 456000000},
	}
}

// signedActionCmd returns a fresh ECDSA key and a validly signed "action"
// envelope with a 60 s window — the base for the AC-4 tamper rows.
func signedActionCmd(t *testing.T) (*ecdsa.PrivateKey, *powermanagev1.SignedCommand) {
	t.Helper()
	priv := newECDSAKey(t)
	cmd := &powermanagev1.SignedCommand{
		Payload:        []byte("tamper-base-payload"),
		CommandType:    "action",
		TargetDeviceId: goldenTarget,
		IssuedAt:       &timestamppb.Timestamp{Seconds: 1700000000},
		ExpiresAt:      &timestamppb.Timestamp{Seconds: 1700000060},
	}
	if err := sign.SignCommand(priv, cmd); err != nil {
		t.Fatalf("SignCommand base envelope: %v", err)
	}
	return priv, cmd
}

// withinOpts verifies as the addressed device, at a fixed instant inside the
// 60 s base window, in the instant freshness class.
func withinOpts() sign.VerifyOptions {
	return sign.VerifyOptions{
		DeviceID: goldenTarget,
		Now:      time.Unix(1700000005, 0).UTC(),
		Instant:  true,
	}
}

// assertRejected pins plan choice 8: any verification failure returns a
// non-nil error AND a nil payload.
func assertRejected(t *testing.T, payload []byte, err error, what string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: VerifyCommand returned nil error, want rejection", what)
	}
	if payload != nil {
		t.Errorf("%s: VerifyCommand returned payload %q, want nil on any failure (plan choice 8)", what, payload)
	}
}

// TestCommandPreimage_GoldenFraming pins the [WIRE-14] preimage: length-
// prefixed, domain-separated covered fields in the plan-choice-5 order. Both
// the exact bytes (against an independent in-test construction) and the digest
// (against a hex literal) are pinned, so a framing change is loud. (AC-4)
func TestCommandPreimage_GoldenFraming(t *testing.T) {
	cmd := goldenEnvelope()

	var want bytes.Buffer
	lp(&want, []byte("power-manage:cmd:action:v1"))
	lp(&want, []byte("action"))
	lp(&want, []byte(goldenTarget))
	lp(&want, tsBytes(1700000000, 123000000))
	lp(&want, tsBytes(1700000600, 456000000))
	lp(&want, []byte("golden-cmd-payload"))

	got, err := sign.CommandPreimage(cmd)
	if err != nil {
		t.Fatalf("CommandPreimage returned error for a fully-populated envelope: %v", err)
	}
	if !bytes.Equal(got, want.Bytes()) {
		t.Errorf("preimage framing drifted from plan choice 5 ([WIRE-14]):\n got  %x\n want %x", got, want.Bytes())
	}
	implDigest := sha256.Sum256(got)
	if hex.EncodeToString(implDigest[:]) != goldenDigestHex {
		t.Errorf("implementation preimage digest = %x, want the pinned %s — the signing preimage changed [WIRE-14]", implDigest[:], goldenDigestHex)
	}
	// Mirror check: the independent construction must itself hash to the pin,
	// so the literal and the construction can never silently agree on a wrong
	// value.
	mirrorDigest := sha256.Sum256(want.Bytes())
	if hex.EncodeToString(mirrorDigest[:]) != goldenDigestHex {
		t.Fatalf("in-test mirror digest = %x, want %s — recompute the golden pin", mirrorDigest[:], goldenDigestHex)
	}
}

// TestSignCommand_ECDSARoundTrip: sign with ECDSA P-256, verify, and the
// returned payload is byte-identical to the signed input. (AC-4)
func TestSignCommand_ECDSARoundTrip(t *testing.T) {
	priv := newECDSAKey(t)
	cmd := &powermanagev1.SignedCommand{
		Payload:        []byte("ecdsa-round-trip-payload"),
		CommandType:    "action",
		TargetDeviceId: goldenTarget,
		IssuedAt:       &timestamppb.Timestamp{Seconds: 1700000000},
		ExpiresAt:      &timestamppb.Timestamp{Seconds: 1700000060},
	}
	orig := append([]byte(nil), cmd.Payload...)
	if err := sign.SignCommand(priv, cmd); err != nil {
		t.Fatalf("SignCommand (ECDSA P-256): %v", err)
	}
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, withinOpts())
	if err != nil {
		t.Fatalf("VerifyCommand rejected a valid ECDSA envelope: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Errorf("verified payload = %q, want byte-identical to the signed input %q (AC-4, [WIRE-14])", got, orig)
	}
}

// TestSignCommand_RSARoundTrip: the same round-trip under RSA PKCS#1 v1.5
// over the SHA-256 digest. (AC-4)
func TestSignCommand_RSARoundTrip(t *testing.T) {
	priv := newRSAKey(t)
	cmd := &powermanagev1.SignedCommand{
		Payload:        []byte("rsa-round-trip-payload"),
		CommandType:    "action",
		TargetDeviceId: goldenTarget,
		IssuedAt:       &timestamppb.Timestamp{Seconds: 1700000000},
		ExpiresAt:      &timestamppb.Timestamp{Seconds: 1700000060},
	}
	orig := append([]byte(nil), cmd.Payload...)
	if err := sign.SignCommand(priv, cmd); err != nil {
		t.Fatalf("SignCommand (RSA 2048): %v", err)
	}
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, withinOpts())
	if err != nil {
		t.Fatalf("VerifyCommand rejected a valid RSA envelope: %v", err)
	}
	if !bytes.Equal(got, orig) {
		t.Errorf("verified payload = %q, want byte-identical to the signed input %q (AC-4)", got, orig)
	}
}

// TestSignCommand_RSADeterministic pins plan choice 11: RSA PKCS#1 v1.5 is
// deterministic — signing two identical envelopes yields identical signature
// bytes. (AC-4)
func TestSignCommand_RSADeterministic(t *testing.T) {
	priv := newRSAKey(t)
	build := func() *powermanagev1.SignedCommand {
		return &powermanagev1.SignedCommand{
			Payload:        []byte("rsa-determinism-payload"),
			CommandType:    "action",
			TargetDeviceId: goldenTarget,
			IssuedAt:       &timestamppb.Timestamp{Seconds: 1700000000},
			ExpiresAt:      &timestamppb.Timestamp{Seconds: 1700000060},
		}
	}
	a, b := build(), build()
	if err := sign.SignCommand(priv, a); err != nil {
		t.Fatalf("SignCommand a: %v", err)
	}
	if err := sign.SignCommand(priv, b); err != nil {
		t.Fatalf("SignCommand b: %v", err)
	}
	if len(a.Signature) == 0 {
		t.Fatalf("SignCommand left an empty signature")
	}
	if !bytes.Equal(a.Signature, b.Signature) {
		t.Errorf("RSA PKCS#1 v1.5 signatures differ across two signings of identical envelopes — the scheme must be deterministic (plan choice 11)")
	}
}

// TestVerifyCommand_TamperPayload: flipping a payload byte breaks
// verification — payload is a signature-covered field. (AC-4)
func TestVerifyCommand_TamperPayload(t *testing.T) {
	priv, cmd := signedActionCmd(t)
	cmd.Payload[0] ^= 0xFF
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, withinOpts())
	assertRejected(t, got, err, "payload byte flip (AC-4 covered field)")
}

// TestVerifyCommand_TamperCommandType: swapping command_type to another valid
// catalog value breaks verification — it is covered and drives the domain.
// (AC-4)
func TestVerifyCommand_TamperCommandType(t *testing.T) {
	priv, cmd := signedActionCmd(t)
	cmd.CommandType = "osquery" // valid catalog value; signature was over the action domain
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, withinOpts())
	assertRejected(t, got, err, "command_type swap action->osquery (AC-4 covered field + domain separation)")
}

// TestVerifyCommand_TamperTargetDeviceID: changing target_device_id breaks
// verification even when opts.DeviceID follows the change — proving the field
// is signature-covered, not merely addressing. (AC-4)
func TestVerifyCommand_TamperTargetDeviceID(t *testing.T) {
	priv, cmd := signedActionCmd(t)
	cmd.TargetDeviceId = altTarget
	opts := withinOpts()
	opts.DeviceID = altTarget // address check passes; the signature must be what rejects
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, opts)
	assertRejected(t, got, err, "target_device_id changed to another ULID (AC-4 covered field)")
}

// TestVerifyCommand_TamperIssuedAt: shifting issued_at by 1 s breaks
// verification — issued_at is covered. (AC-4)
func TestVerifyCommand_TamperIssuedAt(t *testing.T) {
	priv, cmd := signedActionCmd(t)
	cmd.IssuedAt.Seconds++ // still issued < expires and inside the window
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, withinOpts())
	assertRejected(t, got, err, "issued_at shifted +1s (AC-4 covered field)")
}

// TestVerifyCommand_TamperExpiresAt: shifting expires_at by 1 s breaks
// verification — expires_at is covered. (AC-4)
func TestVerifyCommand_TamperExpiresAt(t *testing.T) {
	priv, cmd := signedActionCmd(t)
	cmd.ExpiresAt.Seconds++ // window stays far under 15m, so the signature — not freshness — must reject
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, withinOpts())
	assertRejected(t, got, err, "expires_at shifted +1s (AC-4 covered field)")
}

// TestVerifyCommand_TamperSignature: flipping a signature byte breaks
// verification. (AC-4)
func TestVerifyCommand_TamperSignature(t *testing.T) {
	priv, cmd := signedActionCmd(t)
	cmd.Signature[len(cmd.Signature)-1] ^= 0xFF
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, withinOpts())
	assertRejected(t, got, err, "signature byte flip (AC-4)")
}

// TestVerifyCommand_ExpiredInstant: an instant envelope whose expires_at is
// before opts.Now is rejected — a valid signature never rescues an expired
// command, and nothing is returned. (AC-6; rejection row "expires_at in the
// past")
func TestVerifyCommand_ExpiredInstant(t *testing.T) {
	priv := newECDSAKey(t)
	cmd := &powermanagev1.SignedCommand{
		Payload:        []byte("expired-payload"),
		CommandType:    "action",
		TargetDeviceId: goldenTarget,
		IssuedAt:       &timestamppb.Timestamp{Seconds: 1700000000},
		ExpiresAt:      &timestamppb.Timestamp{Seconds: 1700000060},
	}
	if err := sign.SignCommand(priv, cmd); err != nil {
		t.Fatalf("SignCommand: %v", err)
	}
	opts := sign.VerifyOptions{DeviceID: goldenTarget, Now: time.Unix(1700000100, 0).UTC(), Instant: true}
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, opts)
	assertRejected(t, got, err, "AC-6 expired instant envelope (expires_at < Now)")
}

// TestVerifyCommand_InstantWindowTooLong: an instant envelope whose
// expires_at - issued_at exceeds 15 min is rejected at verification. (AC-6;
// rejection row "instant window > 15 min")
func TestVerifyCommand_InstantWindowTooLong(t *testing.T) {
	priv := newECDSAKey(t)
	cmd := &powermanagev1.SignedCommand{
		Payload:        []byte("wide-window-payload"),
		CommandType:    "action",
		TargetDeviceId: goldenTarget,
		IssuedAt:       &timestamppb.Timestamp{Seconds: 1700000000},
		ExpiresAt:      &timestamppb.Timestamp{Seconds: 1700000000 + 15*60 + 1}, // 15m + 1s
	}
	if err := sign.SignCommand(priv, cmd); err != nil {
		t.Fatalf("SignCommand: %v", err)
	}
	opts := sign.VerifyOptions{DeviceID: goldenTarget, Now: time.Unix(1700000005, 0).UTC(), Instant: true}
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, opts)
	assertRejected(t, got, err, "AC-6 instant window 15m+1s")
}

// TestVerifyCommand_TerminalGrantWindowTooLong: a terminal-grant envelope with
// a 61 s window is rejected even in the durable class (Instant=false) — the
// 60 s bound is hard-coded per [WIRE-16], independent of the caller's
// freshness class. (AC-6; rejection row "terminal grant older than 60 s")
func TestVerifyCommand_TerminalGrantWindowTooLong(t *testing.T) {
	priv := newECDSAKey(t)
	cmd := &powermanagev1.SignedCommand{
		Payload:        []byte("grant-payload"),
		CommandType:    "terminal-grant",
		TargetDeviceId: goldenTarget,
		IssuedAt:       &timestamppb.Timestamp{Seconds: 1700000000},
		ExpiresAt:      &timestamppb.Timestamp{Seconds: 1700000061}, // 61s
	}
	if err := sign.SignCommand(priv, cmd); err != nil {
		t.Fatalf("SignCommand: %v", err)
	}
	opts := sign.VerifyOptions{DeviceID: goldenTarget, Now: time.Unix(1700000005, 0).UTC(), Instant: false}
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, opts)
	assertRejected(t, got, err, "AC-6 terminal-grant window 61s (must fail even when Instant=false) [WIRE-16]")
}

// TestVerifyCommand_TargetMismatch: an envelope whose target_device_id differs
// from opts.DeviceID (the verifying agent's own ULID) is refused. (AC-6;
// rejection row "target_device_id != agent's own ULID")
func TestVerifyCommand_TargetMismatch(t *testing.T) {
	priv := newECDSAKey(t)
	cmd := &powermanagev1.SignedCommand{
		Payload:        []byte("addressed-payload"),
		CommandType:    "action",
		TargetDeviceId: goldenTarget,
		IssuedAt:       &timestamppb.Timestamp{Seconds: 1700000000},
		ExpiresAt:      &timestamppb.Timestamp{Seconds: 1700000060},
	}
	if err := sign.SignCommand(priv, cmd); err != nil {
		t.Fatalf("SignCommand: %v", err)
	}
	opts := sign.VerifyOptions{DeviceID: altTarget, Now: time.Unix(1700000005, 0).UTC(), Instant: true}
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, opts)
	assertRejected(t, got, err, "AC-6 target_device_id != verifying agent's own ULID [WIRE-18]")
}

// TestVerifyCommand_UnknownCommandType: an envelope carrying a command_type
// outside the closed §3.4 set is rejected fail-closed, before any signature
// check. (AC-6; rejection row "signature invalid or wrong domain" via an
// unframable type)
func TestVerifyCommand_UnknownCommandType(t *testing.T) {
	priv, cmd := signedActionCmd(t)
	cmd.CommandType = "bogus" // not in the closed catalog
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, withinOpts())
	assertRejected(t, got, err, "AC-6 unknown command_type 'bogus' (fail-closed at the verifier)")
}

// TestVerifyCommand_EmptyPayload: an envelope with an empty payload never
// verifies — empty inputs are rejected symmetrically ([WIRE-25]). (AC-6)
func TestVerifyCommand_EmptyPayload(t *testing.T) {
	priv, cmd := signedActionCmd(t)
	cmd.Payload = []byte{} // blanked after signing
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, withinOpts())
	assertRejected(t, got, err, "AC-6 empty payload ([WIRE-25] symmetric empty-input rejection)")
}

// TestVerifyCommand_IssuedAfterExpires: an envelope whose issued_at is after
// its expires_at is rejected at the ordering check. (AC-6)
func TestVerifyCommand_IssuedAfterExpires(t *testing.T) {
	priv := newECDSAKey(t)
	cmd := &powermanagev1.SignedCommand{
		Payload:        []byte("backwards-window-payload"),
		CommandType:    "action",
		TargetDeviceId: goldenTarget,
		IssuedAt:       &timestamppb.Timestamp{Seconds: 1700000600}, // issued > expires
		ExpiresAt:      &timestamppb.Timestamp{Seconds: 1700000000},
	}
	if err := sign.SignCommand(priv, cmd); err != nil {
		t.Fatalf("SignCommand: %v", err)
	}
	opts := sign.VerifyOptions{DeviceID: goldenTarget, Now: time.Unix(1700000300, 0).UTC(), Instant: true}
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, opts)
	assertRejected(t, got, err, "AC-6 issued_at > expires_at (ordering check)")
}

// TestVerifyCommand_InstantWindowExactly15m: the 15-min instant bound is
// inclusive — an exactly-15m0s window passes. (AC-6 positive sanity)
func TestVerifyCommand_InstantWindowExactly15m(t *testing.T) {
	priv := newECDSAKey(t)
	cmd := &powermanagev1.SignedCommand{
		Payload:        []byte("boundary-15m-payload"),
		CommandType:    "action",
		TargetDeviceId: goldenTarget,
		IssuedAt:       &timestamppb.Timestamp{Seconds: 1700000000},
		ExpiresAt:      &timestamppb.Timestamp{Seconds: 1700000000 + 15*60}, // exactly 900s
	}
	orig := append([]byte(nil), cmd.Payload...)
	if err := sign.SignCommand(priv, cmd); err != nil {
		t.Fatalf("SignCommand: %v", err)
	}
	opts := sign.VerifyOptions{DeviceID: goldenTarget, Now: time.Unix(1700000005, 0).UTC(), Instant: true}
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, opts)
	if err != nil {
		t.Fatalf("an exactly-15m instant window was rejected: %v — the bound is <=, not < ([WIRE-15])", err)
	}
	if !bytes.Equal(got, orig) {
		t.Errorf("verified payload = %q, want %q", got, orig)
	}
}

// TestVerifyCommand_TerminalGrantWindowExactly60s: the terminal-grant 60 s
// bound is inclusive — an exactly-60s window passes. (AC-6 positive sanity)
func TestVerifyCommand_TerminalGrantWindowExactly60s(t *testing.T) {
	priv := newECDSAKey(t)
	cmd := &powermanagev1.SignedCommand{
		Payload:        []byte("grant-60-payload"),
		CommandType:    "terminal-grant",
		TargetDeviceId: goldenTarget,
		IssuedAt:       &timestamppb.Timestamp{Seconds: 1700000000},
		ExpiresAt:      &timestamppb.Timestamp{Seconds: 1700000060}, // exactly 60s
	}
	orig := append([]byte(nil), cmd.Payload...)
	if err := sign.SignCommand(priv, cmd); err != nil {
		t.Fatalf("SignCommand: %v", err)
	}
	opts := sign.VerifyOptions{DeviceID: goldenTarget, Now: time.Unix(1700000005, 0).UTC(), Instant: false}
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, opts)
	if err != nil {
		t.Fatalf("an exactly-60s terminal grant was rejected: %v — the bound is <=, not < ([WIRE-16])", err)
	}
	if !bytes.Equal(got, orig) {
		t.Errorf("verified payload = %q, want %q", got, orig)
	}
}

// TestVerifyCommand_DurableLongWindow: a durable (Instant=false) envelope with
// a 24 h window passes — long-lived assignments ride the manifest for
// liveness, so the helper does not cap the durable window. (AC-6 positive
// sanity, [WIRE-15])
func TestVerifyCommand_DurableLongWindow(t *testing.T) {
	priv := newECDSAKey(t)
	cmd := &powermanagev1.SignedCommand{
		Payload:        []byte("durable-payload"),
		CommandType:    "sync-manifest",
		TargetDeviceId: goldenTarget,
		IssuedAt:       &timestamppb.Timestamp{Seconds: 1700000000},
		ExpiresAt:      &timestamppb.Timestamp{Seconds: 1700000000 + 24*3600}, // 24h
	}
	orig := append([]byte(nil), cmd.Payload...)
	if err := sign.SignCommand(priv, cmd); err != nil {
		t.Fatalf("SignCommand: %v", err)
	}
	opts := sign.VerifyOptions{DeviceID: goldenTarget, Now: time.Unix(1700000000+3600, 0).UTC(), Instant: false}
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, opts)
	if err != nil {
		t.Fatalf("a durable 24h envelope was rejected with Instant=false: %v ([WIRE-15])", err)
	}
	if !bytes.Equal(got, orig) {
		t.Errorf("verified payload = %q, want %q", got, orig)
	}
}

// TestValidateSigningKey_RejectsEd25519: the key-load path refuses an Ed25519
// key, naming the algorithm. (AC-14; rejection row "Ed25519 key material")
func TestValidateSigningKey_RejectsEd25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}
	err = sign.ValidateSigningKey(pub)
	if err == nil {
		t.Fatalf("ValidateSigningKey accepted an Ed25519 key — Ed25519 command/CA keys are refused at boot (AC-14, [WIRE-14])")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "ed25519") {
		t.Errorf("ValidateSigningKey error = %q, want it to name ed25519 (AC-14)", err)
	}
}

// TestSignCommand_RejectsEd25519: SignCommand refuses an Ed25519 signer, so an
// Ed25519 key can never sign a command. (AC-14)
func TestSignCommand_RejectsEd25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}
	cmd := &powermanagev1.SignedCommand{
		Payload:        []byte("ed25519-sign-payload"),
		CommandType:    "action",
		TargetDeviceId: goldenTarget,
		IssuedAt:       &timestamppb.Timestamp{Seconds: 1700000000},
		ExpiresAt:      &timestamppb.Timestamp{Seconds: 1700000060},
	}
	err = sign.SignCommand(priv, cmd)
	if err == nil {
		t.Fatalf("SignCommand signed a command with an Ed25519 key — it must be refused (AC-14)")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "ed25519") {
		t.Errorf("SignCommand error = %q, want it to name ed25519 (AC-14)", err)
	}
}

// TestVerifyCommand_RejectsEd25519: VerifyCommand refuses an Ed25519 verifying
// key before any content check, returning a nil payload. (AC-14)
func TestVerifyCommand_RejectsEd25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 key: %v", err)
	}
	cmd := &powermanagev1.SignedCommand{
		Payload:        []byte("ed25519-verify-payload"),
		CommandType:    "action",
		TargetDeviceId: goldenTarget,
		IssuedAt:       &timestamppb.Timestamp{Seconds: 1700000000},
		ExpiresAt:      &timestamppb.Timestamp{Seconds: 1700000060},
		Signature:      []byte{0x01}, // key is rejected before the signature is examined
	}
	got, err := sign.VerifyCommand(pub, cmd, withinOpts())
	if err == nil {
		t.Fatalf("VerifyCommand accepted an Ed25519 verifying key (AC-14)")
	}
	if got != nil {
		t.Errorf("VerifyCommand returned payload %q on an Ed25519 key, want nil", got)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "ed25519") {
		t.Errorf("VerifyCommand error = %q, want it to name ed25519 (AC-14)", err)
	}
}

// TestVerifyCommand_ZeroNowRejected: a zero opts.Now must be rejected before
// any timestamp math — time.Time{} is year 1, so every expired envelope would
// otherwise pass the expiry check (fail closed; review finding, AC-6).
func TestVerifyCommand_ZeroNowRejected(t *testing.T) {
	priv, cmd := signedActionCmd(t)
	opts := sign.VerifyOptions{DeviceID: goldenTarget, Now: time.Time{}, Instant: true}
	got, err := sign.VerifyCommand(&priv.PublicKey, cmd, opts)
	assertRejected(t, got, err, "zero verification clock (fail-closed, AC-6)")
}

// TestCommandPreimage_RejectsMalformedTarget: the framing chokepoint refuses a
// target_device_id that is not a ULID, so neither signing nor verification can
// ever cover a malformed address — defense in depth beneath the proto
// boundary's ULID tag (review finding, [WIRE-18]).
func TestCommandPreimage_RejectsMalformedTarget(t *testing.T) {
	for name, target := range map[string]string{
		"empty":                     "",
		"too short":                 "01ARZ3NDEKTSV4RRFFQ69G5FA",
		"bad charset":               "01ARZ3NDEKTSV4RRFFQ69G5FIL", // I and L are outside Crockford base32
		"lowercase":                 "01arz3ndektsv4rrffq69g5fav",
		"uuid":                      "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
		"high timestamp first char": "81ARZ3NDEKTSV4RRFFQ69G5FAV", // first char must be 0-7
	} {
		t.Run(name, func(t *testing.T) {
			cmd := goldenEnvelope()
			cmd.TargetDeviceId = target
			got, err := sign.CommandPreimage(cmd)
			if err == nil {
				t.Errorf("CommandPreimage accepted target_device_id %q — a non-ULID target must never be framed ([WIRE-18], ULID rule)", target)
			}
			if got != nil {
				t.Errorf("CommandPreimage returned bytes for target %q, want nil on error", target)
			}
		})
	}
}

// TestSignCommand_RejectsMalformedTarget: the signing seam inherits the
// chokepoint — a malformed target cannot be signed into existence.
func TestSignCommand_RejectsMalformedTarget(t *testing.T) {
	priv := newECDSAKey(t)
	cmd := goldenEnvelope()
	cmd.TargetDeviceId = "not-a-ulid"
	if err := sign.SignCommand(priv, cmd); err == nil {
		t.Fatalf("SignCommand signed an envelope with a non-ULID target_device_id — the mint seam must fail closed ([WIRE-18])")
	}
}

// TestValidateSigningKey_RejectsNil: nil key material — the untyped nil and
// every typed-nil pointer shape — is rejected instead of passing the type
// switch and panicking later in verification (fail closed; review finding).
func TestValidateSigningKey_RejectsNil(t *testing.T) {
	for name, key := range map[string]crypto.PublicKey{
		"untyped nil":            nil,
		"typed nil ecdsa pub":    (*ecdsa.PublicKey)(nil),
		"typed nil rsa pub":      (*rsa.PublicKey)(nil),
		"typed nil ecdsa signer": (*ecdsa.PrivateKey)(nil),
		"typed nil rsa signer":   (*rsa.PrivateKey)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			if err := sign.ValidateSigningKey(key); err == nil {
				t.Errorf("ValidateSigningKey accepted %s — nil key material must fail closed, never panic downstream", name)
			}
		})
	}
}

// TestVerifyCommand_TypedNilKeyRejected: a typed-nil verifying key is refused
// up front — it must never reach the curve math and panic (a remote-triggered
// panic at the verification boundary is denial of service).
func TestVerifyCommand_TypedNilKeyRejected(t *testing.T) {
	_, cmd := signedActionCmd(t)
	got, err := sign.VerifyCommand((*ecdsa.PublicKey)(nil), cmd, withinOpts())
	assertRejected(t, got, err, "typed-nil ECDSA verifying key (fail-closed)")
}

// TestCommandDomain_CatalogTypes: each of the 8 closed command types maps to
// its [WIRE-14] domain "power-manage:cmd:<type>:v1". (AC-5 / plan choice 4)
func TestCommandDomain_CatalogTypes(t *testing.T) {
	for _, ct := range catalogCommandTypes {
		got, err := sign.CommandDomain(ct)
		if err != nil {
			t.Errorf("CommandDomain(%q) errored: %v — every closed catalog type has a domain [WIRE-14]", ct, err)
			continue
		}
		want := "power-manage:cmd:" + ct + ":v1"
		if got != want {
			t.Errorf("CommandDomain(%q) = %q, want %q ([WIRE-14] formula)", ct, got, want)
		}
	}
}

// TestCommandDomain_UnknownTypeErrors: an unknown command_type fails closed,
// so the verifier can never frame a preimage for an unregistered type. (plan
// choice 4)
func TestCommandDomain_UnknownTypeErrors(t *testing.T) {
	got, err := sign.CommandDomain("bogus")
	if err == nil {
		t.Fatalf("CommandDomain(\"bogus\") returned no error — an unknown command_type must fail closed (plan choice 4)")
	}
	if got != "" {
		t.Errorf("CommandDomain(\"bogus\") = %q, want empty string on error (fail-closed)", got)
	}
}
