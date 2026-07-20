package seal_test

// SPEC-003 M4 sealed-transport shape + info-constant tests (AC-8, [WIRE-23],
// SEC-11). The seal/open CRYPTO lives exclusively in sdk (crypto allocation,
// §2) — contract defines only the SealedBlob message shape and the mandated
// domain-info constants. This file pins:
//   - the three info-string constant values (choice 5, operator decision
//     2026-07-19),
//   - that the exported closed info set is EXACTLY those three, and
//   - the SealedBlob descriptor shape: field set, numbers, and the
//     buf.validate rules that make each field boundable ([WIRE-2]).
//
// Bound API for the closed set (plan left this free): seal.InfoStrings()
// []string — a function returning the closed info set, asserted exact-set in
// both directions against the three constants.

import (
	"sort"
	"testing"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/contract/seal"
)

// TestSealInfoConstants pins the three [WIRE-23]/SEC-11 domain-info strings to
// their exact recorded values. These bind the HKDF info tag at the sdk seal
// seam; a drift here silently breaks every already-sealed blob. (AC-8)
func TestSealInfoConstants(t *testing.T) {
	for name, got := range map[string]string{
		"LpsPasswordSealInfo":       seal.LpsPasswordSealInfo,
		"LuksPassphraseSealInfo":    seal.LuksPassphraseSealInfo,
		"ActionFieldSecretSealInfo": seal.ActionFieldSecretSealInfo,
	} {
		want := map[string]string{
			"LpsPasswordSealInfo":       "power-manage-lps-password:v1",
			"LuksPassphraseSealInfo":    "power-manage-luks-passphrase:v1",
			"ActionFieldSecretSealInfo": "power-manage-action-field-secret:v1",
		}[name]
		if got != want {
			t.Errorf("seal.%s = %q, want %q ([WIRE-23], SEC-11, choice 5)", name, got, want)
		}
	}
}

// TestInfoStrings_ClosedSet pins the exported closed info set to exactly the
// three constants, both directions — an extra entry is an unapproved sealing
// domain, a missing one leaves a mandated domain unrepresentable. (AC-8)
func TestInfoStrings_ClosedSet(t *testing.T) {
	got := seal.InfoStrings()
	want := []string{
		seal.ActionFieldSecretSealInfo,
		seal.LpsPasswordSealInfo,
		seal.LuksPassphraseSealInfo,
	}
	if len(got) != len(want) {
		t.Fatalf("seal.InfoStrings() = %v (%d entries), want exactly the 3 mandated info strings %v", got, len(got), want)
	}
	gs := append([]string(nil), got...)
	sort.Strings(gs)
	sort.Strings(want)
	for i := range want {
		if gs[i] != want[i] {
			t.Errorf("seal.InfoStrings()[%d] = %q, want %q — the closed set is exactly the three constants (AC-8, choice 5)", i, gs[i], want[i])
		}
	}
	// Exact-set means exact membership: no info string outside the constants.
	consts := map[string]bool{
		seal.LpsPasswordSealInfo:       true,
		seal.LuksPassphraseSealInfo:    true,
		seal.ActionFieldSecretSealInfo: true,
	}
	for _, s := range got {
		if !consts[s] {
			t.Errorf("seal.InfoStrings() contains %q, which is not one of the three mandated constants (AC-8)", s)
		}
	}
}

// sealedBlobDescriptor returns the SealedBlob message descriptor, sourced from
// the generated message (ground truth), for the shape assertions below.
func sealedBlobDescriptor(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	return (&powermanagev1.SealedBlob{}).ProtoReflect().Descriptor()
}

func fieldRules(f protoreflect.FieldDescriptor) *validate.FieldRules {
	rules, _ := proto.GetExtension(f.Options(), validate.E_Field).(*validate.FieldRules)
	return rules
}

// TestSealedBlob_Shape pins the AC-8 / [WIRE-23] SealedBlob descriptor:
// exactly {ciphertext, ephemeral_public_key, info, context} with field numbers
// 1..4 — an accidental renumbering or an extra field is loud. (AC-8)
func TestSealedBlob_Shape(t *testing.T) {
	md := sealedBlobDescriptor(t)
	fields := md.Fields()
	var names []string
	for i := 0; i < fields.Len(); i++ {
		names = append(names, string(fields.Get(i).Name()))
	}
	sort.Strings(names)
	want := []string{"ciphertext", "context", "ephemeral_public_key", "info"}
	if len(names) != len(want) {
		t.Fatalf("SealedBlob fields = %v, want exactly %v ([WIRE-23]: no extra transport surface)", names, want)
	}
	for i, w := range want {
		if names[i] != w {
			t.Fatalf("SealedBlob fields = %v, want exactly %v", names, want)
		}
	}
	for name, tag := range map[string]protoreflect.FieldNumber{
		"ciphertext": 1, "ephemeral_public_key": 2, "info": 3, "context": 4,
	} {
		f := fields.ByName(protoreflect.Name(name))
		if f == nil {
			t.Fatalf("SealedBlob missing field %q", name)
		}
		if got := f.Number(); got != tag {
			t.Errorf("SealedBlob.%s field number = %d, want %d (wire contract)", name, got, tag)
		}
	}
}

// TestSealedBlob_CiphertextRule: ciphertext is bytes with min_len 1 — an empty
// ciphertext is a degenerate seal ([WIRE-25] symmetric empty-input rejection).
// (AC-8, [WIRE-2])
func TestSealedBlob_CiphertextRule(t *testing.T) {
	f := sealedBlobDescriptor(t).Fields().ByName("ciphertext")
	if f.Kind() != protoreflect.BytesKind {
		t.Fatalf("SealedBlob.ciphertext kind = %v, want bytes", f.Kind())
	}
	if got := fieldRules(f).GetBytes().GetMinLen(); got != 1 {
		t.Errorf("SealedBlob.ciphertext bytes.min_len = %d, want 1 ([WIRE-2], [WIRE-25])", got)
	}
}

// TestSealedBlob_EphemeralPublicKeyRule: ephemeral_public_key is bytes with an
// exact length of 32 — an X25519 public key is 32 bytes. (AC-8, [WIRE-23])
func TestSealedBlob_EphemeralPublicKeyRule(t *testing.T) {
	f := sealedBlobDescriptor(t).Fields().ByName("ephemeral_public_key")
	if f.Kind() != protoreflect.BytesKind {
		t.Fatalf("SealedBlob.ephemeral_public_key kind = %v, want bytes", f.Kind())
	}
	if got := fieldRules(f).GetBytes().GetLen(); got != 32 {
		t.Errorf("SealedBlob.ephemeral_public_key bytes.len = %d, want 32 (X25519 public key) ([WIRE-23])", got)
	}
}

// TestSealedBlob_InfoRule: info is a string constrained `in` the closed info
// set — exactly the three mandated constants, both directions. A blob claiming
// an unregistered sealing domain must fail validation at the boundary. (AC-8,
// [WIRE-23])
func TestSealedBlob_InfoRule(t *testing.T) {
	f := sealedBlobDescriptor(t).Fields().ByName("info")
	if f.Kind() != protoreflect.StringKind {
		t.Fatalf("SealedBlob.info kind = %v, want string", f.Kind())
	}
	got := fieldRules(f).GetString().GetIn()
	want := []string{
		seal.ActionFieldSecretSealInfo,
		seal.LpsPasswordSealInfo,
		seal.LuksPassphraseSealInfo,
	}
	gs := append([]string(nil), got...)
	sort.Strings(gs)
	sort.Strings(want)
	if len(gs) != len(want) {
		t.Fatalf("SealedBlob.info string.in = %v, want exactly the 3 closed info strings %v ([WIRE-23])", got, want)
	}
	for i := range want {
		if gs[i] != want[i] {
			t.Errorf("SealedBlob.info string.in[%d] = %q, want %q — the tag must bind exactly the closed set (AC-8)", i, gs[i], want[i])
		}
	}
}

// TestSealedBlob_ContextRule: context is a string with min_len 1 — the
// device|action|username (or device|action) binding is mandatory; an empty
// context is unbound sealing. (AC-8, [WIRE-23])
func TestSealedBlob_ContextRule(t *testing.T) {
	f := sealedBlobDescriptor(t).Fields().ByName("context")
	if f.Kind() != protoreflect.StringKind {
		t.Fatalf("SealedBlob.context kind = %v, want string", f.Kind())
	}
	if got := fieldRules(f).GetString().GetMinLen(); got != 1 {
		t.Errorf("SealedBlob.context string.min_len = %d, want 1 (mandatory context binding) ([WIRE-23])", got)
	}
}
