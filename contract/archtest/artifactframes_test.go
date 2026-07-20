package archtest

// SPEC-003 M5 artifact-fetch frame shapes (AC-10, [WIRE-28] verbatim, plan
// choice 4). Shared by both streams ([WIRE-1] one definition): AgentFrame /
// ServerFrame carry them directly; the internal stream wraps them via the
// *Relay messages (pinned in streams_test.go). Schema-level only — the
// relay/chokepoint behaviour is SPEC-010/012/013.

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

const sha256Pattern = "^[a-f0-9]{64}$"

// TestArtifactFetchRequest_Shape: {sha256: string ^[a-f0-9]{64}$ = 1, offset:
// uint64 = 2} ([WIRE-28], plan choice 4). offset is DELIBERATELY untagged —
// full uint64 range is legal resume input; bounds are the artifact's size,
// enforced server-side (ART-2, SPEC-010). A bound here would over-constrain
// legitimate resume ([WIRE-2] "tags must not over-constrain").
func TestArtifactFetchRequest_Shape(t *testing.T) {
	md := requireMessage(t, "ArtifactFetchRequest")
	assertExact(t, "ArtifactFetchRequest fields", msgFieldNames(md), []string{"offset", "sha256"})
	assertSha256Field(t, md, "sha256", 1)
	assertUnconstrainedOffset(t, md, "offset", 2)
}

// TestArtifactChunk_Shape: {sha256: string ^[a-f0-9]{64}$ = 1, offset: uint64
// = 2, data: bytes min_len 1 = 3} ([WIRE-28], plan choice 4). Completion is
// the agent's (sha256, size) reference from the signed command, not a
// zero-length success — so data is non-empty. offset stays unconstrained.
func TestArtifactChunk_Shape(t *testing.T) {
	md := requireMessage(t, "ArtifactChunk")
	assertExact(t, "ArtifactChunk fields", msgFieldNames(md), []string{"data", "offset", "sha256"})
	assertSha256Field(t, md, "sha256", 1)
	assertUnconstrainedOffset(t, md, "offset", 2)
	d := requireFieldNum(t, md, "data", 3)
	if d.Kind() != protoreflect.BytesKind {
		t.Fatalf("ArtifactChunk.data kind = %v, want bytes", d.Kind())
	}
	if got := fieldRules(d).GetBytes().GetMinLen(); got != 1 {
		t.Errorf("ArtifactChunk.data bytes.min_len = %d, want 1 — never a zero-length success ([WIRE-28])", got)
	}
}

// TestArtifactFetchError_Shape: {sha256: string ^[a-f0-9]{64}$ = 1, code:
// ArtifactFetchErrorCode (defined_only, not_in 0) = 2} ([WIRE-28], plan choice
// 4). Static messages per [WIRE-7], so NO message/text/detail field exists —
// the code IS the whole answer; raw text would be an information oracle.
func TestArtifactFetchError_Shape(t *testing.T) {
	md := requireMessage(t, "ArtifactFetchError")
	assertExact(t, "ArtifactFetchError fields", msgFieldNames(md), []string{"code", "sha256"})
	assertSha256Field(t, md, "sha256", 1)
	assertBoundedEnumField(t, md, "code", 2, "ArtifactFetchErrorCode")
	// [WIRE-7] static-message pin: no in-band error text of any name.
	for _, banned := range []string{"message", "text", "detail", "reason", "error"} {
		assertNoField(t, md, banned)
	}
}

// TestArtifactFetchErrorCode_Values: enum {UNSPECIFIED=0, UNKNOWN_DIGEST=1,
// GONE=2} — exactly the two unservable causes [WIRE-28] names (unknown digest,
// garbage-collected blob) plus the [WIRE-4] zero. A third cause without an
// implementation would be dead contract surface.
func TestArtifactFetchErrorCode_Values(t *testing.T) {
	assertEnumValues(t, "ArtifactFetchErrorCode", map[protoreflect.EnumNumber]string{
		0: "_UNSPECIFIED",
		1: "_UNKNOWN_DIGEST",
		2: "_GONE",
	})
}

func assertSha256Field(t *testing.T, md protoreflect.MessageDescriptor, name string, num protoreflect.FieldNumber) {
	t.Helper()
	f := requireFieldNum(t, md, name, num)
	if f.Kind() != protoreflect.StringKind {
		t.Fatalf("%s.%s kind = %v, want string", md.Name(), name, f.Kind())
	}
	if got := fieldRules(f).GetString().GetPattern(); got != sha256Pattern {
		t.Errorf("%s.%s string.pattern = %q, want %q — sha256 is 64 lowercase hex ([WIRE-28])", md.Name(), name, got, sha256Pattern)
	}
}

// assertUnconstrainedOffset pins the deliberate absence of rules on offset
// (plan choice 4): the field is present, uint64, and carries NO buf.validate
// constraint. The G-1 collision reported at test authorship is resolved:
// descwalk.go's untaggedExemptions sanctions exactly these two offset
// fields, keyed by full name with rationale.
func assertUnconstrainedOffset(t *testing.T, md protoreflect.MessageDescriptor, name string, num protoreflect.FieldNumber) {
	t.Helper()
	f := requireFieldNum(t, md, name, num)
	if f.Kind() != protoreflect.Uint64Kind {
		t.Fatalf("%s.%s kind = %v, want uint64", md.Name(), name, f.Kind())
	}
	rules := fieldRules(f)
	if rules != nil && (rules.Type != nil || rules.Cel != nil || rules.Required != nil) {
		t.Errorf("%s.%s carries buf.validate rules but must be deliberately unconstrained — full uint64 range is legal resume input; bounds are the artifact's size, server-side (plan choice 4, ART-2/SPEC-010)", md.Name(), name)
	}
}
