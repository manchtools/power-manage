package archtest

// SPEC-003 G-8 near-copy guard (TestGuard_NearCopies, [WIRE-1], plan choice
// 12). A descriptor walk over every contract message: two messages whose
// field-name+type multisets are identical are a mirrored near-copy — the shape
// that drifted field by field in the predecessor (log-query vs osquery). They
// fail unless allowlisted with a per-entry rationale. Matches-zero protection
// is the Discover floor on the proto-file population.
//
// Empty (zero-field) messages are excluded: they have no field shape to mirror,
// and the closed catalog carries 21 empty ActionParams stubs by design (their
// fields land with SPEC-014). This is the ONLY refinement of the literal
// criterion — single-field messages stay in scope (a single field can still be
// a mirrored pair), so the allowlist is where a legitimately-distinct identical
// pair is recorded.

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// nearCopyAllowlist records identical-shape pairs that are legitimately
// distinct (keyed by the sorted "fullA|fullB" pair, value = the rationale).
// Every entry is a deliberate, reviewable decision that these two identical
// shapes are NOT a [WIRE-1] mirrored copy.
var nearCopyAllowlist = map[string]string{
	"powermanage.v1.CompleteOidcSessionResponse|powermanage.v1.RefreshSessionResponse": "Buf requires operation-specific unary response types; both return the ordinary rotating session token pair, while their authentication ceremonies and future response evolution remain independent",
	"powermanage.v1.DeviceConnected|powermanage.v1.DeviceDisconnected":                 "two distinct lifecycle events sharing the minimal addressing-only shape {device_id: ULID}; the discriminant is the frame-oneof tag, not a drifted payload field (GW-3.1)",
	"powermanage.v1.EnrollAgentResponse|powermanage.v1.RenewAgentResponse":             "operation-specific RPC results currently share public certificate/CA fields, while renewal alone gains CA-continuity material in SPEC-006 M8; distinct descriptors keep that evolution out of fresh enrollment",
	"powermanage.v1.EnrollGatewayResponse|powermanage.v1.RenewGatewayResponse":         "operation-specific gateway lifecycle results share the exact public certificate/issuing-CA shape; renewal authorization and state transition remain distinct from token-authorized enrollment",
	"powermanage.v1.ForceRenewAgentRequest|powermanage.v1.RevokeAgentRequest":          "Buf requires operation-specific unary request types; both identify the exact current certificate, while force-renew may gain renewal policy independently of terminal revocation (PKI-6)",
	"powermanage.v1.ForceRenewAgentRequest|powermanage.v1.RevokeGatewayRequest":        "operator lifecycle operations identify the exact current certificate while preserving separate agent force-renew and terminal gateway-revocation procedures",
	"powermanage.v1.RevokeAgentRequest|powermanage.v1.RevokeGatewayRequest":            "agent and gateway revocation both identify the exact current certificate, while separate RPC descriptors preserve class-specific authorization and lifecycle handling",
}

// TestGuard_NearCopies is G-8 over the real contract: no two messages share an
// identical field-name/type shape outside the allowlist.
func TestGuard_NearCopies(t *testing.T) {
	files := Discover(t, "contract proto files", 11, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(ContractPackage), nil
	})
	for _, v := range nearCopyViolations(files) {
		t.Errorf("%s (G-8, [WIRE-1], SPEC-003)", v)
	}
	allowlistPairs := make([]string, 0, len(nearCopyAllowlist))
	for pair := range nearCopyAllowlist {
		allowlistPairs = append(allowlistPairs, pair)
	}
	sort.Strings(allowlistPairs)
	for _, pair := range allowlistPairs {
		names := strings.Split(pair, "|")
		if len(names) != 2 {
			t.Errorf("near-copy allowlist key %q is not an exact pair", pair)
			continue
		}
		messages := make([]protoreflect.MessageDescriptor, 0, 2)
		for _, fullName := range names {
			message, err := findRegistry(files, protoreflect.Name(strings.TrimPrefix(fullName, "powermanage.v1.")))
			if err != nil {
				t.Errorf("near-copy allowlist key %q is stale: %v", pair, err)
				continue
			}
			messages = append(messages, message)
		}
		if len(messages) == 2 && shapeSignature(messages[0]) != shapeSignature(messages[1]) {
			t.Errorf("near-copy allowlist key %q no longer names an identical-shape pair", pair)
		}
	}
	// The addressing wrappers (plan choice 3) are composition, not near-copies:
	// pin that DeviceReport and PushCommand exist and differ structurally, so a
	// refactor collapsing them into a mirrored pair is loud.
	dr := requireMessage(t, "DeviceReport")
	pc := requireMessage(t, "PushCommand")
	if shapeSignature(dr) == shapeSignature(pc) {
		t.Errorf("DeviceReport and PushCommand share a shape — they must differ (report:DeviceSigned vs command:SignedCommand); the wrappers are composition around the ONE definition, not near-copies (plan choice 3, [WIRE-1])")
	}
}

// TestGuard_NearCopies_Liveness plants an exact structural-twin pair
// (FixtureTwinA / FixtureTwinB, both {twin_id: string}) and asserts EXACTLY
// that pair is flagged — the empty stub (FixtureAParams) and the single-field
// non-twins (distinct field names) must stay clean. Proof the walk can go red
// and does not over-flag.
func TestGuard_NearCopies_Liveness(t *testing.T) {
	files := Discover(t, "fixture proto files", 1, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(fixturePackage), nil
	})
	got := nearCopyViolations(files)
	if len(got) != 1 {
		t.Fatalf("fixture near-copy violations = %v, want exactly the FixtureTwinA/FixtureTwinB pair — the guard can no longer go red for the planted twins (or it over-flags)", got)
	}
	if !strings.Contains(got[0], "FixtureTwinA") || !strings.Contains(got[0], "FixtureTwinB") {
		t.Errorf("flagged pair = %q, want it to name FixtureTwinA and FixtureTwinB", got[0])
	}
	for _, g := range got {
		for _, clean := range []string{
			"FixtureResponse", "UnreachableLoose", "NestedParams",
			"FixtureAParams", "FixtureManifestEntry", "FixtureDenyFields", "FixtureOptBoolParams",
		} {
			if strings.Contains(g, clean) {
				t.Errorf("guard flagged %q — %s is a distinct shape (or empty), not a near-copy; the walk over-flags", g, clean)
			}
		}
	}
}

// TestNearCopySignature_NameAndType pins the criterion: the shape signature is
// field NAME + field TYPE. Twins with the same name+type collide; two
// single-field messages with the SAME type but DIFFERENT field names do NOT —
// this is why the addressing wrappers (report vs command) pass.
func TestNearCopySignature_NameAndType(t *testing.T) {
	files := packageFiles(fixturePackage)
	twinA, err := findRegistry(files, "FixtureTwinA")
	if err != nil {
		t.Fatalf("FixtureTwinA: %v", err)
	}
	twinB, err := findRegistry(files, "FixtureTwinB")
	if err != nil {
		t.Fatalf("FixtureTwinB: %v", err)
	}
	resp, err := findRegistry(files, "FixtureResponse")
	if err != nil {
		t.Fatalf("FixtureResponse: %v", err)
	}
	if shapeSignature(twinA) != shapeSignature(twinB) {
		t.Errorf("FixtureTwinA/FixtureTwinB signatures differ (%q vs %q) — identical {twin_id: string} must collide", shapeSignature(twinA), shapeSignature(twinB))
	}
	// Same type (string), different field name (twin_id vs tagged_out): distinct.
	if shapeSignature(twinA) == shapeSignature(resp) {
		t.Errorf("FixtureTwinA and FixtureResponse share a signature %q — different field names must NOT collide (this is why report vs command pass)", shapeSignature(twinA))
	}
}

// nearCopyViolations returns a violation per unordered pair of non-empty
// messages that share an identical field-name/type signature and are not
// allowlisted.
func nearCopyViolations(files []protoreflect.FileDescriptor) []string {
	bySig := map[string][]protoreflect.MessageDescriptor{}
	for _, md := range allMessages(files) {
		if md.Fields().Len() == 0 {
			continue // an empty message has no field shape to mirror
		}
		sig := shapeSignature(md)
		bySig[sig] = append(bySig[sig], md)
	}
	var out []string
	for _, group := range bySig {
		if len(group) < 2 {
			continue
		}
		sort.Slice(group, func(i, j int) bool { return group[i].FullName() < group[j].FullName() })
		for i := 0; i < len(group); i++ {
			for j := i + 1; j < len(group); j++ {
				a, b := string(group[i].FullName()), string(group[j].FullName())
				if _, ok := nearCopyAllowlist[a+"|"+b]; ok {
					continue
				}
				out = append(out, fmt.Sprintf("%s and %s share an identical field-name/type shape — mirrored near-copies drift field by field ([WIRE-1]); make one the shared definition, or record a rationale in nearCopyAllowlist keyed %q", a, b, a+"|"+b))
			}
		}
	}
	sort.Strings(out)
	return out
}

// shapeSignature is the canonical field-name+type multiset of md: sorted
// "name=type" pairs. Type is the full name for message/enum fields (so two
// wrappers embedding DIFFERENT types differ), the kind for scalars, and carries
// the repeated/map cardinality.
func shapeSignature(md protoreflect.MessageDescriptor) string {
	fields := md.Fields()
	parts := make([]string, 0, fields.Len())
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		parts = append(parts, string(f.Name())+"="+fieldTypeString(f))
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

func fieldTypeString(f protoreflect.FieldDescriptor) string {
	if f.IsMap() {
		return "map<" + f.MapKey().Kind().String() + "," + fieldValueType(f.MapValue()) + ">"
	}
	base := fieldValueType(f)
	if f.IsList() {
		return "repeated " + base
	}
	return base
}

func fieldValueType(f protoreflect.FieldDescriptor) string {
	if m := f.Message(); m != nil {
		return "message:" + string(m.FullName())
	}
	if e := f.Enum(); e != nil {
		return "enum:" + string(e.FullName())
	}
	return f.Kind().String()
}
