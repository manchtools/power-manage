package archtest

// SPEC-003 G-8 near-copy guard (TestGuard_NearCopies, [WIRE-1], plan choice
// 12). A descriptor walk over every contract message: two messages whose
// field-name+type multisets are identical are a mirrored near-copy — the shape
// that drifted field by field in the predecessor (log-query vs osquery). They
// fail unless allowlisted with a per-entry rationale or they are the
// operation-specific CRUD envelopes Buf requires. Matches-zero protection is
// the Discover floor on the proto-file population.
//
// Empty (zero-field) messages are excluded: they have no field shape to mirror,
// and the closed catalog carries 21 empty ActionParams stubs by design (their
// fields land with SPEC-014). This is the ONLY refinement of the literal
// criterion. Single-field messages stay in scope unless they are uniform CRUD
// envelopes: get/list/delete requests, delete responses, and same-resource
// create/get/update responses compose canonical types and intentionally repeat
// only the kernel fields.

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
	"powermanage.v1.ActionSet|powermanage.v1.UserGroup":                                 "both are named, versioned aggregates, but their independently constrained names and distinct action/user membership relations make them separate domain resources rather than mirrored wire definitions",
	"powermanage.v1.CompleteOidcSessionResponse|powermanage.v1.RefreshSessionResponse":  "Buf requires operation-specific unary response types; both return the ordinary rotating session token pair, while their authentication ceremonies and future response evolution remain independent",
	"powermanage.v1.CreateActionSetRequest|powermanage.v1.CreateUserGroupRequest":       "create payloads intentionally share identifier/name primitives while applying different domain-specific name limits and creating distinct action-set versus user-group aggregates",
	"powermanage.v1.CreateDeviceGroupResponse|powermanage.v1.GetDeviceGroupResponse":    "Buf requires operation-specific unary response types; both expose the same canonical DeviceGroup projection and carry no independently duplicated domain fields",
	"powermanage.v1.CreateDeviceGroupResponse|powermanage.v1.UpdateDeviceGroupResponse": "Buf requires operation-specific unary response types; create and full-replacement update both compose the same canonical DeviceGroup projection",
	"powermanage.v1.DeviceConnected|powermanage.v1.DeviceDisconnected":                  "two distinct lifecycle events sharing the minimal addressing-only shape {device_id: ULID}; the discriminant is the frame-oneof tag, not a drifted payload field (GW-3.1)",
	"powermanage.v1.EnrollAgentResponse|powermanage.v1.RenewAgentResponse":              "operation-specific RPC results currently share public certificate/CA fields, while renewal alone gains CA-continuity material in SPEC-006 M8; distinct descriptors keep that evolution out of fresh enrollment",
	"powermanage.v1.EnrollGatewayResponse|powermanage.v1.RenewGatewayResponse":          "operation-specific gateway lifecycle results share the exact public certificate/issuing-CA shape; renewal authorization and state transition remain distinct from token-authorized enrollment",
	"powermanage.v1.ForceRenewAgentRequest|powermanage.v1.RevokeAgentRequest":           "Buf requires operation-specific unary request types; both identify the exact current certificate, while force-renew may gain renewal policy independently of terminal revocation (PKI-6)",
	"powermanage.v1.ForceRenewAgentRequest|powermanage.v1.RevokeGatewayRequest":         "operator lifecycle operations identify the exact current certificate while preserving separate agent force-renew and terminal gateway-revocation procedures",
	"powermanage.v1.RevokeAgentRequest|powermanage.v1.RevokeGatewayRequest":             "agent and gateway revocation both identify the exact current certificate, while separate RPC descriptors preserve class-specific authorization and lifecycle handling",
	"powermanage.v1.GetDeviceGroupResponse|powermanage.v1.UpdateDeviceGroupResponse":    "Buf requires operation-specific unary response types; both compose the one canonical DeviceGroup projection rather than mirroring its fields",
	"powermanage.v1.UpdateActionSetRequest|powermanage.v1.UpdateUserGroupRequest":       "full-replacement updates share kernel identifier/version fields plus a name, but enforce distinct action-set and user-group constraints and evolve with separate aggregate semantics",
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

func TestCRUDEnvelopePair_OnlyKernelWrappersAreExcluded(t *testing.T) {
	for _, pair := range [][2]string{
		{"GetActionRequest", "GetRoleRequest"},
		{"ListActionsRequest", "ListRolesRequest"},
		{"DeleteActionRequest", "DeleteRoleRequest"},
		{"DeleteActionResponse", "DeleteRoleResponse"},
		{"CreateActionResponse", "GetActionResponse"},
		{"GetActionResponse", "UpdateActionResponse"},
	} {
		if !isCRUDEnvelopePair(requireMessage(t, pair[0]), requireMessage(t, pair[1])) {
			t.Errorf("%s/%s not recognized as CRUD kernel envelopes", pair[0], pair[1])
		}
	}
	for _, pair := range [][2]string{
		{"CreateActionRequest", "CreateRoleRequest"},
		{"UpdateActionRequest", "UpdateRoleRequest"},
		{"ActionSet", "UserGroup"},
		{"CreateActionResponse", "GetRoleResponse"},
	} {
		if isCRUDEnvelopePair(requireMessage(t, pair[0]), requireMessage(t, pair[1])) {
			t.Errorf("%s/%s excluded even though domain payloads must remain guarded", pair[0], pair[1])
		}
	}
}

// nearCopyViolations returns a violation per unordered pair of non-empty
// messages that share an identical field-name/type signature and are not
// allowlisted or operation-specific CRUD kernel envelopes.
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
				if _, ok := nearCopyAllowlist[a+"|"+b]; ok ||
					isCRUDEnvelopePair(group[i], group[j]) {
					continue
				}
				out = append(out, fmt.Sprintf("%s and %s share an identical field-name/type shape — mirrored near-copies drift field by field ([WIRE-1]); make one the shared definition, or record a rationale in nearCopyAllowlist keyed %q", a, b, a+"|"+b))
			}
		}
	}
	sort.Strings(out)
	return out
}

// isCRUDEnvelopePair recognizes only operation-specific wrappers whose
// identical fields are imposed by the shared CRUD kernel. Domain objects and
// create/update payloads remain subject to the near-copy guard.
func isCRUDEnvelopePair(a, b protoreflect.MessageDescriptor) bool {
	aOperation, aResource, aKind, aOK := splitCRUDEnvelope(a.Name())
	bOperation, bResource, bKind, bOK := splitCRUDEnvelope(b.Name())
	if !aOK || !bOK || aKind != bKind {
		return false
	}
	if aKind == "Request" && aOperation == bOperation {
		return aOperation == "Get" || aOperation == "List" || aOperation == "Delete"
	}
	if aKind != "Response" {
		return false
	}
	if aOperation == "Delete" && bOperation == "Delete" {
		return true
	}
	return aResource == bResource &&
		isCanonicalObjectResponse(aOperation) &&
		isCanonicalObjectResponse(bOperation)
}

func splitCRUDEnvelope(
	name protoreflect.Name,
) (operation, resource, kind string, ok bool) {
	value := string(name)
	for _, candidateKind := range []string{"Request", "Response"} {
		if !strings.HasSuffix(value, candidateKind) {
			continue
		}
		withoutKind := strings.TrimSuffix(value, candidateKind)
		for _, candidateOperation := range []string{"Create", "Get", "List", "Update", "Delete"} {
			if strings.HasPrefix(withoutKind, candidateOperation) &&
				len(withoutKind) > len(candidateOperation) {
				return candidateOperation,
					strings.TrimPrefix(withoutKind, candidateOperation),
					candidateKind,
					true
			}
		}
	}
	return "", "", "", false
}

func isCanonicalObjectResponse(operation string) bool {
	return operation == "Create" || operation == "Get" || operation == "Update"
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
