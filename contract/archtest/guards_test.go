package archtest

import (
	"sort"
	"strings"
	"testing"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"

	// Register the fixture descriptors (test-only import — production
	// archtest never links the planted violations).
	_ "github.com/manchtools/power-manage/contract/archtest/internal/fixturepb/powermanage/fixture/v1"
)

const fixturePackage = "powermanage.fixture.v1"

// TestGuard_ServiceSurface pins the §3.2 service set (SPEC-003): exactly
// the six normative services exist — a missing service is unimplemented
// surface, an extra one is surface the spec never approved.
func TestGuard_ServiceSurface(t *testing.T) {
	got := Discover(t, "contract services", 6, func() ([]string, error) {
		return services(packageFiles(ContractPackage)), nil
	})
	want := []string{
		"powermanage.v1.AgentService",
		"powermanage.v1.ControlService",
		"powermanage.v1.ExportService",
		"powermanage.v1.InternalService",
		"powermanage.v1.PkiService",
		"powermanage.v1.ScimService",
	}
	sort.Strings(want)
	for _, w := range want {
		if !contains(got, w) {
			t.Errorf("service %s missing — the §3.2 surface is normative (SPEC-003)", w)
		}
	}
	for _, g := range got {
		if !contains(want, g) {
			t.Errorf("service %s is not in the §3.2 set — new services need a spec change first (SPEC-003)", g)
		}
	}
}

// TestGuard_ValidateTagCoverage is G-1 (SPEC-003 AC-1): every field of
// every message reachable from the six services carries buf.validate
// rules. The population anchor is the file set — a walk that finds fewer
// files than the contract has is broken, not clean.
func TestGuard_ValidateTagCoverage(t *testing.T) {
	files := Discover(t, "contract proto files", 8, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(ContractPackage), nil
	})
	for _, v := range untaggedFields(files) {
		t.Errorf("%s — add the constraint or the field ships unvalidated (G-1, SPEC-003)", v)
	}
}

// TestGuard_EnumHygiene is the G-2 descriptor half (SPEC-003 AC-2): every
// contract enum starts at *_UNSPECIFIED = 0. The erroring-default switch
// half wires up with the first contract-enum switch (M3).
func TestGuard_EnumHygiene(t *testing.T) {
	files := Discover(t, "contract proto files", 8, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(ContractPackage), nil
	})
	for _, v := range enumHygieneViolations(files) {
		t.Errorf("%s — fix the enum, never the guard (G-2, SPEC-003)", v)
	}
}

// TestGuard_ValidateTagCoverage_Liveness: the fixture plants an untagged
// reachable field, an untagged field one closure hop away, tagged fields,
// and an unreachable message — exactly the two planted violations flag.
func TestGuard_ValidateTagCoverage_Liveness(t *testing.T) {
	files := Discover(t, "fixture proto files", 1, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(fixturePackage), nil
	})
	got := untaggedFields(files)
	want := []string{
		"powermanage.fixture.v1.FixtureRequest.untagged_name",
		"powermanage.fixture.v1.NestedParams.untagged_inner",
	}
	if len(got) != len(want) {
		t.Fatalf("fixture violations = %v, want exactly %v — the guard can no longer go red for the planted shapes", got, want)
	}
	for i, w := range want {
		if !strings.HasPrefix(got[i], w+":") {
			t.Errorf("violation %d = %q, want it to flag %s", i, got[i], w)
		}
	}
	for _, g := range got {
		for _, never := range []string{"tagged_id", "tagged_out", "never_flagged", "FixtureRequest.nested"} {
			if strings.Contains(g, never) {
				t.Errorf("guard flagged %q — that shape is planted as conforming", g)
			}
		}
	}
}

// TestGuard_EnumHygiene_Liveness: the bad fixture enum flags, the good one
// stays clean.
func TestGuard_EnumHygiene_Liveness(t *testing.T) {
	files := Discover(t, "fixture proto files", 1, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(fixturePackage), nil
	})
	got := enumHygieneViolations(files)
	if len(got) != 1 || !strings.HasPrefix(got[0], "powermanage.fixture.v1.FixtureBadEnum:") {
		t.Fatalf("fixture enum violations = %v, want exactly one flagging FixtureBadEnum", got)
	}
}

// TestDescwalk_FixtureShapes pins the walk mechanics against known fixture
// shapes: service enumeration, reachability closure through a field hop,
// unreachable exclusion, and nested+top-level enum listing.
func TestDescwalk_FixtureShapes(t *testing.T) {
	files := packageFiles(fixturePackage)
	if got := services(files); len(got) != 1 || got[0] != "powermanage.fixture.v1.FixtureService" {
		t.Fatalf("services = %v, want exactly FixtureService", got)
	}
	reach := reachableMessages(files)
	for _, w := range []string{"FixtureRequest", "FixtureResponse", "NestedParams"} {
		if _, ok := reach[protoreflect.FullName(fixturePackage+"."+w)]; !ok {
			t.Errorf("reachable set misses %s", w)
		}
	}
	if _, ok := reach[protoreflect.FullName(fixturePackage+".UnreachableLoose")]; ok {
		t.Errorf("UnreachableLoose is not service-reachable but the closure included it")
	}
	if _, ok := reach[protoreflect.FullName("google.protobuf.Timestamp")]; ok {
		t.Errorf("google.protobuf.Timestamp is referenced but defined outside the audited files — the closure must stop at foreign messages, not audit their internals")
	}
	es := enums(files)
	if len(es) != 2 {
		t.Fatalf("enums = %d, want the two fixture enums", len(es))
	}
}

// TestGuard_ActionRegistry pins the ActionParams oneof to exactly the 21
// closed catalog types ([WIRE-12]; CAT-1, SPEC-014), both directions —
// a missing member is unimplementable surface, an extra one is a type the
// catalog never approved.
func TestGuard_ActionRegistry(t *testing.T) {
	got := Discover(t, "ActionParams oneof members", 21, func() ([]string, error) {
		registry, err := findRegistry(packageFiles(ContractPackage), "ActionParams")
		if err != nil {
			return nil, err
		}
		var names []string
		oneofs := registry.Oneofs()
		for i := 0; i < oneofs.Len(); i++ {
			fields := oneofs.Get(i).Fields()
			for j := 0; j < fields.Len(); j++ {
				names = append(names, string(fields.Get(j).Name()))
			}
		}
		sort.Strings(names)
		return names, nil
	})
	want := []string{
		"admin_policy", "agent_update", "app_image", "directory", "encryption",
		"file", "flatpak", "group", "lps", "package", "package_file", "reboot",
		"repository", "service", "shell", "ssh", "sshd", "sync", "update",
		"user", "wifi",
	}
	for _, w := range want {
		if !contains(got, w) {
			t.Errorf("registry member %s missing — the catalog is closed at the 21 types (CAT-1, SPEC-014)", w)
		}
	}
	for _, g := range got {
		if !contains(want, g) {
			t.Errorf("registry member %s is not a catalog type — adding one is a contract+executor+spec change (CAT-1, SPEC-014)", g)
		}
	}
}

// TestGuard_ActionParamsAuthority is G-3 (SPEC-003): exactly one
// ActionParams exists and no field outside it references a member type —
// the predecessor duplicated this oneof across five messages and the
// copies diverged.
func TestGuard_ActionParamsAuthority(t *testing.T) {
	files := Discover(t, "contract proto files", 8, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(ContractPackage), nil
	})
	violations, err := registryViolations(files, "ActionParams")
	if err != nil {
		t.Fatalf("registry walk failed: %v (G-3, SPEC-003)", err)
	}
	for _, v := range violations {
		t.Errorf("%s (G-3, SPEC-003)", v)
	}
}

// TestGuard_ActionParamsAuthority_Liveness: the fixture registry analog
// plants a direct member embed and a second oneof — both flag; embedding
// the registry itself stays clean.
func TestGuard_ActionParamsAuthority_Liveness(t *testing.T) {
	files := Discover(t, "fixture proto files", 1, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(fixturePackage), nil
	})
	got, err := registryViolations(files, "FixtureActionParams")
	if err != nil {
		t.Fatalf("fixture registry walk failed: %v", err)
	}
	want := []string{
		"powermanage.fixture.v1.FixtureDirectEmbed.direct",
		"powermanage.fixture.v1.FixtureSecondOneof.a2",
		"powermanage.fixture.v1.FixtureSecondOneof.b2",
	}
	if len(got) != len(want) {
		t.Fatalf("fixture violations = %v, want exactly the three planted shapes %v", got, want)
	}
	for i, w := range want {
		if !strings.HasPrefix(got[i], w+":") {
			t.Errorf("violation %d = %q, want it to flag %s", i, got[i], w)
		}
	}
	for _, g := range got {
		if strings.Contains(g, "FixtureConformingEmbed") {
			t.Errorf("guard flagged %q — embedding the registry is the conforming form", g)
		}
	}
}

// TestGuard_ExplicitPresence is G-4 (SPEC-003, [WIRE-6]): no plain bool in
// the registry subtree without a recorded two-value rationale.
func TestGuard_ExplicitPresence(t *testing.T) {
	files := Discover(t, "contract proto files", 8, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(ContractPackage), nil
	})
	violations, err := plainBoolViolations(files, "ActionParams")
	if err != nil {
		t.Fatalf("registry subtree walk failed: %v (G-4, SPEC-003)", err)
	}
	for _, v := range violations {
		t.Errorf("%s (G-4, SPEC-003)", v)
	}
}

// TestGuard_ExplicitPresence_Liveness: the planted plain bool flags; the
// optional sibling stays clean.
func TestGuard_ExplicitPresence_Liveness(t *testing.T) {
	files := Discover(t, "fixture proto files", 1, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(fixturePackage), nil
	})
	got, err := plainBoolViolations(files, "FixtureActionParams")
	if err != nil {
		t.Fatalf("fixture subtree walk failed: %v", err)
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], "powermanage.fixture.v1.FixtureBoolParams.plain_flag:") {
		t.Fatalf("fixture violations = %v, want exactly the planted plain_flag", got)
	}
	for _, g := range got {
		if strings.Contains(g, "opt_flag") {
			t.Errorf("guard flagged %q — optional bool is the conforming form", g)
		}
	}
}

// TestGuard_EnumBounds enforces the descriptor-derived bound pair on every
// enum field of every service-reachable message ([WIRE-2], AC-2).
// Vacuously green until the first service-reachable enum field lands
// (recorded, docs/plans/spec-003-m2.md choice 4); the liveness row proves
// the walk can go red.
func TestGuard_EnumBounds(t *testing.T) {
	files := Discover(t, "contract proto files", 8, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(ContractPackage), nil
	})
	for _, v := range enumBoundViolations(files) {
		t.Errorf("%s (G-1 enum half, SPEC-003)", v)
	}
}

// TestGuard_EnumBounds_Liveness: the carrier's untagged enum field flags;
// its fully-tagged sibling stays clean.
func TestGuard_EnumBounds_Liveness(t *testing.T) {
	files := Discover(t, "fixture proto files", 1, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(fixturePackage), nil
	})
	got := enumBoundViolations(files)
	if len(got) != 1 || !strings.HasPrefix(got[0], "powermanage.fixture.v1.FixtureEnumCarrier.untagged_enum:") {
		t.Fatalf("fixture violations = %v, want exactly the planted untagged_enum", got)
	}
	for _, g := range got {
		if strings.HasPrefix(g, "powermanage.fixture.v1.FixtureEnumCarrier.tagged_enum:") {
			t.Errorf("guard flagged %q — the bound pair is the conforming form", g)
		}
	}
}

// TestAction_Shape pins the one action shape ([WIRE-13], plan choice 3):
// exactly {id, name, params} with the recorded tags — enrichment composes
// around this shape, never onto it.
func TestAction_Shape(t *testing.T) {
	action, err := findRegistry(packageFiles(ContractPackage), "Action")
	if err != nil {
		t.Fatalf("Action message: %v", err)
	}
	fields := action.Fields()
	var names []string
	for i := 0; i < fields.Len(); i++ {
		names = append(names, string(fields.Get(i).Name()))
	}
	sort.Strings(names)
	want := []string{"id", "name", "params"}
	if len(names) != len(want) {
		t.Fatalf("Action fields = %v, want exactly %v — enrichment is composition, not new fields [WIRE-13]", names, want)
	}
	for i, w := range want {
		if names[i] != w {
			t.Fatalf("Action fields = %v, want exactly %v", names, want)
		}
	}
	rulesOf := func(name protoreflect.Name) *validate.FieldRules {
		f := fields.ByName(name)
		rules, _ := proto.GetExtension(f.Options(), validate.E_Field).(*validate.FieldRules)
		return rules
	}
	if ulid, _ := proto.GetExtension(rulesOf("id").GetString(), powermanagev1.E_Ulid).(bool); !ulid {
		t.Errorf("Action.id does not carry the predefined ULID rule [WIRE-5]")
	}
	nameRules := rulesOf("name").GetString()
	if nameRules.GetMinLen() != 1 || nameRules.GetMaxLen() != 200 {
		t.Errorf("Action.name rules = min_len %d, max_len %d; want 1 and 200 (plan choice 3)", nameRules.GetMinLen(), nameRules.GetMaxLen())
	}
	if !rulesOf("params").GetRequired() {
		t.Errorf("Action.params must be required — an action without params is untyped surface")
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
