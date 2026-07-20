package archtest

import (
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

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
	files := Discover(t, "contract proto files", 7, func() ([]protoreflect.FileDescriptor, error) {
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
	files := Discover(t, "contract proto files", 7, func() ([]protoreflect.FileDescriptor, error) {
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
	es := enums(files)
	if len(es) != 2 {
		t.Fatalf("enums = %d, want the two fixture enums", len(es))
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
