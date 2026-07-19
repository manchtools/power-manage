package guardtest

import (
	"strings"
	"testing"
)

// requireFlagged asserts the exact violation set: exactly one violation per
// wanted locator, no extras (an overmatching scan must not stay green), and
// nothing at any mustNotFlag locator. Locators are "path" or "path:line"
// prefixes of the "path:line: message" violation form — matched on the
// colon boundary, so "bad.go:1" cannot match bad.go:10 or aliased_bad.go.
func requireFlagged(t *testing.T, violations []string, want []string, mustNotFlag []string) {
	t.Helper()
	at := func(v, locator string) bool { return strings.HasPrefix(v, locator+":") }
	for _, w := range want {
		matches := 0
		for _, v := range violations {
			if at(v, w) {
				matches++
			}
		}
		if matches != 1 {
			t.Errorf("want exactly one violation at %q, got %d (%v) — a miss means the scan can no longer go red, extras mean it overmatches", w, matches, violations)
		}
	}
	if len(violations) != len(want) {
		t.Errorf("violation count = %d, want %d — unexpected extras or misses: got %v, want %v", len(violations), len(want), violations, want)
	}
	for _, n := range mustNotFlag {
		for _, v := range violations {
			if at(v, n) {
				t.Errorf("%q was flagged (%q) — the scan matches names, not resolved imports", n, v)
			}
		}
	}
}

func TestBannedCalls_ClockFixture(t *testing.T) {
	RequireViolation(t, "time.Now ban", func(root string) ([]string, error) {
		return BannedCalls(root, "time", "Now")
	}, "testdata/astban/clock")

	v, err := BannedCalls("testdata/astban/clock", "time", "Now")
	if err != nil {
		t.Fatalf("scanning the clock fixture: %v", err)
	}
	// bad.go plants two call sites (plain + inside SetDeadline), the alias
	// and dot-import files one more each; clean.go and the decoy alias must
	// stay unflagged.
	requireFlagged(t, v, []string{"bad.go:10", "bad.go:13", "aliased_bad.go:6", "dot_bad.go:6"}, []string{"decoy.go", "clean.go"})
}

func TestBannedCalls_CtxBackgroundFixture(t *testing.T) {
	RequireViolation(t, "context.Background ban", func(root string) ([]string, error) {
		return BannedCalls(root, "context", "Background")
	}, "testdata/astban/ctxbg")

	v, err := BannedCalls("testdata/astban/ctxbg", "context", "Background")
	if err != nil {
		t.Fatalf("scanning the ctxbg fixture: %v", err)
	}
	requireFlagged(t, v, []string{"bad.go:7"}, []string{"clean.go"})
}

func TestBannedCalls_GenericInstantiationFixture(t *testing.T) {
	RequireViolation(t, "generic-call ban", func(root string) ([]string, error) {
		return BannedCalls(root, "example.com/registry", "Make")
	}, "testdata/astban/generic")

	v, err := BannedCalls("testdata/astban/generic", "example.com/registry", "Make")
	if err != nil {
		t.Fatalf("scanning the generic fixture: %v", err)
	}
	// IndexExpr (one type arg) and IndexListExpr (two) call sites; the
	// same package's other symbol stays unflagged.
	requireFlagged(t, v, []string{"bad.go:8", "bad.go:10"}, []string{"clean.go"})
}

func TestBannedImports_MathRandFixture(t *testing.T) {
	RequireViolation(t, "math/rand ban", func(root string) ([]string, error) {
		return BannedImports(root, "math/rand")
	}, "testdata/astban/mathrand")

	v, err := BannedImports("testdata/astban/mathrand", "math/rand")
	if err != nil {
		t.Fatalf("scanning the mathrand fixture: %v", err)
	}
	requireFlagged(t, v, []string{"bad.go", "jitter/jitter.go"}, []string{"clean.go"})
}

func TestBannedImports_AllowlistHonored(t *testing.T) {
	v, err := BannedImports("testdata/astban/mathrand", "math/rand", "jitter")
	if err != nil {
		t.Fatalf("scanning the mathrand fixture: %v", err)
	}
	requireFlagged(t, v, []string{"bad.go"}, []string{"jitter/jitter.go"})
}

func TestBannedImports_ProtojsonFixture(t *testing.T) {
	RequireViolation(t, "encoding/json ban", func(root string) ([]string, error) {
		return BannedImports(root, "encoding/json")
	}, "testdata/astban/protojson")

	v, err := BannedImports("testdata/astban/protojson", "encoding/json")
	if err != nil {
		t.Fatalf("scanning the protojson fixture: %v", err)
	}
	requireFlagged(t, v, []string{"bad.go"}, []string{"clean.go"})
}

func TestSentinelComparisons_Fixture(t *testing.T) {
	sentinels := map[string][]string{"database/sql": {"ErrNoRows"}}
	RequireViolation(t, "sentinel-comparison ban", func(root string) ([]string, error) {
		return SentinelComparisons(root, sentinels)
	}, "testdata/astban/sentinel")

	v, err := SentinelComparisons("testdata/astban/sentinel", sentinels)
	if err != nil {
		t.Fatalf("scanning the sentinel fixture: %v", err)
	}
	// errors.Is, ==, != in bad.go plus the aliased and dot-imported
	// errors.Is — the clean recognizer call must stay unflagged.
	requireFlagged(t, v, []string{"bad.go:11", "bad.go:13", "bad.go:15", "aliased_bad.go:9", "dot_bad.go:10"}, []string{"clean.go"})
}

func TestEnumSwitches_Fixture(t *testing.T) {
	prefixes := []string{"example.com/gen/"}
	RequireViolation(t, "enum erroring-default", func(root string) ([]string, error) {
		return EnumSwitchesWithoutErroringDefault(root, prefixes)
	}, "testdata/astban/enumdefault")

	v, err := EnumSwitchesWithoutErroringDefault("testdata/astban/enumdefault", prefixes)
	if err != nil {
		t.Fatalf("scanning the enumdefault fixture: %v", err)
	}
	// The no-default switch, the non-erroring-default switch, and the
	// return-only-inside-a-closure switch are violations; the erroring
	// switch and the non-enum switch are clean.
	requireFlagged(t, v, []string{"bad.go:11", "bad.go:24", "bad.go:36"}, []string{"clean.go"})
}
