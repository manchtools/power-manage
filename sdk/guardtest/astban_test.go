package guardtest

import (
	"strings"
	"testing"
)

// requireFlagged asserts that for every wanted substring exactly the
// violations containing it are present, and that nothing matches any of
// the mustNotFlag substrings.
func requireFlagged(t *testing.T, violations []string, want []string, mustNotFlag []string) {
	t.Helper()
	for _, w := range want {
		found := false
		for _, v := range violations {
			if strings.Contains(v, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("planted violation %q was not flagged (got %v) — the scan can no longer go red against it", w, violations)
		}
	}
	for _, n := range mustNotFlag {
		for _, v := range violations {
			if strings.Contains(v, n) {
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
	// file one more; clean.go and the decoy alias must stay unflagged.
	requireFlagged(t, v, []string{"bad.go:10", "bad.go:13", "aliased_bad.go:6"}, []string{"decoy.go", "clean.go"})
}

func TestBannedCalls_CtxBackgroundFixture(t *testing.T) {
	v, err := BannedCalls("testdata/astban/ctxbg", "context", "Background")
	if err != nil {
		t.Fatalf("scanning the ctxbg fixture: %v", err)
	}
	requireFlagged(t, v, []string{"bad.go:7"}, []string{"clean.go"})
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
	// errors.Is, ==, != in bad.go plus the aliased errors.Is — the clean
	// recognizer call must stay unflagged.
	requireFlagged(t, v, []string{"bad.go:11", "bad.go:13", "bad.go:15", "aliased_bad.go:9"}, []string{"clean.go"})
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
	// The no-default switch and the non-erroring-default switch are both
	// violations; the erroring switch and the non-enum switch are clean.
	requireFlagged(t, v, []string{"bad.go:11", "bad.go:24"}, []string{"clean.go"})
}
