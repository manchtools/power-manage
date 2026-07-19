package guardtest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recordTB captures a harness helper's failure instead of aborting, so the
// tests can observe it. Embedding testing.TB satisfies the interface's
// unexported method. Load-bearing constraint: harness helpers fail via
// Fatalf ONLY — any other failure method would fall through to the real
// *testing.T instead of being recorded here.
type recordTB struct {
	testing.TB
	failed bool
	last   string
}

func (r *recordTB) Helper() {}

func (r *recordTB) Fatalf(format string, args ...any) {
	r.failed = true
	r.last = fmt.Sprintf(format, args...)
}

func TestDiscover_EmptyDiscoveryFails(t *testing.T) {
	rec := &recordTB{TB: t}
	got := Discover(rec, "empty-population", 1, func() ([]string, error) { return nil, nil })
	if !rec.failed {
		t.Fatal("Discover accepted an empty subject set — matches-zero protection is missing")
	}
	if !strings.Contains(rec.last, "floor") {
		t.Fatalf("failure message must name the floor so the tripping session knows what broke, got: %q", rec.last)
	}
	if got != nil {
		t.Fatalf("Discover returned subjects after failing: %v", got)
	}
}

func TestDiscover_FloorBelowOneFails(t *testing.T) {
	rec := &recordTB{TB: t}
	got := Discover(rec, "no-floor", 0, func() ([]string, error) { return []string{"a"}, nil })
	if !rec.failed {
		t.Fatal("Discover accepted floor 0 — a guard could disable its own matches-zero protection")
	}
	if !strings.Contains(rec.last, "floor") {
		t.Fatalf("failure message must name the floor, got: %q", rec.last)
	}
	if got != nil {
		t.Fatalf("Discover returned subjects after failing: %v", got)
	}
}

func TestDiscover_BelowFloorFails(t *testing.T) {
	rec := &recordTB{TB: t}
	Discover(rec, "modules", 4, func() ([]string, error) { return []string{"a", "b", "c"}, nil })
	if !rec.failed {
		t.Fatal("Discover accepted 3 subjects against a floor of 4")
	}
	if !strings.Contains(rec.last, "3") || !strings.Contains(rec.last, "4") {
		t.Fatalf("failure message must state found count and floor, got: %q", rec.last)
	}
}

func TestDiscover_DiscoveryErrorFails(t *testing.T) {
	rec := &recordTB{TB: t}
	got := Discover(rec, "broken-walk", 1, func() ([]string, error) { return nil, errors.New("walk exploded") })
	if !rec.failed {
		t.Fatal("Discover swallowed a discovery error — fail-open")
	}
	if !strings.Contains(rec.last, "walk exploded") {
		t.Fatalf("failure message must carry the discovery error, got: %q", rec.last)
	}
	if got != nil {
		t.Fatalf("Discover returned subjects after an error: %v", got)
	}
}

func TestDiscover_FloorMetReturnsSubjects(t *testing.T) {
	rec := &recordTB{TB: t}
	got := Discover(rec, "ok", 2, func() ([]string, error) { return []string{"x", "y"}, nil })
	if rec.failed {
		t.Fatalf("Discover failed on a satisfied floor: %q", rec.last)
	}
	if len(got) != 2 {
		t.Fatalf("Discover returned %d subjects, want 2", len(got))
	}
}

func TestRequireViolation_PlantedViolationPasses(t *testing.T) {
	rec := &recordTB{TB: t}
	RequireViolation(rec, "some-guard", func(root string) ([]string, error) {
		return []string{root + ": planted violation"}, nil
	}, "fixture-root")
	if rec.failed {
		t.Fatalf("RequireViolation failed although the violation was detected: %q", rec.last)
	}
}

func TestRequireViolation_CleanScanFails(t *testing.T) {
	rec := &recordTB{TB: t}
	RequireViolation(rec, "some-guard", func(root string) ([]string, error) { return nil, nil }, "fixture-root")
	if !rec.failed {
		t.Fatal("RequireViolation accepted a scan that no longer detects the planted violation — the guard could silently lose its ability to go red")
	}
	if !strings.Contains(rec.last, "red") {
		t.Fatalf("failure message must say the guard can no longer go red, got: %q", rec.last)
	}
}

func TestRequireViolation_ScanErrorFails(t *testing.T) {
	rec := &recordTB{TB: t}
	RequireViolation(rec, "some-guard", func(root string) ([]string, error) { return nil, errors.New("scan exploded") }, "fixture-root")
	if !rec.failed {
		t.Fatal("RequireViolation swallowed a scan error")
	}
	if !strings.Contains(rec.last, "scan exploded") {
		t.Fatalf("failure message must carry the scan error, got: %q", rec.last)
	}
}

func TestRepoRoot_FindsGoWorkRoot(t *testing.T) {
	root := RepoRoot(t)
	if root == "" {
		t.Fatal("RepoRoot returned an empty path")
	}
	if _, err := os.Stat(filepath.Join(root, "go.work")); err != nil {
		t.Fatalf("RepoRoot = %q, but it holds no go.work: %v", root, err)
	}
}
