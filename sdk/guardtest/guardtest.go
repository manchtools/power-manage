// Package guardtest is the guard harness of SPEC-000 (M2): discovery with
// matches-zero protection and the liveness-fixture pattern. Every guard in
// this repository enumerates its subjects through Discover — a guard whose
// discovery returns nothing must fail, because an empty result means the
// discovery broke, not that the codebase is clean.
package guardtest

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// Discover runs discover and returns its subjects. It fails t when discovery
// errors or yields fewer than floor subjects (matches-zero protection,
// SPEC-000 [PROC-3]). floor is the guard's known-population minimum and must
// be at least 1.
func Discover[T any](t testing.TB, desc string, floor int, discover func() ([]T, error)) []T {
	t.Helper()
	if floor < 1 {
		t.Fatalf("guardtest.Discover(%q): floor %d < 1 — a guard without a matches-zero floor fails open", desc, floor)
		return nil
	}
	subjects, err := discover()
	if err != nil {
		t.Fatalf("guard discovery %q failed: %v", desc, err)
		return nil
	}
	if len(subjects) < floor {
		t.Fatalf("guard discovery %q found %d subject(s), floor is %d — the discovery broke or the convention moved; fix the discovery, never lower the floor without a spec change", desc, len(subjects), floor)
		return nil
	}
	return subjects
}

// RequireViolation proves a guard can still go red: scanning fixtureRoot —
// which contains a deliberate violation — must report at least one finding
// (liveness, SPEC-000 [PROC-3]).
func RequireViolation(t testing.TB, name string, scan func(root string) ([]string, error), fixtureRoot string) {
	t.Helper()
	violations, err := scan(fixtureRoot)
	if err != nil {
		t.Fatalf("liveness scan for guard %q over %s failed: %v", name, fixtureRoot, err)
		return
	}
	if len(violations) == 0 {
		t.Fatalf("liveness fixture for guard %q reported no violations from %s — the guard can no longer go red; fix the guard, not the fixture", name, fixtureRoot)
	}
}

// RepoRoot returns the repository root, found by walking up from the test's
// working directory to the directory holding go.work.
func RepoRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("guardtest.RepoRoot: getwd: %v", err)
		return ""
	}
	for {
		_, err := os.Stat(filepath.Join(dir, "go.work"))
		if err == nil {
			return dir
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("guardtest.RepoRoot: stat %s/go.work: %v", dir, err)
			return ""
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("guardtest.RepoRoot: no go.work found walking up from the working directory — run guards from inside the repository")
			return ""
		}
		dir = parent
	}
}
