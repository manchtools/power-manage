package guardtest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nestedModuleViolations returns every test-bearing package under root whose
// owning module is NOT a depth-1 directory of root — exactly the packages
// verify.sh's `*/go.mod` walk (and therefore CI) can never reach. A
// test-bearing package with no owning module at all is equally a violation.
func nestedModuleViolations(root string) ([]string, error) {
	pkgs, err := testBearingPackages(root)
	if err != nil {
		return nil, err
	}
	var violations []string
	for _, pkg := range pkgs {
		mod, err := owningModule(root, pkg)
		if err != nil {
			return nil, err
		}
		relPkg, rerr := filepath.Rel(root, pkg)
		if rerr != nil {
			return nil, fmt.Errorf("rel %s: %w", pkg, rerr)
		}
		relPkg = filepath.ToSlash(relPkg)
		if mod == "" {
			violations = append(violations, relPkg+": test-bearing package with no owning go.mod")
			continue
		}
		relMod, rerr := filepath.Rel(root, mod)
		if rerr != nil {
			return nil, fmt.Errorf("rel %s: %w", mod, rerr)
		}
		relMod = filepath.ToSlash(relMod)
		if relMod == "." || strings.Contains(relMod, "/") {
			violations = append(violations, fmt.Sprintf("%s: owning module %s is not a depth-1 directory, so verify.sh's `*/go.mod` walk never tests it", relPkg, relMod))
		}
	}
	return violations, nil
}

// owningModule walks up from dir (staying at or below root) and returns the
// first directory holding a go.mod, or "" if none.
func owningModule(root, dir string) (string, error) {
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("stat %s/go.mod: %w", dir, err)
		}
		if dir == root {
			return "", nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil
		}
		dir = parent
	}
}

// testBearingPackages returns every directory under root containing at least
// one *_test.go file (testdata and hidden directories skipped).
func testBearingPackages(root string) ([]string, error) {
	var pkgs []string
	seen := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != root && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		if dir := filepath.Dir(path); !seen[dir] {
			seen[dir] = true
			pkgs = append(pkgs, dir)
		}
		return nil
	})
	return pkgs, err
}

// workflowRunsVerify reports whether some workflow under .github/workflows
// runs scripts/verify.sh on pull_request.
// ponytail: text-level match, not YAML parsing — a workflow that mentions
// both without wiring them would slip through; parse YAML if that ever bites.
func workflowRunsVerify(root string) (bool, error) {
	files, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.y*ml"))
	if err != nil {
		return false, fmt.Errorf("listing workflows: %w", err)
	}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			return false, fmt.Errorf("reading %s: %w", f, err)
		}
		if strings.Contains(string(body), "scripts/verify.sh") && strings.Contains(string(body), "pull_request") {
			return true, nil
		}
	}
	return false, nil
}

// TestGuard_CILaneCompleteness is G-000-2 (SPEC-000 [TEST-3]): every
// test-bearing package must be reachable by the CI lane. The lane is
// workflow → scripts/verify.sh → depth-1 module walk → `go test ./...`, so
// the guard proves each link: at least one test-bearing package exists, none
// lives outside a depth-1 module, and a workflow runs the gate on PRs.
func TestGuard_CILaneCompleteness(t *testing.T) {
	root := RepoRoot(t)
	Discover(t, "test-bearing packages", 1, func() ([]string, error) {
		return testBearingPackages(root)
	})
	violations, err := nestedModuleViolations(root)
	if err != nil {
		t.Fatalf("scanning for unreachable packages: %v", err)
	}
	for _, v := range violations {
		t.Errorf("%s — CI never runs these tests; move the package into a depth-1 module or extend the gate first", v)
	}
	ok, err := workflowRunsVerify(root)
	if err != nil {
		t.Fatalf("reading workflows: %v", err)
	}
	if !ok {
		t.Error("no workflow under .github/workflows runs scripts/verify.sh on pull_request — the gate is not wired to CI (AC-2)")
	}
}

// TestCILane_Liveness: the fixture plants a test-bearing package inside a
// nested (depth-2) module — invisible to the verify.sh walk — next to a
// conforming depth-1 module. The scan must flag exactly the nested one.
func TestCILane_Liveness(t *testing.T) {
	violations, err := nestedModuleViolations("testdata/cilane")
	if err != nil {
		t.Fatalf("scanning the cilane fixture failed: %v", err)
	}
	foundNested := false
	for _, v := range violations {
		if strings.Contains(v, "tools/helper") {
			foundNested = true
		}
		if strings.Contains(v, "goodmod") {
			t.Errorf("depth-1 fixture module was flagged (%q) — the scan went always-red", v)
		}
	}
	if !foundNested {
		t.Fatalf("planted nested-module package tools/helper was not flagged (got %v) — G-000-2 can no longer go red", violations)
	}
}
