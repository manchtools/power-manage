package guardtest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// guardInventory walks root for *_test.go files (skipping testdata and hidden
// directories), parses each, and returns every TestGuard_* function it finds
// plus the subset that never calls a harness helper (Discover or
// RequireViolation). Entries are "relpath:FuncName".
func guardInventory(root string) (all, bad []string, err error) {
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			// The fixture root itself may live under a testdata directory;
			// only descents below root are pruned.
			if path != root && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return fmt.Errorf("rel %s: %w", path, rerr)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "TestGuard_") {
				continue
			}
			id := rel + ":" + fn.Name.Name
			all = append(all, id)
			if !callsHarness(fn) {
				bad = append(bad, id)
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return all, bad, nil
}

// callsHarness reports whether fn's body contains a call to a harness helper,
// qualified (guardtest.Discover) or not (Discover, inside this package).
func callsHarness(fn *ast.FuncDecl) bool {
	if fn.Body == nil {
		return false
	}
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		if name == "Discover" || name == "RequireViolation" {
			found = true
		}
		return !found
	})
	return found
}

// TestGuard_GuardAPIConformance is G-000-3 (SPEC-000): every guard in the
// repository goes through the harness — a guard with a hand-rolled discovery
// loses matches-zero protection without anyone noticing.
func TestGuard_GuardAPIConformance(t *testing.T) {
	root := RepoRoot(t)
	var bad []string
	Discover(t, "TestGuard_* functions in the repository", 1, func() ([]string, error) {
		all, b, err := guardInventory(root)
		bad = b
		return all, err
	})
	for _, g := range bad {
		t.Errorf("guard %s never calls guardtest.Discover or guardtest.RequireViolation — every guard enumerates its subjects through the harness (G-000-3, SPEC-000); wire it through guardtest", g)
	}
}

// TestGuardAPIConformance_Liveness proves G-000-3 can still go red: the
// fixture under testdata/liveness contains a deliberately non-conforming
// guard that the scan must flag.
func TestGuardAPIConformance_Liveness(t *testing.T) {
	_, bad, err := guardInventory("testdata/liveness")
	if err != nil {
		t.Fatalf("scanning the liveness fixture failed: %v", err)
	}
	found := false
	for _, g := range bad {
		if strings.HasSuffix(g, "TestGuard_Fixture") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the planted non-conforming guard TestGuard_Fixture was not flagged (got %v) — G-000-3 can no longer go red", bad)
	}
}
