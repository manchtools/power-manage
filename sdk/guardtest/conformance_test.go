package guardtest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
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
		// The harness package's own files call the helpers unqualified;
		// everywhere else the call must resolve through an import of the
		// real harness path.
		inHarnessPkg := file.Name.Name == "guardtest" &&
			strings.HasPrefix(filepath.ToSlash(rel), "sdk/guardtest/")
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "TestGuard_") {
				continue
			}
			id := rel + ":" + fn.Name.Name
			all = append(all, id)
			if !callsHarness(file, fn, inHarnessPkg) {
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

const guardtestImportPath = "github.com/manchtools/power-manage/sdk/guardtest"

// harnessRefs returns the local identifiers through which file can reach the
// real harness: names bound to an import of guardtestImportPath, and whether
// a dot-import makes unqualified calls resolve to it.
func harnessRefs(file *ast.File) (names map[string]bool, dotImported bool) {
	names = map[string]bool{}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != guardtestImportPath {
			// An unquotable path literal cannot be the harness import;
			// either way this import is not a harness ref.
			continue
		}
		switch {
		case imp.Name == nil:
			names["guardtest"] = true
		case imp.Name.Name == ".":
			dotImported = true
		default:
			names[imp.Name.Name] = true
		}
	}
	return names, dotImported
}

// callsHarness reports whether fn's body calls a harness helper that
// actually resolves to this package — a same-named helper from an unrelated
// import or a shadowing local declaration does not count (G-000-3 would
// otherwise be bypassable by naming).
func callsHarness(file *ast.File, fn *ast.FuncDecl, inHarnessPkg bool) bool {
	if fn.Body == nil {
		return false
	}
	names, dotImported := harnessRefs(file)
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			// ponytail: a dot-import shadowed by a local decl would still
			// pass this syntactic check; move to type-checked resolution
			// if that ever bites.
			if (inHarnessPkg || dotImported) && (fun.Name == "Discover" || fun.Name == "RequireViolation") {
				found = true
			}
		case *ast.SelectorExpr:
			pkg, ok := fun.X.(*ast.Ident)
			if ok && names[pkg.Name] && (fun.Sel.Name == "Discover" || fun.Sel.Name == "RequireViolation") {
				found = true
			}
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
// fixtures under testdata/liveness plant every known bypass — no harness
// call at all, a same-named helper from an unrelated import, a shadowing
// local declaration — and the scan must flag each, while the conforming
// fixture stays clean.
func TestGuardAPIConformance_Liveness(t *testing.T) {
	_, bad, err := guardInventory("testdata/liveness")
	if err != nil {
		t.Fatalf("scanning the liveness fixture failed: %v", err)
	}
	flagged := func(name string) bool {
		for _, g := range bad {
			if strings.HasSuffix(g, ":"+name) {
				return true
			}
		}
		return false
	}
	for _, planted := range []string{"TestGuard_Fixture", "TestGuard_UnrelatedImport", "TestGuard_Shadowed"} {
		if !flagged(planted) {
			t.Errorf("planted non-conforming guard %s was not flagged (got %v) — G-000-3 can no longer go red against this bypass", planted, bad)
		}
	}
	if flagged("TestGuard_Conforming") {
		t.Errorf("the conforming fixture guard was flagged (got %v) — the checker went always-red", bad)
	}
}
