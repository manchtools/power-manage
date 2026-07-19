package guardtest

import (
	"go/ast"
	"go/token"
	"regexp"
	"strings"
	"testing"
)

// guardInventory walks root for *_test.go files (skipping testdata and hidden
// directories), parses each, and returns every TestGuard_* function it finds,
// the subset that never calls a harness helper (Discover or
// RequireViolation), and the invariant registrations extracted from
// "Guards: INV-n[, INV-m]" doc-comment lines (SPEC-000 AC-5 — registration
// is co-located with the guard). Entries are "relpath:FuncName".
func guardInventory(root string) (all, bad []string, guardsByInv map[string][]string, err error) {
	guardsByInv = map[string][]string{}
	err = walkGoFiles(root, true, func(rel string, _ *token.FileSet, file *ast.File) error {
		// The harness package's own files call the helpers unqualified;
		// everywhere else the call must resolve through an import of the
		// real harness path.
		inHarnessPkg := file.Name.Name == "guardtest" &&
			strings.HasPrefix(rel, "sdk/guardtest/")
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "TestGuard_") {
				continue
			}
			id := rel + ":" + fn.Name.Name
			all = append(all, id)
			if !callsHarness(file, fn, inHarnessPkg) {
				// A non-conforming guard has no matches-zero protection, so
				// its registrations must not satisfy G-000-1 coverage.
				bad = append(bad, id)
				continue
			}
			for _, inv := range guardRegistrations(fn.Doc) {
				guardsByInv[inv] = append(guardsByInv[inv], id)
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return all, bad, guardsByInv, nil
}

const guardtestImportPath = "github.com/manchtools/power-manage/sdk/guardtest"

var guardsLineRe = regexp.MustCompile(`^Guards: ((?:INV|TM)-\d+(?:, (?:INV|TM)-\d+)*)\.?$`)

// guardRegistrations extracts the invariant IDs from a guard's
// "Guards: INV-n[, INV-m]." doc-comment line, if any. The registration must
// be a single unwrapped line exactly in that form — a wrapped or reformatted
// line is not extracted and surfaces as a missing guard (fail-closed).
func guardRegistrations(doc *ast.CommentGroup) []string {
	if doc == nil {
		return nil
	}
	for _, line := range strings.Split(doc.Text(), "\n") {
		if m := guardsLineRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			return strings.Split(strings.ReplaceAll(m[1], " ", ""), ",")
		}
	}
	return nil
}

// callsHarness reports whether fn's body calls a harness helper that
// actually resolves to this package — a same-named helper from an unrelated
// import or a shadowing local declaration does not count (G-000-3 would
// otherwise be bypassable by naming). Import resolution is shared with the
// AST-guard library (importAliases, astban.go).
func callsHarness(file *ast.File, fn *ast.FuncDecl, inHarnessPkg bool) bool {
	if fn.Body == nil {
		return false
	}
	names, dotImported := importAliases(file, guardtestImportPath)
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
		all, b, _, err := guardInventory(root)
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
	_, bad, _, err := guardInventory("testdata/liveness")
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

// TestGuardInventory_ExtractsRegistrations: the "Guards: INV-n" doc-comment
// line on the conforming fixture guard must surface as a registration.
func TestGuardInventory_ExtractsRegistrations(t *testing.T) {
	_, _, guardsByInv, err := guardInventory("testdata/liveness")
	if err != nil {
		t.Fatalf("scanning the liveness fixture failed: %v", err)
	}
	found := false
	for _, g := range guardsByInv["INV-19"] {
		if strings.HasSuffix(g, ":TestGuard_Conforming") {
			found = true
		}
	}
	if !found {
		t.Fatalf("fixture guard's 'Guards: INV-19.' registration was not extracted, got %v", guardsByInv)
	}
	if regs := guardsByInv["INV-12"]; len(regs) != 0 {
		t.Fatalf("the NON-conforming fixture guard's 'Guards: INV-12.' line was counted (%v) — a guard without matches-zero protection must not satisfy G-000-1 coverage", regs)
	}
	found = false
	for _, g := range guardsByInv["TM-3"] {
		if strings.HasSuffix(g, ":TestGuard_ConformingTM") {
			found = true
		}
	}
	if !found {
		t.Fatalf("fixture guard's 'Guards: TM-3.' registration was not extracted, got %v — trust-model rows (SPEC-001 M3) are registered through the same grammar", guardsByInv)
	}
}
