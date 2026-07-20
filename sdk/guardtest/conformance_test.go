package guardtest

import (
	"go/ast"
	"go/token"
	"os"
	"path"
	"path/filepath"
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
		// The harness packages' own files call the helpers unqualified;
		// everywhere else the call must resolve through an import of a
		// sanctioned harness path. Exact-directory match: a nested package
		// reusing the name (contract/archtest/x declaring package archtest)
		// must not inherit the unqualified-call privilege.
		inHarnessPkg := (file.Name.Name == "guardtest" &&
			path.Dir(rel) == "sdk/guardtest") ||
			(file.Name.Name == "archtest" &&
				path.Dir(rel) == "contract/archtest")
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

// The sanctioned guard harnesses. contract/archtest is a second, minimal
// harness because the import direction is one-way both ways (INV-19):
// contract cannot import sdk/guardtest, and sdk cannot link the generated
// descriptors that contract's guards walk.
var harnessImportPaths = []string{
	"github.com/manchtools/power-manage/sdk/guardtest",
	"github.com/manchtools/power-manage/contract/archtest",
}

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
	names := map[string]bool{}
	dotImported := false
	for _, p := range harnessImportPaths {
		n, d := importAliases(file, p)
		for alias := range n {
			names[alias] = true
		}
		dotImported = dotImported || d
	}
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
	for _, conforming := range []string{"TestGuard_Conforming", "TestGuard_ViaArchtest"} {
		if flagged(conforming) {
			t.Errorf("the conforming fixture guard %s was flagged (got %v) — the checker went always-red", conforming, bad)
		}
	}
}

// TestGuardAPIConformance_NestedPackageSpoof: a nested package reusing a
// harness package name (contract/archtest/spoofdir declaring package
// archtest with a local no-op Discover) must NOT inherit the
// unqualified-call privilege — only files in the harness directory itself
// do. Built on a temp tree because committing such a spoof would rightly
// trip the real guard. Regression for the prefix-match bypass.
func TestGuardAPIConformance_NestedPackageSpoof(t *testing.T) {
	root := t.TempDir()
	spoofBody := `func Discover[T any](t testing.TB, what string, floor int, fn func() ([]T, error)) []T {
	t.Helper()
	return nil
}
`
	for relFile, src := range map[string]string{
		// In-harness file at the exact directory: unqualified call accepted.
		"sdk/guardtest/real_test.go": "package guardtest\n\nimport \"testing\"\n\nfunc TestGuard_Real(t *testing.T) {\n\tDiscover(t, \"x\", 1, func() ([]string, error) { return []string{\"s\"}, nil })\n}\n",
		// Nested spoofs: same package name, one directory deeper.
		"sdk/guardtest/nested/spoof_test.go":       "package guardtest\n\nimport \"testing\"\n\n" + spoofBody + "\nfunc TestGuard_Spoof(t *testing.T) {\n\tDiscover(t, \"x\", 1, func() ([]string, error) { return nil, nil })\n}\n",
		"contract/archtest/spoofdir/spoof_test.go": "package archtest\n\nimport \"testing\"\n\n" + spoofBody + "\nfunc TestGuard_ArchSpoof(t *testing.T) {\n\tDiscover(t, \"x\", 1, func() ([]string, error) { return nil, nil })\n}\n",
	} {
		full := filepath.Join(root, filepath.FromSlash(relFile))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	all, bad, _, err := guardInventory(root)
	if err != nil {
		t.Fatalf("scanning the spoof tree failed: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("inventory found %v, want the three planted guards", all)
	}
	flagged := func(name string) bool {
		for _, g := range bad {
			if strings.HasSuffix(g, ":"+name) {
				return true
			}
		}
		return false
	}
	for _, spoof := range []string{"TestGuard_Spoof", "TestGuard_ArchSpoof"} {
		if !flagged(spoof) {
			t.Errorf("nested-package spoof %s was accepted as conforming (bad=%v) — harness recognition regressed to a prefix match", spoof, bad)
		}
	}
	if flagged("TestGuard_Real") {
		t.Errorf("the exact-directory harness file was flagged (bad=%v) — the checker went always-red for the harness itself", bad)
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
