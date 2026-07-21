package guardtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// backendLaneNames discovers the canonical package-manager backend names from
// the Backend.String() method in sdk/pkg — the same source the runtime resolves
// names through — so the expected lane set is never a hand-maintained list that
// can silently drift from the enum. A new backend adds a String case, which
// this scan picks up, which forces its CI container lane below.
func backendLaneNames(t *testing.T, root string) []string {
	t.Helper()
	src := filepath.Join(root, "sdk", "pkg", "pkg.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}
	var names []string
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "String" || fn.Recv == nil || len(fn.Recv.List) != 1 {
			return true
		}
		id, ok := fn.Recv.List[0].Type.(*ast.Ident)
		if !ok || id.Name != "Backend" {
			return true
		}
		ast.Inspect(fn.Body, func(m ast.Node) bool {
			cc, ok := m.(*ast.CaseClause)
			if !ok || len(cc.List) == 0 { // skip the default sentinel case
				return true
			}
			for _, stmt := range cc.Body {
				ret, ok := stmt.(*ast.ReturnStmt)
				if !ok || len(ret.Results) != 1 {
					continue
				}
				lit, ok := ret.Results[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if v, err := strconv.Unquote(lit.Value); err == nil {
					names = append(names, v)
				}
			}
			return true
		})
		return false
	})
	sort.Strings(names)
	return names
}

func packageManagerLaneBackends(workflow string) []string {
	var backends []string
	inJob := false
	inInclude := false
	for _, raw := range strings.Split(workflow, "\n") {
		trimmed := strings.TrimSpace(raw)
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if indent == 2 {
			inJob = trimmed == "package-managers:"
			inInclude = false
			continue
		}
		if !inJob {
			continue
		}
		if indent == 8 && trimmed == "include:" {
			inInclude = true
			continue
		}
		if inInclude && indent <= 8 && trimmed != "" {
			inInclude = false
		}
		if !inInclude {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimSpace(strings.TrimPrefix(trimmed, "-")), ":")
		if !ok || strings.TrimSpace(key) != "backend" {
			continue
		}
		backends = append(backends, strings.Trim(strings.TrimSpace(value), `"'`))
	}
	sort.Strings(backends)
	return backends
}

func TestPackageManagerLaneBackends_Liveness(t *testing.T) {
	workflow := "jobs:\n  unrelated:\n    backend: ignored\n  package-managers:\n    strategy:\n      matrix:\n        include:\n          - backend: apt\n          - backend: dnf\n    steps: []\n"
	got := packageManagerLaneBackends(workflow)
	if want := []string{"apt", "dnf"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := packageManagerLaneBackends("jobs: {}\n"); len(got) != 0 {
		t.Fatalf("empty workflow discovered %v", got)
	}
}

func TestGuard_PackageManagerLaneParity(t *testing.T) {
	root := RepoRoot(t)
	want := backendLaneNames(t, root)
	if len(want) == 0 {
		t.Fatal("discovered zero backend names from Backend.String()")
	}
	workflows := Discover(t, "package-manager CI workflow", 1, func() ([]string, error) {
		path := filepath.Join(root, ".github", "workflows", "ci.yml")
		if _, err := os.Stat(path); err != nil {
			return nil, err
		}
		return []string{path}, nil
	})
	workflow, err := os.ReadFile(workflows[0])
	if err != nil {
		t.Fatal(err)
	}
	got := packageManagerLaneBackends(string(workflow))
	if len(got) == 0 {
		t.Fatal("package-manager lane discovery matched zero backends")
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("package-manager lanes = %v, want exactly the Backend.String() set %v", got, want)
	}
}
