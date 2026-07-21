package guardtest

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

var packageManagerBackends = []string{"apt", "dnf", "flatpak", "pacman", "zypper"}

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
	if !reflect.DeepEqual(got, packageManagerBackends) {
		t.Fatalf("package-manager lanes = %v, want exactly %v", got, packageManagerBackends)
	}
}
