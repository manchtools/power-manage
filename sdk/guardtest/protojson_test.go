package guardtest

import (
	"path/filepath"
	"testing"
)

// TestGuard_ProtojsonOnly is G-6 (SPEC-003 AC-12): no file in any
// workspace module imports both encoding/json and a generated contract
// package. The population anchor is the go.work module set.
func TestGuard_ProtojsonOnly(t *testing.T) {
	root := RepoRoot(t)
	mods := Discover(t, "workspace modules from go.work", 4, func() ([]string, error) {
		return workspaceModules(root)
	})
	for _, mod := range mods {
		v, err := protojsonViolations(filepath.Join(root, mod))
		if err != nil {
			t.Fatalf("scanning module %s: %v", mod, err)
		}
		for _, s := range v {
			t.Errorf("%s/%s", mod, s)
		}
	}
}

// TestGuard_ProtojsonOnly_Liveness: the bad fixture's mixed file flags,
// its protojson sibling and the json-only package stay clean.
func TestGuard_ProtojsonOnly_Liveness(t *testing.T) {
	RequireViolation(t, "protojson-only", protojsonViolations, "testdata/arch/protojson/bad")
	v, err := protojsonViolations("testdata/arch/protojson/bad")
	if err != nil {
		t.Fatalf("scanning the bad fixture: %v", err)
	}
	requireFlagged(t, v, []string{"mixed.go"}, []string{"clean.go"})

	clean, err := protojsonViolations("testdata/arch/protojson/good")
	if err != nil {
		t.Fatalf("scanning the good fixture: %v", err)
	}
	if len(clean) != 0 {
		t.Fatalf("json-only fixture flagged: %v — the checker went always-red", clean)
	}
}
