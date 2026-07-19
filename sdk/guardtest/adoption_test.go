package guardtest

import "testing"

// loaderImportPath is the shared CFG-1 loader every shipped binary boots
// through.
const loaderImportPath = "github.com/manchtools/power-manage/sdk/config"

// binaryFloor ratchets as specs land binaries (control/gateway, agent —
// SPEC-013 and the server specs); a discovered binary can then never
// silently drop out of adoption.
const binaryFloor = 0

// TestGuard_ConfigAdoption is G-002-5's per-binary ratchet (SPEC-002 AC-4,
// [CFG-1]): every main package under a module's cmd/ tree imports the
// shared loader — one typed struct, one file, derived overrides. The
// round-trip proof itself is TestGuard_ConfigRoundTrip in sdk/config.
// Zero binaries exist today, so this guard's red proof is its liveness
// fixture. ponytail: a main package outside cmd/ is not a shipped binary
// by repo convention (recorded ceiling).
func TestGuard_ConfigAdoption(t *testing.T) {
	root := RepoRoot(t)
	mods := Discover(t, "workspace modules from go.work", 4, func() ([]string, error) {
		return workspaceModules(root)
	})
	v, bins, err := binaryAdoptionViolations(root, mods, loaderImportPath)
	if err != nil {
		t.Fatalf("scanning cmd/ binaries: %v", err)
	}
	if len(bins) < binaryFloor {
		t.Errorf("found %d cmd/ binaries, floor is %d — a shipped binary disappeared from discovery; fix the walk, never lower the floor without a spec change", len(bins), binaryFloor)
	}
	for _, s := range v {
		t.Errorf("%s — CFG-1: one typed config struct, loaded through the shared sdk loader; hand-rolled config is INV-18 sprawl", s)
	}
}

// TestGuard_ConfigAdoption_Liveness: the fixture workspace plants one
// binary that never imports the loader; the adopted one stays clean.
func TestGuard_ConfigAdoption_Liveness(t *testing.T) {
	scan := func(root string) ([]string, error) {
		mods, err := workspaceModules(root)
		if err != nil {
			return nil, err
		}
		v, _, err := binaryAdoptionViolations(root, mods, "example.com/pm/sdk/config")
		return v, err
	}
	RequireViolation(t, "config adoption", scan, "testdata/arch/adoption/ws")
	v, err := scan("testdata/arch/adoption/ws")
	if err != nil {
		t.Fatalf("scanning the adoption fixture: %v", err)
	}
	requireFlagged(t, v, []string{"app/cmd/bad"}, []string{"app/cmd/good"})
}
