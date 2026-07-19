package guardtest

import "testing"

// loaderImportPath is the shared CFG-1 loader every shipped binary boots
// through.
const loaderImportPath = "github.com/manchtools/power-manage/sdk/config"

// binaryFloor ratchets as specs land binaries (control/gateway, agent —
// SPEC-013 and the server specs); a discovered binary can then never
// silently drop out of adoption.
const binaryFloor = 0

// TestGuard_ConfigAdoption is the per-binary ratchet for G-002-5 and
// G-002-6 (SPEC-002 AC-4/AC-6, [CFG-1]): every main package under a
// module's cmd/ tree imports the shared loader AND carries a test calling
// the loader's Doc, so each binary's config reference stays generated.
// The round-trip and golden proofs themselves are TestGuard_ConfigRoundTrip
// and TestDoc_GoldenMatch in sdk/config. Zero binaries exist today, so
// this guard's red proof is its liveness fixture. ponytail: a main package
// outside cmd/ is not a shipped binary by repo convention (recorded
// ceiling).
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
// binary that neither imports the loader nor carries a docs test — both
// violation classes fire on it; the adopted one (import + a test calling
// Doc) stays clean. Locators are class-qualified (`:import`, `:docs`) so
// each class is proven independently on the colon boundary.
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
	requireFlagged(t, v,
		[]string{"app/cmd/bad:import", "app/cmd/bad:docs"},
		[]string{"app/cmd/good"})
}
