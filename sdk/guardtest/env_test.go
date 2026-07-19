package guardtest

import (
	"fmt"
	"path/filepath"
	"testing"
)

// TestGuard_EnvHygiene is G-002-4 (SPEC-002 AC-4/AC-5, [INV-18], [CFG-2]):
// every read of the process environment across the workspace resolves to a
// sanctioned reader — today exactly the config loader's derived-PM_* pass.
// Sites are discovered by AST walk through real import bindings (aliased
// and dot imports cannot evade; same-named symbols from unrelated packages
// are not flagged) and attributed to their enclosing declaration; the
// allowlist is keyed by that identity and checked exact-set in both
// directions.
//
// Guards: INV-18.
func TestGuard_EnvHygiene(t *testing.T) {
	root := RepoRoot(t)
	mods := Discover(t, "workspace modules from go.work", 4, func() ([]string, error) {
		return workspaceModules(root)
	})
	var sites []envReadSite
	for _, mod := range mods {
		s, err := envReadSites(filepath.Join(root, mod))
		if err != nil {
			t.Fatalf("scanning %s for environment reads: %v", mod, err)
		}
		for _, site := range s {
			site.Pos = mod + "/" + site.Pos
			site.Key = mod + "/" + site.Key
			sites = append(sites, site)
		}
	}
	Discover(t, "process-environment read sites", 1, func() ([]string, error) {
		var keys []string
		for _, s := range sites {
			keys = append(keys, s.Key)
		}
		return keys, nil
	})
	seen := map[string]bool{}
	for _, s := range sites {
		seen[s.Key] = true
		if _, sanctioned := envReadAllowlist[s.Key]; !sanctioned {
			t.Errorf("%s: os.%s read in %s — INV-18/CFG-2: only the config loader (and the SPEC-004 child-env builder, when it lands) read the environment; route the knob through the config struct", s.Pos, s.Func, s.Key)
		}
	}
	for key, why := range envReadAllowlist {
		if !seen[key] {
			t.Errorf("envReadAllowlist entry %q (%s) matched no site — the sanctioned reader moved; update the entry", key, why)
		}
	}
}

// TestGuard_EnvHygiene_Liveness: the fixture plants a plain read, a read
// in a var initializer, aliased and parenthesized reads, and a dot-import
// read; a same-named helper from an unrelated package and env WRITES stay
// clean.
func TestGuard_EnvHygiene_Liveness(t *testing.T) {
	scan := func(root string) ([]string, error) {
		sites, err := envReadSites(root)
		if err != nil {
			return nil, err
		}
		var v []string
		for _, s := range sites {
			v = append(v, fmt.Sprintf("%s: os.%s in %s", s.Pos, s.Func, s.Key))
		}
		return v, nil
	}
	RequireViolation(t, "env hygiene", scan, "testdata/arch/env")
	v, err := scan("testdata/arch/env")
	if err != nil {
		t.Fatalf("scanning the env fixture: %v", err)
	}
	requireFlagged(t, v, []string{
		"plain.go:8",   // os.Getenv in a function body
		"plain.go:11",  // os.ExpandEnv in a var initializer
		"alias.go:8",   // aliased osx.LookupEnv
		"alias.go:12",  // parenthesized (osx.Environ)()
		"dot.go:8",     // dot-imported Getenv
		"closure.go:9", // read inside a closure, attributed to viaClosure
	}, []string{"clean.go"})
}

// TestEnvReadFuncs_ThreatModel: the ban set is the threat model — the
// spec's Getenv/LookupEnv/Environ plus ExpandEnv, which reads the
// environment identically. Writes are not config inputs and stay out.
// Recorded ceiling: syscall/x-sys env access and indirect references
// (f := os.Getenv; f(...)) are not matched — same ceiling class as
// BannedCalls.
func TestEnvReadFuncs_ThreatModel(t *testing.T) {
	for _, fn := range []string{"Getenv", "LookupEnv", "Environ", "ExpandEnv"} {
		if !envReadFuncs[fn] {
			t.Errorf("environment read os.%s not in the ban set — the threat model lost a family", fn)
		}
	}
	for _, fn := range []string{"Setenv", "Unsetenv", "Clearenv", "Getwd"} {
		if envReadFuncs[fn] {
			t.Errorf("os.%s is not an environment READ — the ban set overmatches", fn)
		}
	}
	if len(envReadFuncs) == 0 {
		t.Fatal("envReadFuncs is empty — the threat model lost its subjects")
	}
}
