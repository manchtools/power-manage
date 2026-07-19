package guardtest

import (
	"testing"
)

// TestGuard_BoundaryRegistry is G-001-2 (SPEC-001 AC-2): every discovered
// listener/serve call site is registered against exactly one boundary of
// §3.4, and every registration matches a real site. Floor = current
// listener count (zero today → reported dormant skip; ratchets to 7 as
// owning specs land their listeners).
func TestGuard_BoundaryRegistry(t *testing.T) {
	root := RepoRoot(t)
	sites, err := ListenerSites(root)
	if err != nil {
		t.Fatalf("discovering listener call sites: %v", err)
	}
	if len(sites) == 0 && len(ListenerRegistrations) == 0 {
		t.Skipf("G-001-2 dormant: no listener/serve call sites in the repository yet — floor is the current listener count (SPEC-001 §9 M2) and ratchets as owning specs land")
	}
	Discover(t, "listener/serve call sites", 1, func() ([]string, error) {
		keys := make([]string, 0, len(sites))
		for _, s := range sites {
			keys = append(keys, s.Pos)
		}
		return keys, nil
	})
	for _, v := range boundaryJoinViolations(sites, ListenerRegistrations, Boundaries) {
		t.Errorf("%s — every network listener and local socket maps to exactly one boundary of SPEC-001 §3.4 [ARCH-3]; a new listener needs a boundary row and a registration first", v)
	}
}

// TestGuard_BoundaryRegistry_Liveness: the fixture plants every evasion
// family the matcher's grammar must decide — plain call, unix socket,
// aliased import, paren-wrapped callee, closure, serve-family method,
// ListenConfig method, dot-import — plus a registered site (clean), a
// registration against an unknown boundary, an orphan registration, and a
// decoy alias (clean).
func TestGuard_BoundaryRegistry_Liveness(t *testing.T) {
	regs := map[string]string{
		"registered.go:gatewayListen": "B4",  // sanctioned: the clean case
		"plain.go:tcp":                "B99", // unknown boundary — violation
		"ghost.go:Nope":               "B1",  // orphan — violation
	}
	scan := func(root string) ([]string, error) {
		sites, err := ListenerSites(root)
		if err != nil {
			return nil, err
		}
		return boundaryJoinViolations(sites, regs, Boundaries), nil
	}
	RequireViolation(t, "boundary registry", scan, "testdata/arch/listeners")
	v, err := scan("testdata/arch/listeners")
	if err != nil {
		t.Fatalf("scanning the listeners fixture: %v", err)
	}
	requireFlagged(t, v, []string{
		"plain.go:7",    // registered against the unknown B99
		"plain.go:9",    // unregistered unix socket
		"wrapped.go:8",  // aliased
		"wrapped.go:10", // paren-wrapped callee
		"wrapped.go:12", // inside a closure
		"wrapped.go:20", // serve-family method on a custom server
		"wrapped.go:25", // ListenConfig.Listen method
		"dot.go:6",      // dot-imported
		"ghost.go:Nope", // orphan registration
	}, []string{"decoy.go", "registered.go"})
}

// TestBoundaryJoin_Exhaustive: pure-function proof of the three violation
// classes (unregistered site, unknown boundary, orphan registration) and
// the clean case.
func TestBoundaryJoin_Exhaustive(t *testing.T) {
	sites := []ListenerSite{
		{Pos: "a.go:5", Key: "a.go:F"},  // registered, valid — clean
		{Pos: "b.go:7", Key: "b.go:G"},  // registered, unknown boundary
		{Pos: "d.go:9", Key: "d.go:HH"}, // unregistered
	}
	regs := map[string]string{
		"a.go:F": "B1",
		"b.go:G": "B99",
		"c.go:H": "B2", // orphan
	}
	boundaries := map[string]string{"B1": "one", "B2": "two"}
	v := boundaryJoinViolations(sites, regs, boundaries)
	requireFlagged(t, v, []string{"b.go:7", "d.go:9", "c.go:H"}, []string{"a.go:5", "a.go:F"})
}
