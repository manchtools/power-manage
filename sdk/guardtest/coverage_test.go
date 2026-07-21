package guardtest

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// invariant is one row of the machine-readable INV registry (SPEC-000 AC-5).
// The registry is DERIVED, never hand-maintained [META-2]: owners come from
// the SPEC-000 §3.4 catalog text unioned with cross-references in the other
// spec files.
type invariant struct {
	ID          string   // "INV-1".."INV-19"
	OwningSpecs []string // "SPEC-NNN"
	InRepo      bool     // false only for the web-repo invariant
}

// notInRepo exempts invariants enforced outside this repository — keyed by
// identity with the reason, never a bare name list.
var notInRepo = map[string]string{
	"INV-17": "web UI invariant; enforced in the separate web repository (SPEC-000 §3.4)",
}

// ownerlessPending records in-repo invariants whose §3.4 entry cites no
// owning spec yet. It is intentionally empty: an entry is a temporary, loud
// hole that must disappear once ownership is resolved.
var ownerlessPending = map[string]string{}

var (
	invEntryRe = regexp.MustCompile(`(?m)^- \*\*\[INV-(\d+)\]\*\*`)
	tmEntryRe  = regexp.MustCompile(`(?m)^- \*\*\[TM-(\d+)\]\*\*`)
	specRefRe  = regexp.MustCompile(`\bSPEC-(\d{3})\b`)
	invRefRe   = regexp.MustCompile(`\bINV-(\d+)\b`)
	tmRefRe    = regexp.MustCompile(`\bTM-(\d+)\b`)
)

// invariantRegistry parses SPEC-000 §3.4 under root and returns one entry
// per catalog invariant, owners unioned with any other spec citing the ID.
func invariantRegistry(root string) ([]invariant, error) {
	return derivedRegistry(root, "000-development-process.md", "### 3.4", "### 3.5", "INV-", invEntryRe, invRefRe)
}

// derivedRegistry parses the catalog section [secStart, secEnd) of sourceFile
// under root, one row per entryRe match; owners are the SPEC refs in the
// entry's own text unioned with any OTHER spec file citing the ID via refRe —
// the defining spec's own file is excluded, or its completion would demand
// every one of its rows' guards at once.
func derivedRegistry(root, sourceFile, secStart, secEnd, idPrefix string, entryRe, refRe *regexp.Regexp) ([]invariant, error) {
	specDir := filepath.Join(root, "docs", "content", "01-specs")
	src, err := os.ReadFile(filepath.Join(specDir, sourceFile))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", sourceFile, err)
	}
	text := string(src)
	start := strings.Index(text, secStart)
	end := strings.Index(text, secEnd)
	if start < 0 || end < start {
		return nil, fmt.Errorf("%s catalog section %q not found — the spec layout moved", sourceFile, secStart)
	}
	catalog := text[start:end]

	// Each catalog entry's own text names its owning specs.
	owners := map[string]map[string]bool{}
	var ids []string
	entries := entryRe.FindAllStringSubmatchIndex(catalog, -1)
	for i, e := range entries {
		id := idPrefix + catalog[e[2]:e[3]]
		entryEnd := len(catalog)
		if i+1 < len(entries) {
			entryEnd = entries[i+1][0]
		}
		ids = append(ids, id)
		owners[id] = map[string]bool{}
		for _, m := range specRefRe.FindAllStringSubmatch(catalog[e[1]:entryEnd], -1) {
			owners[id]["SPEC-"+m[1]] = true
		}
	}

	// Union with cross-references: any other spec whose text cites the ID
	// co-owns it. The citing spec's ID comes from its filename (NNN-name.md).
	files, err := filepath.Glob(filepath.Join(specDir, "[0-9][0-9][0-9]-*.md"))
	if err != nil {
		return nil, fmt.Errorf("listing spec files: %w", err)
	}
	for _, f := range files {
		base := filepath.Base(f)
		if base == sourceFile {
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", base, err)
		}
		for _, m := range refRe.FindAllStringSubmatch(string(body), -1) {
			if set, ok := owners[idPrefix+m[1]]; ok {
				set["SPEC-"+base[:3]] = true
			}
		}
	}

	var invs []invariant
	for _, id := range ids {
		var specs []string
		for s := range owners[id] {
			specs = append(specs, s)
		}
		sort.Strings(specs)
		invs = append(invs, invariant{ID: id, OwningSpecs: specs, InRepo: notInRepo[id] == ""})
	}
	return invs, nil
}

// trustModelRegistry parses SPEC-001 §3.2 under root and returns one entry
// per trust-model invariant TM-1..TM-5, owners derived the same way as the
// INV rows (SPEC-001 M3 ledger wiring): entry refs unioned with cross-citing
// specs, SPEC-001 itself excluded as the defining spec.
func trustModelRegistry(root string) ([]invariant, error) {
	return derivedRegistry(root, "001-architecture-and-trust-model.md", "### 3.2", "### 3.3", "TM-", tmEntryRe, tmRefRe)
}

// specStatuses parses the ledger table in 00-index.md under root and maps
// "SPEC-NNN" to its status column ("Spec ready", "In progress (…)",
// "Implemented").
func specStatuses(root string) (map[string]string, error) {
	body, err := os.ReadFile(filepath.Join(root, "docs", "content", "01-specs", "00-index.md"))
	if err != nil {
		return nil, fmt.Errorf("reading the ledger: %w", err)
	}
	statuses := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		cells := strings.Split(line, "|")
		// A spec row splits into 7: "", #, name, builds-on, modules, status, "".
		if len(cells) != 7 {
			continue
		}
		num := strings.TrimSpace(cells[1])
		if len(num) != 3 || strings.Trim(num, "0123456789") != "" {
			continue
		}
		statuses["SPEC-"+num] = strings.TrimSpace(cells[5])
	}
	if len(statuses) == 0 {
		return nil, fmt.Errorf("no spec rows parsed from the ledger — the table format moved")
	}
	return statuses, nil
}

// coverageViolations is the G-000-1 join: every in-repo invariant with an
// Implemented owning spec must have at least one registered guard.
func coverageViolations(invs []invariant, statuses map[string]string, guardsByInv map[string][]string) []string {
	var out []string
	for _, inv := range invs {
		if !inv.InRepo || len(guardsByInv[inv.ID]) > 0 {
			continue
		}
		for _, owner := range inv.OwningSpecs {
			if strings.HasPrefix(statuses[owner], "Implemented") {
				out = append(out, fmt.Sprintf("%s: owning spec %s is Implemented but no guard carries a `Guards: %s` registration — the guard ships with the invariant (G-000-1, SPEC-000 §6.3)", inv.ID, owner, inv.ID))
				break
			}
		}
	}
	return out
}

// TestGuard_InvariantCoverage is G-000-1 (SPEC-000): the registry must
// contain exactly INV-1..INV-19, each owner must be a real spec, and no
// invariant whose owning spec is implemented may lack a registered guard.
func TestGuard_InvariantCoverage(t *testing.T) {
	root := RepoRoot(t)
	invs := Discover(t, "invariants from the SPEC-000 catalog", 19, func() ([]invariant, error) {
		return invariantRegistry(root)
	})

	// Exact set, both directions: a 20th or a missing entry both mean the
	// catalog or the parse moved.
	seen := map[string]bool{}
	for _, inv := range invs {
		seen[inv.ID] = true
	}
	for i := 1; i <= 19; i++ {
		id := fmt.Sprintf("INV-%d", i)
		if !seen[id] {
			t.Errorf("registry is missing %s — the §3.4 catalog or its parse moved", id)
		}
		delete(seen, id)
	}
	for id := range seen {
		t.Errorf("registry contains unexpected entry %q — the catalog holds exactly INV-1..INV-19; a new invariant needs a spec change first", id)
	}

	// Per-invariant owner floor: an empty owner set makes the coverage join
	// vacuous for that invariant forever — silent fail-open.
	for _, inv := range invs {
		if inv.InRepo && len(inv.OwningSpecs) == 0 && ownerlessPending[inv.ID] == "" {
			t.Errorf("%s has no derived owning spec and no recorded pending decision — G-000-1 can never demand its guard; add the ref to its §3.4 entry or record the open question in ownerlessPending", inv.ID)
		}
	}

	var statusMap map[string]string
	Discover(t, "spec statuses from the ledger", 18, func() ([]string, error) {
		m, err := specStatuses(root)
		if err != nil {
			return nil, err
		}
		statusMap = m
		flat := make([]string, 0, len(m))
		for spec, status := range m {
			flat = append(flat, spec+"="+status)
		}
		return flat, nil
	})
	for _, inv := range invs {
		for _, owner := range inv.OwningSpecs {
			if _, ok := statusMap[owner]; !ok {
				t.Errorf("%s names owning spec %s which is not in the ledger — parse drift", inv.ID, owner)
			}
		}
	}

	// SPEC-001 M3: the trust-model rows join the same ledger with the same
	// exact-set, owner-floor, and coverage demands.
	tms := Discover(t, "trust-model invariants from SPEC-001 §3.2", 5, func() ([]invariant, error) {
		return trustModelRegistry(root)
	})
	seen = map[string]bool{}
	for _, tm := range tms {
		seen[tm.ID] = true
	}
	for i := 1; i <= 5; i++ {
		id := fmt.Sprintf("TM-%d", i)
		if !seen[id] {
			t.Errorf("registry is missing %s — the SPEC-001 §3.2 catalog or its parse moved", id)
		}
		delete(seen, id)
	}
	for id := range seen {
		t.Errorf("registry contains unexpected entry %q — SPEC-001 §3.2 holds exactly TM-1..TM-5; a new trust-model invariant needs a spec change first", id)
	}
	for _, tm := range tms {
		if tm.InRepo && len(tm.OwningSpecs) == 0 && ownerlessPending[tm.ID] == "" {
			t.Errorf("%s has no derived owning spec and no recorded pending decision — the coverage join can never demand its guard", tm.ID)
		}
		for _, owner := range tm.OwningSpecs {
			if _, ok := statusMap[owner]; !ok {
				t.Errorf("%s names owning spec %s which is not in the ledger — parse drift", tm.ID, owner)
			}
		}
	}

	_, _, guardsByInv, err := guardInventory(root)
	if err != nil {
		t.Fatalf("guard inventory: %v", err)
	}
	for _, v := range coverageViolations(append(invs, tms...), statusMap, guardsByInv) {
		t.Error(v)
	}
}

// TestInvariantRegistry_DerivedOwners spot-checks derivation against
// hand-verified catalog facts: INV-19's entry cites SPEC-002, INV-12's cites
// SPEC-005, and INV-17 is the web-repo invariant.
func TestInvariantRegistry_DerivedOwners(t *testing.T) {
	invs, err := invariantRegistry(RepoRoot(t))
	if err != nil {
		t.Fatalf("invariantRegistry: %v", err)
	}
	byID := map[string]invariant{}
	for _, inv := range invs {
		byID[inv.ID] = inv
	}
	owns := func(id, spec string) bool {
		for _, s := range byID[id].OwningSpecs {
			if s == spec {
				return true
			}
		}
		return false
	}
	if !owns("INV-19", "SPEC-002") {
		t.Errorf("INV-19 owners = %v, want SPEC-002 among them (its §3.4 entry cites it)", byID["INV-19"].OwningSpecs)
	}
	if !owns("INV-12", "SPEC-005") {
		t.Errorf("INV-12 owners = %v, want SPEC-005 among them", byID["INV-12"].OwningSpecs)
	}
	if !owns("INV-5", "SPEC-003") {
		t.Errorf("INV-5 owners = %v, want SPEC-003 among them (signed-bytes/preimage requirements live there)", byID["INV-5"].OwningSpecs)
	}
	if !owns("INV-3", "SPEC-006") {
		t.Errorf("INV-3 owners = %v, want SPEC-006 (the PKI boot path owns fail-closed signer/verifier wiring)", byID["INV-3"].OwningSpecs)
	}
	if _, ok := ownerlessPending["INV-3"]; ok {
		t.Error("INV-3 remains exempted in ownerlessPending after assigning SPEC-006 ownership")
	}
	if !owns("INV-11", "SPEC-008") {
		t.Errorf("INV-11 owners = %v, want SPEC-008 among them (AUTHZ-2 last-admin protection)", byID["INV-11"].OwningSpecs)
	}
	if byID["INV-17"].InRepo {
		t.Error("INV-17 is enforced in the web repository (SPEC-000 §3.4/§10) and must be marked not-in-repo")
	}
	if !byID["INV-19"].InRepo {
		t.Error("INV-19 must be in-repo")
	}
}

// TestTrustModelRegistry_DerivedOwners spot-checks TM derivation against
// hand-verified facts: TM-1's §3.2 entry cites SPEC-005, TM-3's cites
// SPEC-016 and is cross-cited by SPEC-005 (the AC-5 singleton-work
// obligation), TM-5 is cross-cited by SPEC-003 and SPEC-013 (the AC-4
// fail-closed obligation), and SPEC-001 never owns its own rows.
func TestTrustModelRegistry_DerivedOwners(t *testing.T) {
	tms, err := trustModelRegistry(RepoRoot(t))
	if err != nil {
		t.Fatalf("trustModelRegistry: %v", err)
	}
	byID := map[string]invariant{}
	for _, tm := range tms {
		byID[tm.ID] = tm
	}
	owns := func(id, spec string) bool {
		for _, s := range byID[id].OwningSpecs {
			if s == spec {
				return true
			}
		}
		return false
	}
	if !owns("TM-1", "SPEC-005") {
		t.Errorf("TM-1 owners = %v, want SPEC-005 among them (its §3.2 entry cites ES-1)", byID["TM-1"].OwningSpecs)
	}
	if !owns("TM-3", "SPEC-016") || !owns("TM-3", "SPEC-005") {
		t.Errorf("TM-3 owners = %v, want SPEC-016 (entry ref) and SPEC-005 (cross-ref) among them — AC-5's singleton-work guard is demanded when either implements", byID["TM-3"].OwningSpecs)
	}
	if !owns("TM-5", "SPEC-003") || !owns("TM-5", "SPEC-013") {
		t.Errorf("TM-5 owners = %v, want SPEC-003 and SPEC-013 among them — AC-4's fail-closed tests are demanded when either implements", byID["TM-5"].OwningSpecs)
	}
	for _, tm := range tms {
		if owns(tm.ID, "SPEC-001") {
			t.Errorf("%s lists defining spec SPEC-001 as an owner (%v) — the defining spec is excluded, or its own completion would demand every TM guard at once", tm.ID, tm.OwningSpecs)
		}
		if !tm.InRepo {
			t.Errorf("%s marked not-in-repo — every trust-model invariant is enforced in this repository", tm.ID)
		}
	}
}

func TestSpecStatuses_ReadsLedger(t *testing.T) {
	statuses, err := specStatuses(RepoRoot(t))
	if err != nil {
		t.Fatalf("specStatuses: %v", err)
	}
	if len(statuses) != 18 {
		t.Fatalf("ledger yielded %d specs, want 18", len(statuses))
	}
	if s := statuses["SPEC-000"]; s != "Implemented" {
		t.Errorf("SPEC-000 status = %q, want %q (all four milestones landed)", s, "Implemented")
	}
	if s := statuses["SPEC-017"]; s != "Spec ready" {
		t.Errorf("SPEC-017 status = %q, want %q", s, "Spec ready")
	}
}

// TestCoverageJoin_Liveness: the planted case — an invariant whose owning
// spec is Implemented and which has NO registered guard — must be flagged;
// the same invariant WITH a guard must not be. Removing a guard registration
// is exactly the neutralizing edit SPEC-000 §6.3 names.
func TestCoverageJoin_Liveness(t *testing.T) {
	invs := []invariant{
		{ID: "INV-5", OwningSpecs: []string{"SPEC-003"}, InRepo: true},
		{ID: "INV-17", OwningSpecs: []string{"SPEC-007"}, InRepo: false},
	}
	statuses := map[string]string{"SPEC-003": "Implemented", "SPEC-007": "Implemented"}

	v := coverageViolations(invs, statuses, map[string][]string{})
	if len(v) != 1 || !strings.Contains(v[0], "INV-5") {
		t.Fatalf("implemented spec without guard: want exactly one INV-5 violation, got %v", v)
	}

	v = coverageViolations(invs, statuses, map[string][]string{"INV-5": {"x_test.go:TestGuard_X"}})
	if len(v) != 0 {
		t.Fatalf("registered guard present: want no violations, got %v", v)
	}

	v = coverageViolations(invs, map[string]string{"SPEC-003": "Spec ready"}, map[string][]string{})
	if len(v) != 0 {
		t.Fatalf("owner not implemented yet: want no violations, got %v", v)
	}
}
