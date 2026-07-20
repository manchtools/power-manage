package guardtest

// SPEC-004 M1 guard rows (docs/plans/spec-004-m1.md). G-1/G-2/G-8 are the
// existing estate — TestGuard_ProtoPurity, TestGuard_EnvHygiene,
// TestGuard_DirectionalImports (plan choice 1); the guards here are the new
// wirings G-3..G-7 and G-9 over the sdk module.

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// sdkRoot resolves the sdk module directory for the armed scans.
func sdkRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join(RepoRoot(t), "sdk")
}

// TestGuard_Randomness is SPEC-004 G-3 ([SDK-13]): math/rand AND
// math/rand/v2 are banned across sdk. The jitter allowlist is empty until
// the jitter package lands (M2) — extend the allow there with rationale,
// never weaken the ban here. The spec's ≥1-crypto-call-site floor arms at
// M5 with sdk/crypto; until then the floor is the scanned-file population.
//
// INV-8 scope: THIS guard proves the math/rand-ban half. The ULID-not-UUID
// and crypto/rand-error-checking halves arm at M5 (sdk/crypto unit tests
// and the G-5 extension) — extend there, never weaken here.
//
// Guards: INV-8.
func TestGuard_Randomness(t *testing.T) {
	root := sdkRoot(t)
	Discover(t, "sdk Go files", 1, func() ([]string, error) {
		return sdkGoFiles(root)
	})
	v, err := randomnessViolations(root)
	if err != nil {
		t.Fatalf("scanning sdk for math/rand: %v", err)
	}
	for _, s := range v {
		t.Errorf("%s — INV-8: crypto/rand only; math/rand is legal solely under the jitter allowlist (SDK-13)", s)
	}
}

// TestGuard_Randomness_Liveness: the fixture plants v1 outside and inside
// the (fixture-local, here unallowed) jitter dir plus a v2 import; the
// crypto/rand file stays clean. v2_bad.go doubles as the path-exactness
// decoy for the v1 scan.
func TestGuard_Randomness_Liveness(t *testing.T) {
	RequireViolation(t, "math/rand ban", randomnessViolations, "testdata/astban/mathrand")
	v, err := randomnessViolations("testdata/astban/mathrand")
	if err != nil {
		t.Fatalf("scanning the mathrand fixture: %v", err)
	}
	requireFlagged(t, v, []string{"bad.go", "jitter/jitter.go", "v2_bad.go"}, []string{"clean.go"})
}

// TestGuard_RegexChokepoint is SPEC-004 G-4 ([SDK-6]): every
// regexp.{Must,}Compile{POSIX,} call site in sdk routes through the redos
// chokepoint package (lands M2) or carries a decl-keyed allowlist entry
// with rationale. Orphaned allowlist entries fail the guard — the exact-set
// rule: a key matching no discovered site means the surface moved under it.
func TestGuard_RegexChokepoint(t *testing.T) {
	root := sdkRoot(t)
	v, sites, err := regexChokepointViolations(root, regexCompileAllowlist)
	if err != nil {
		t.Fatalf("scanning sdk for regexp compiles: %v", err)
	}
	siteSet := map[string]bool{}
	for _, s := range Discover(t, "regexp compile call sites in sdk", 1, func() ([]string, error) {
		return sites, nil
	}) {
		siteSet[s] = true
	}
	for _, s := range v {
		t.Errorf("%s — SDK-6: patterns route through the redos chokepoint (M2) or get a decl-keyed allowlist entry with rationale", s)
	}
	for key := range regexCompileAllowlist {
		if !siteSet[key] {
			t.Errorf("allowlist entry %q matches no discovered compile site — remove the orphan or fix the key", key)
		}
	}
}

// TestGuard_RegexChokepoint_Liveness: plain, aliased+POSIX, and dot-import
// compiles are flagged; the local same-named helper and the chokepoint's
// own compile stay clean.
func TestGuard_RegexChokepoint_Liveness(t *testing.T) {
	scan := func(root string) ([]string, error) {
		v, _, err := regexChokepointViolations(root, nil)
		return v, err
	}
	RequireViolation(t, "regex chokepoint", scan, "testdata/sdkcore/regexploose")
	v, sites, err := regexChokepointViolations("testdata/sdkcore/regexploose", nil)
	if err != nil {
		t.Fatalf("scanning the regexploose fixture: %v", err)
	}
	requireFlagged(t, v,
		[]string{"bad.go:7", "bad.go:10", "aliased_bad.go:7", "dot_bad.go:6", "method_bad.go:11"},
		[]string{"decoy.go", "redos/vetted.go"})
	// The method site keys by receiver-qualified identity, so a same-named
	// package var can never share (or steal) its allowlist exemption.
	wantKey := "method_bad.go:probe.rx"
	found := false
	for _, s := range sites {
		if s == wantKey {
			found = true
		}
	}
	if !found {
		t.Errorf("site keys %v lack %q — method sites must key by receiver-qualified decl identity", sites, wantKey)
	}
}

// TestGuard_PreimageFraming is SPEC-004 G-5 ([SDK-13]) in its M1 form:
// crypto/sha256, crypto/sha512, and crypto/hmac are banned in sdk outside
// the crypto package path, so no hash/MAC surface can grow outside the
// package the M5 guard will walk. Per-construction lp/domain-helper
// enforcement INSIDE sdk/crypto is the M5 extension — extend there, never
// weaken this ban (plan choice 5). The single file-keyed exception is
// recorded with its rationale and M5 sunset at hashImportAllow.
func TestGuard_PreimageFraming(t *testing.T) {
	root := sdkRoot(t)
	Discover(t, "sdk Go files", 1, func() ([]string, error) {
		return sdkGoFiles(root)
	})
	v, err := hashImportViolations(root)
	if err != nil {
		t.Fatalf("scanning sdk for hash imports: %v", err)
	}
	for _, s := range v {
		t.Errorf("%s — SDK-13: hash/MAC constructions live in sdk/crypto behind the length-prefix/domain helper; move the construction there", s)
	}
}

// TestGuard_PreimageFraming_Liveness: sha256, hmac, and sha512 imports
// outside the crypto dir are flagged; crypto/subtle and the crypto
// package's own hash use stay clean.
func TestGuard_PreimageFraming_Liveness(t *testing.T) {
	RequireViolation(t, "hash imports outside crypto", hashImportViolations, "testdata/sdkcore/hashout")
	v, err := hashImportViolations("testdata/sdkcore/hashout")
	if err != nil {
		t.Fatalf("scanning the hashout fixture: %v", err)
	}
	requireFlagged(t, v,
		[]string{"bad.go:3", "mac_bad.go:4", "mac_bad.go:5"},
		[]string{"clean.go", "crypto/inpkg.go"})
}

// TestGuard_SealAADSurface is SPEC-004 G-6 ([SDK-13]): every exported
// seal/open function in sdk/crypto carries a parameter named aad — no
// nil-AAD API exists. AST walk rather than the spec's reflection sketch: a
// test cannot link a deliberately-wrong fixture API, and the walk covers
// methods and fails closed on a renamed AAD parameter (plan choice 6).
// Dormant until sdk/crypto lands (M5); the liveness row keeps the walk
// honest meanwhile.
func TestGuard_SealAADSurface(t *testing.T) {
	cryptoRoot := filepath.Join(sdkRoot(t), "crypto")
	if _, err := os.Stat(cryptoRoot); errors.Is(err, fs.ErrNotExist) {
		t.Skipf("G-6 dormant: sdk/crypto does not exist yet — the guard arms when SPEC-004 M5 lands the AEAD surface")
	}
	v, fns, err := aadAPIViolations(cryptoRoot)
	if err != nil {
		t.Fatalf("scanning sdk/crypto seal/open surface: %v", err)
	}
	Discover(t, "exported seal/open functions", 1, func() ([]string, error) {
		return fns, nil
	})
	for _, s := range v {
		t.Errorf("%s — SDK-13: AAD is mandatory on the whole seal/open surface; add the aad parameter (or rename a false positive INTO the aad contract)", s)
	}
}

// TestGuard_SealAADSurface_Liveness: a plain function, a method, and a
// renamed-parameter variant are flagged; the conforming shape, the
// unexported helper, and the non-seal export stay clean.
func TestGuard_SealAADSurface_Liveness(t *testing.T) {
	scan := func(root string) ([]string, error) {
		v, _, err := aadAPIViolations(root)
		return v, err
	}
	RequireViolation(t, "seal/open without aad", scan, "testdata/sdkcore/aad")
	v, err := scan("testdata/sdkcore/aad")
	if err != nil {
		t.Fatalf("scanning the aad fixture: %v", err)
	}
	requireFlagged(t, v,
		[]string{"aad.go:5", "method_bad.go:7", "method_bad.go:11", "iface_bad.go:6"},
		[]string{"aad.go:8", "iface_bad.go:11"})
}

// TestGuard_MutationChokepoint is SPEC-004 G-7 ([SDK-7]): path-based os
// mutation calls are banned in sdk outside the fd-anchored helpers package
// (fsafe, lands M3). Recorded ceiling: os.OpenFile stays legal everywhere —
// it is the fd-anchored primitive itself; clobber-flag inspection anchors
// on the helpers' allow-prefix at M3 (plan choice 7).
func TestGuard_MutationChokepoint(t *testing.T) {
	root := sdkRoot(t)
	Discover(t, "sdk Go files", 1, func() ([]string, error) {
		return sdkGoFiles(root)
	})
	if len(mutationBannedCalls) == 0 {
		t.Fatal("mutationBannedCalls is empty — the threat model lost its subjects")
	}
	v, err := mutationChokepointViolations(root)
	if err != nil {
		t.Fatalf("scanning sdk for path-based mutations: %v", err)
	}
	for _, s := range v {
		t.Errorf("%s — SDK-7: privileged mutations are fd-anchored and symlink-refusing; route through the fsafe helpers (M3)", s)
	}
}

// TestGuard_MutationChokepoint_Liveness: plain chmod/rename and an aliased
// RemoveAll are flagged; the OpenFile decoy and the helpers package's own
// mutation stay clean.
func TestGuard_MutationChokepoint_Liveness(t *testing.T) {
	RequireViolation(t, "mutation chokepoint", mutationChokepointViolations, "testdata/sdkcore/mutation")
	v, err := mutationChokepointViolations("testdata/sdkcore/mutation")
	if err != nil {
		t.Fatalf("scanning the mutation fixture: %v", err)
	}
	requireFlagged(t, v,
		[]string{"bad.go:8", "bad.go:11", "aliased_bad.go:6", "temp_bad.go:12", "temp_bad.go:15", "temp_bad.go:18"},
		[]string{"decoy.go", "fsafe/anchored.go"})
}

// TestGuard_ClockSeam is SPEC-004 G-9 (SPEC-000 cross-cutting): no
// unabstracted time.Now in sdk — instants come from the injected clock. No
// separate SetDeadline scan: a seam-less deadline is caught at its
// time.Now argument (the clock fixture plants exactly that case), and a
// deadline computed from the injected clock is legal (plan choice 8).
//
// INV-16 scope: THIS guard proves the clock-seam half in sdk. The C-locale
// Runner-invariant half arms at M2 (Runner tests, AC-3); the
// protojson-only half is SPEC-003's G-6 in contract/archtest — extend
// there, never weaken here.
//
// Guards: INV-16.
func TestGuard_ClockSeam(t *testing.T) {
	root := sdkRoot(t)
	Discover(t, "sdk Go files", 1, func() ([]string, error) {
		return sdkGoFiles(root)
	})
	v, err := clockViolations(root)
	if err != nil {
		t.Fatalf("scanning sdk for time.Now: %v", err)
	}
	for _, s := range v {
		t.Errorf("%s — INV-16: everything time-dependent takes the clock seam, including SetDeadline arguments", s)
	}
}

// TestGuard_ClockSeam_Liveness: plain, aliased, dot-imported,
// parenthesized, closure-wrapped, and SetDeadline-argument calls are
// flagged; the injected-clock file and the fake-time decoy stay clean.
func TestGuard_ClockSeam_Liveness(t *testing.T) {
	RequireViolation(t, "time.Now ban in sdk", clockViolations, "testdata/astban/clock")
	v, err := clockViolations("testdata/astban/clock")
	if err != nil {
		t.Fatalf("scanning the clock fixture: %v", err)
	}
	requireFlagged(t, v,
		[]string{"bad.go:10", "bad.go:13", "aliased_bad.go:6", "dot_bad.go:6", "paren_bad.go:8", "paren_bad.go:10"},
		[]string{"decoy.go", "clean.go"})
}
