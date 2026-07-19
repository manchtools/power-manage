package guardtest

import (
	"fmt"
	"testing"
)

// TestGuard_LicenseLayout is G-002-3 (SPEC-002 AC-1): every go.work module
// carries its own LICENSE matching the normative [LIC-1] mapping, no
// top-level LICENSE exists, and the root README names each module's license
// and the outside-the-modules MIT grant [LIC-2].
func TestGuard_LicenseLayout(t *testing.T) {
	root := RepoRoot(t)
	mods := Discover(t, "workspace modules from go.work", 4, func() ([]string, error) {
		return workspaceModules(root)
	})
	v, err := licenseLayoutViolations(root, mods)
	if err != nil {
		t.Fatalf("checking the license layout: %v", err)
	}
	for _, s := range v {
		t.Errorf("%s — one accidental relicense is all it takes; fix the layout, never the mapping (SPEC-002 §3.4)", s)
	}
}

// TestGuard_ContractManifestLicense is AC-9 (SPEC-002 [LIC-4]): the
// contract module's TS package manifest declares MIT — the published
// package must carry the contract's license; publication mechanics are
// SPEC-017's.
func TestGuard_ContractManifestLicense(t *testing.T) {
	root := RepoRoot(t)
	lics := Discover(t, "contract TS manifest license", 1, func() ([]string, error) {
		lic, err := contractManifestLicense(root)
		if err != nil {
			return nil, err
		}
		return []string{lic}, nil
	})
	if len(lics) != 1 || lics[0] != "MIT" {
		t.Errorf("contract/package.json license = %v, want exactly MIT [LIC-4]", lics)
	}
}

// TestGuard_ContractManifestLicense_Liveness: a non-MIT manifest carries
// the exact value the guard rejects, and malformed or missing manifests
// error — fail closed, never an empty pass.
func TestGuard_ContractManifestLicense_Liveness(t *testing.T) {
	scan := func(root string) ([]string, error) {
		lic, err := contractManifestLicense(root)
		if err != nil {
			return nil, err
		}
		if lic != "MIT" {
			return []string{fmt.Sprintf("contract/package.json license %q, want MIT [LIC-4]", lic)}, nil
		}
		return nil, nil
	}
	RequireViolation(t, "contract manifest license", scan, "testdata/arch/manifest/nonmit")

	if _, err := contractManifestLicense("testdata/arch/manifest/malformed"); err == nil {
		t.Errorf("malformed manifest parsed cleanly — a broken manifest must fail the guard, not pass it")
	}
	if _, err := contractManifestLicense("testdata/arch/manifest"); err == nil {
		t.Errorf("missing manifest read cleanly — absence must fail the guard, not pass it")
	}
}

// TestGuard_LicenseLayout_Liveness: the bad fixture plants every violation
// class — missing module LICENSE, wrong-identity LICENSE, unclassified
// fifth module, top-level LICENSE, missing README row, missing grant — and
// the good fixture proves the checker is not always-red.
func TestGuard_LicenseLayout_Liveness(t *testing.T) {
	scan := func(root string) ([]string, error) {
		mods, err := workspaceModules(root)
		if err != nil {
			return nil, err
		}
		return licenseLayoutViolations(root, mods)
	}
	RequireViolation(t, "license layout", scan, "testdata/arch/licenses/bad")
	v, err := scan("testdata/arch/licenses/bad")
	if err != nil {
		t.Fatalf("scanning the bad fixture: %v", err)
	}
	requireFlagged(t, v, []string{
		"contract",         // LICENSE file missing
		"agent",            // wrong identity: MIT where GPL-3.0 is required
		"extramod",         // module outside the [LIC-1] mapping
		"LICENSE",          // top-level license file must not exist
		"README.md:server", // README lacks the server row
		"README.md:grant",  // README lacks the root grant
	}, []string{"sdk", "server", "README.md:contract", "README.md:agent"})

	clean, err := scan("testdata/arch/licenses/good")
	if err != nil {
		t.Fatalf("scanning the good fixture: %v", err)
	}
	if len(clean) != 0 {
		t.Fatalf("conforming fixture flagged: %v — the checker went always-red", clean)
	}
}

// TestWorkspaceModules_ParsesForms: block use, single-line use, and comment
// stripping, pinned against the bad fixture's mixed-form go.work.
func TestWorkspaceModules_ParsesForms(t *testing.T) {
	mods, err := workspaceModules("testdata/arch/licenses/bad")
	if err != nil {
		t.Fatalf("workspaceModules: %v", err)
	}
	want := []string{"contract", "sdk", "server", "agent", "extramod"}
	if len(mods) != len(want) {
		t.Fatalf("modules = %v, want %v", mods, want)
	}
	for i, m := range want {
		if mods[i] != m {
			t.Fatalf("modules = %v, want %v", mods, want)
		}
	}
}

// TestLicenseIdentity_ThreatModel: the classifier's phrase set is the threat
// model — each family classified, near-misses (GPLv2, AGPL-vs-GPL) held
// apart, unknown text unclassified.
func TestLicenseIdentity_ThreatModel(t *testing.T) {
	cases := []struct {
		name, text, want string
	}{
		{"mit header", "MIT License\n\nCopyright (c) 2026", "MIT"},
		{"mit grant sentence only", "Permission is hereby granted, free of charge, to any person", "MIT"},
		{"agpl v3", "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007", "AGPL-3.0"},
		{"gpl v3", "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007", "GPL-3.0"},
		{"gpl v2 is not v3", "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991", ""},
		{"agpl v1 is not v3", "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 1, March 2002", ""},
		{"unknown text", "All rights reserved.", ""},
	}
	for _, c := range cases {
		if got := licenseIdentity(c.text); got != c.want {
			t.Errorf("%s: licenseIdentity = %q, want %q", c.name, got, c.want)
		}
	}
}
