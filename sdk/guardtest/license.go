package guardtest

// SPEC-002 M1: the license-layout guard (G-002-3). Discovery ground truth is
// go.work — the same file that defines the workspace — never a hand-listed
// set of module directories.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// contractManifestLicense returns the license field of the contract
// module's TS package manifest (AC-9, [LIC-4]); a missing or unparsable
// manifest is an error, never an empty pass.
func contractManifestLicense(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "contract", "package.json"))
	if err != nil {
		return "", fmt.Errorf("reading the contract TS manifest: %w", err)
	}
	var m struct {
		License string `json:"license"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return "", fmt.Errorf("parsing contract/package.json: %w", err)
	}
	return m.License, nil
}

// moduleLicenses is the normative [LIC-1] module→license mapping. A go.work
// module with no entry here is a violation (fail closed): a fifth module
// cannot land unlicensed or silently inherit a neighbor's terms.
var moduleLicenses = map[string]string{
	"contract": "MIT",      // dependency leaf with three consumers; permissive→copyleft inclusion stays legal [LIC-3]
	"sdk":      "MIT",      // dependency leaf, pure mechanism [LIC-3]
	"server":   "AGPL-3.0", // network-service copyleft [LIC-1]
	"agent":    "GPL-3.0",  // must be v3: Apache-2.0 Go deps are GPLv2-incompatible [LIC-1]
}

// workspaceModules returns the module directory names from root's go.work
// use directives (block and single-line, comments stripped).
func workspaceModules(root string) ([]string, error) {
	src, err := os.ReadFile(filepath.Join(root, "go.work"))
	if err != nil {
		return nil, fmt.Errorf("reading go.work: %w", err)
	}
	var mods []string
	inBlock := false
	for _, line := range strings.Split(string(src), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "use (":
			inBlock = true
		case inBlock && line == ")":
			inBlock = false
		case inBlock && line != "":
			mods = append(mods, strings.TrimPrefix(line, "./"))
		case strings.HasPrefix(line, "use "):
			mods = append(mods, strings.TrimPrefix(strings.TrimSpace(strings.TrimPrefix(line, "use ")), "./"))
		}
	}
	return mods, nil
}

// licenseIdentity classifies a license text by its header phrases: "MIT",
// "AGPL-3.0", "GPL-3.0", or "" for anything unrecognized. AGPL is checked
// before GPL (its header contains the GPL family name pattern), and GPL/AGPL
// require Version 3 — the agent must be v3 [LIC-1], so v2 texts stay
// unclassified and surface as identity violations.
func licenseIdentity(text string) string {
	switch {
	case strings.Contains(text, "GNU AFFERO GENERAL PUBLIC LICENSE"):
		if strings.Contains(text, "Version 3") {
			return "AGPL-3.0"
		}
	case strings.Contains(text, "GNU GENERAL PUBLIC LICENSE"):
		if strings.Contains(text, "Version 3") {
			return "GPL-3.0"
		}
	case strings.Contains(text, "MIT License"),
		strings.Contains(text, "Permission is hereby granted, free of charge"):
		return "MIT"
	}
	return ""
}

// licenseLayoutViolations checks the [LIC-1]/[LIC-2] layout under root for
// the given workspace modules: per-module LICENSE presence and identity, no
// top-level license file, and a README that names each module's license and
// carries the outside-the-modules MIT grant.
// ponytail: the grant probe pins the current README phrases — if the wording
// is ever rewritten, the guard fires and the probe is updated consciously.
func licenseLayoutViolations(root string, mods []string) ([]string, error) {
	var out []string
	for _, name := range []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"} {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			out = append(out, fmt.Sprintf("%s: top-level license file exists — the root carries only the README mapping; remove it [LIC-2]", name))
		}
	}
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		out = append(out, "README.md missing — it carries the module→license mapping and the root MIT grant [LIC-2]")
	}
	for _, mod := range mods {
		want, classified := moduleLicenses[mod]
		if !classified {
			out = append(out, fmt.Sprintf("%s: module not in the license mapping — a new module needs a [LIC-1] classification and README row first", mod))
			continue
		}
		lic, lerr := os.ReadFile(filepath.Join(root, mod, "LICENSE"))
		switch {
		case os.IsNotExist(lerr):
			out = append(out, fmt.Sprintf("%s: LICENSE file missing — every module directory carries its own license [LIC-1]", mod))
		case lerr != nil:
			return nil, fmt.Errorf("reading %s/LICENSE: %w", mod, lerr)
		default:
			if got := licenseIdentity(string(lic)); got != want {
				out = append(out, fmt.Sprintf("%s: LICENSE identity %q, want %q — the module license mapping is normative [LIC-1]", mod, got, want))
			}
		}
		if err == nil && !readmeNamesLicense(string(readme), mod, want) {
			out = append(out, fmt.Sprintf("README.md:%s: no table row naming the module's license (%s) [LIC-2]", mod, want))
		}
	}
	if err == nil && !(strings.Contains(string(readme), "outside the four module directories") &&
		strings.Contains(string(readme), "MIT License")) {
		out = append(out, "README.md:grant: MIT grant for content outside the module directories not found [LIC-2]")
	}
	sort.Strings(out)
	return out, nil
}

// readmeNamesLicense reports whether some README line names both the module
// directory and its license — the shape of the mapping table's rows.
func readmeNamesLicense(readme, mod, license string) bool {
	for _, line := range strings.Split(readme, "\n") {
		if strings.Contains(line, "`"+mod+"/`") && strings.Contains(line, license) {
			return true
		}
	}
	return false
}
