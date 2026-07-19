package guardtest

// SPEC-002 M2: the directional-import archtest (G-002-1, INV-19) and the
// proto-purity archtest (G-002-2, SDK-0). Modules come from go.work, module
// identities from each go.mod's module line, packages and imports from the
// file walk — import PATHS are matched, so aliased/blank/dot imports cannot
// evade. Test files are included: a test importing a forbidden module links
// the same code.

import (
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// importAllowlist is the normative SPEC-002 §3.3 table. A go.work module
// with no entry here is a violation (fail closed) — a fifth module cannot
// import anything until the table classifies it.
var importAllowlist = map[string][]string{
	"contract": nil,                 // wire contract: dependency leaf [SDK-0]
	"sdk":      nil,                 // pure OS mechanism: dependency leaf [SDK-0]
	"agent":    {"contract", "sdk"}, // GPL binary: server (AGPL) import would relicense it [LIC-3]
	"server":   {"contract", "sdk"},
}

// modulePackageFloors ratchets as specs land code: sdk carries guardtest
// today; contract/server/agent gain their floors with SPEC-003/005/013.
// A code-bearing module can never silently drop to zero packages.
var modulePackageFloors = map[string]int{"contract": 0, "sdk": 1, "server": 0, "agent": 0}

// modulePaths returns each module dir's declared module path from its
// go.mod module line.
func modulePaths(root string, mods []string) (map[string]string, error) {
	paths := map[string]string{}
	for _, mod := range mods {
		src, err := os.ReadFile(filepath.Join(root, mod, "go.mod"))
		if err != nil {
			return nil, fmt.Errorf("reading %s/go.mod: %w", mod, err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			if p, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
				paths[mod] = strings.TrimSpace(p)
				break
			}
		}
		if paths[mod] == "" {
			return nil, fmt.Errorf("%s/go.mod declares no module path", mod)
		}
	}
	return paths, nil
}

// walkAllGoFiles visits non-test AND test files: walkGoFiles's testFiles
// flag is either/or, and the archtests need both — a test importing a
// forbidden module links the same code.
func walkAllGoFiles(root string, visit func(rel string, fset *token.FileSet, file *ast.File) error) error {
	for _, testFiles := range []bool{false, true} {
		if err := walkGoFiles(root, testFiles, visit); err != nil {
			return err
		}
	}
	return nil
}

// importedModule maps an import path to the module dir it belongs to
// (exact match or "/"-boundary prefix), or "" for out-of-workspace imports.
func importedModule(imp string, paths map[string]string) string {
	for dir, p := range paths {
		if imp == p || strings.HasPrefix(imp, p+"/") {
			return dir
		}
	}
	return ""
}

// directionalImportViolations walks every module's Go files (tests
// included) and returns INV-19 allowlist violations plus the package dirs
// seen per module (the discovery floor's subjects).
func directionalImportViolations(root string, mods []string) ([]string, map[string][]string, error) {
	paths, err := modulePaths(root, mods)
	if err != nil {
		return nil, nil, err
	}
	var out []string
	pkgs := map[string][]string{}
	for _, mod := range mods {
		allow, classified := importAllowlist[mod]
		if !classified {
			out = append(out, fmt.Sprintf("%s: module not in the §3.3 import allowlist — a new module needs a classification first [INV-19]", mod))
			continue
		}
		allowed := map[string]bool{}
		for _, a := range allow {
			allowed[a] = true
		}
		seenPkg := map[string]bool{}
		err := walkAllGoFiles(filepath.Join(root, mod), func(rel string, fset *token.FileSet, file *ast.File) error {
			if dir := filepath.ToSlash(filepath.Dir(rel)); !seenPkg[dir] {
				seenPkg[dir] = true
				pkgs[mod] = append(pkgs[mod], dir)
			}
			for _, imp := range file.Imports {
				p, uerr := strconv.Unquote(imp.Path.Value)
				if uerr != nil {
					continue
				}
				target := importedModule(p, paths)
				if target == "" || target == mod || allowed[target] {
					continue
				}
				out = append(out, fmt.Sprintf("%s/%s:%d: %s imports %s (%q) — outside the §3.3 allowlist [INV-19]",
					mod, rel, fset.Position(imp.Path.Pos()).Line, mod, target, p))
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
		sort.Strings(pkgs[mod])
	}
	sort.Strings(out)
	return out, pkgs, nil
}

// protoImportPrefixes marks the proto/connect/protobuf families banned from
// sdk [SDK-0]. The set is a test-owned threat model — a new family means a
// new prefix WITH a threat-model entry. grpc is included: a grpc import is
// a proto dependency by construction. Transitive proto reach through an
// innocent-named wrapper is a recorded ceiling — import paths are what the
// scan sees; the module's go.mod stays the reviewable second line.
var protoImportPrefixes = []string{
	"google.golang.org/protobuf",
	"github.com/golang/protobuf", // legacy APIv1 proto bindings — deprecated but still importable, same family
	"github.com/gogo/protobuf",   // gogo proto family
	"google.golang.org/genproto",
	"google.golang.org/grpc",
	"connectrpc.com",
	"buf.build/gen",
	"github.com/manchtools/power-manage/contract",
}

// protoImportToken returns the banned-family prefix an import path matches,
// or "" for a clean import.
func protoImportToken(imp string) string {
	for _, p := range protoImportPrefixes {
		if imp == p || strings.HasPrefix(imp, p+"/") {
			return p
		}
	}
	return ""
}

// protoPurityViolations walks the Go files under sdkRoot (tests included)
// and returns SDK-0 violations plus the package dirs seen.
func protoPurityViolations(sdkRoot string) ([]string, []string, error) {
	var out, pkgs []string
	seenPkg := map[string]bool{}
	err := walkAllGoFiles(sdkRoot, func(rel string, fset *token.FileSet, file *ast.File) error {
		if dir := filepath.ToSlash(filepath.Dir(rel)); !seenPkg[dir] {
			seenPkg[dir] = true
			pkgs = append(pkgs, dir)
		}
		for _, imp := range file.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}
			if tok := protoImportToken(p); tok != "" {
				out = append(out, fmt.Sprintf("%s:%d: sdk imports %q (family %s) — SDK-0: pure OS mechanism, zero proto/connect/protobuf",
					rel, fset.Position(imp.Path.Pos()).Line, p, tok))
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(out)
	sort.Strings(pkgs)
	return out, pkgs, nil
}
