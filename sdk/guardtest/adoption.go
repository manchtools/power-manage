package guardtest

// SPEC-002 M3+M4: per-binary config-adoption discovery (G-002-5/G-002-6,
// CFG-1). Binaries are main packages under a module's cmd/ tree — the
// repo's shipped-binary convention; each must import the shared loader
// (`:import` class) and carry a test in its package calling the loader's
// Doc so its committed config reference stays fresh (`:docs` class).
// ponytail: a main package elsewhere is not a shipped binary (recorded
// ceiling), and presence is the check — the round-trip and golden proofs
// are the per-binary tests demanded as binaries land.

import (
	"fmt"
	"go/ast"
	"go/token"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// binaryAdoptionViolations returns the discovered cmd/ binaries across
// mods and a class-qualified violation for each that never imports
// loaderPath (`:import`) or has no test calling the loader's Doc
// (`:docs`).
func binaryAdoptionViolations(root string, mods []string, loaderPath string) (violations, binaries []string, err error) {
	for _, mod := range mods {
		imported := map[string]bool{}
		docsTested := map[string]bool{}
		err := walkGoFiles(filepath.Join(root, mod), false, func(rel string, _ *token.FileSet, file *ast.File) error {
			dir := path.Dir(rel)
			if file.Name.Name != "main" || (dir != "cmd" && !strings.HasPrefix(dir, "cmd/")) {
				return nil
			}
			bin := mod + "/" + dir
			if _, seen := imported[bin]; !seen {
				imported[bin] = false
			}
			for _, imp := range file.Imports {
				if p, uerr := strconv.Unquote(imp.Path.Value); uerr == nil && p == loaderPath {
					imported[bin] = true
				}
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
		// The non-test pass above registered every binary dir, so a test
		// file elsewhere in cmd/ cannot mint a phantom binary here.
		err = walkGoFiles(filepath.Join(root, mod), true, func(rel string, _ *token.FileSet, file *ast.File) error {
			bin := mod + "/" + path.Dir(rel)
			if _, isBin := imported[bin]; !isBin {
				return nil
			}
			names, dot := importAliases(file, loaderPath)
			if len(names) == 0 && !dot {
				return nil
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch f := unwrapExpr(call.Fun).(type) {
				case *ast.Ident:
					if dot && f.Name == "Doc" {
						docsTested[bin] = true
					}
				case *ast.SelectorExpr:
					if id, ok := f.X.(*ast.Ident); ok && names[id.Name] && f.Sel.Name == "Doc" {
						docsTested[bin] = true
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
		for bin, ok := range imported {
			binaries = append(binaries, bin)
			if !ok {
				violations = append(violations, fmt.Sprintf("%s:import: main package never imports %s — each binary boots one typed config struct through the shared loader [INV-18/CFG-1]", bin, loaderPath))
			}
			if !docsTested[bin] {
				violations = append(violations, fmt.Sprintf("%s:docs: no test in the binary's package calls the loader's Doc — the committed config reference cannot stay fresh [INV-18/AC-6]", bin))
			}
		}
	}
	sort.Strings(violations)
	sort.Strings(binaries)
	return violations, binaries, nil
}
