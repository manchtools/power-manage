package guardtest

// SPEC-002 M3: per-binary config-adoption discovery (G-002-5, CFG-1).
// Binaries are main packages under a module's cmd/ tree — the repo's
// shipped-binary convention; each must import the shared loader.
// ponytail: a main package elsewhere is not a shipped binary (recorded
// ceiling), and import presence is the check — the round-trip proof is
// the per-binary test demanded as binaries land.

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
// mods and a violation for each that never imports loaderPath.
func binaryAdoptionViolations(root string, mods []string, loaderPath string) (violations, binaries []string, err error) {
	for _, mod := range mods {
		adopted := map[string]bool{}
		err := walkGoFiles(filepath.Join(root, mod), false, func(rel string, _ *token.FileSet, file *ast.File) error {
			dir := path.Dir(rel)
			if file.Name.Name != "main" || (dir != "cmd" && !strings.HasPrefix(dir, "cmd/")) {
				return nil
			}
			bin := mod + "/" + dir
			if _, seen := adopted[bin]; !seen {
				adopted[bin] = false
			}
			for _, imp := range file.Imports {
				if p, uerr := strconv.Unquote(imp.Path.Value); uerr == nil && p == loaderPath {
					adopted[bin] = true
				}
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
		for bin, ok := range adopted {
			binaries = append(binaries, bin)
			if !ok {
				violations = append(violations, fmt.Sprintf("%s: main package never imports %s — each binary boots one typed config struct through the shared loader [INV-18/CFG-1]", bin, loaderPath))
			}
		}
	}
	sort.Strings(violations)
	sort.Strings(binaries)
	return violations, binaries, nil
}
