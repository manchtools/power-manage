package guardtest

// SPEC-003 M1: G-6 — stdlib encoding/json must never touch a proto
// message ([WIRE-10]: it silently mis-serializes oneofs and enums).
// Grammar (recorded ceiling): a file that imports BOTH encoding/json and
// a generated contract package is a violation; call-site type analysis is
// out of scope. A file that legitimately needs both marshals its protos
// with protojson and earns an identity-keyed allowlist entry with a
// rationale — an allowlist that grows silently is the hand-maintained
// list returning through the back door.

import (
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
	"strings"
)

const contractGenPrefix = "github.com/manchtools/power-manage/contract/gen/"

// protojsonAllowed: rel path → rationale. Empty until a sanctioned mixed
// use exists; every entry must say why stdlib JSON near proto types is
// safe there.
var protojsonAllowed = map[string]string{}

// protojsonViolations flags every Go file under root importing both
// encoding/json and a generated contract package.
func protojsonViolations(root string) ([]string, error) {
	var out []string
	err := walkAllGoFiles(root, func(rel string, _ *token.FileSet, file *ast.File) error {
		if _, ok := protojsonAllowed[rel]; ok {
			return nil
		}
		stdJSON, contractGen := false, false
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return fmt.Errorf("%s: unquoting import %s: %w", rel, imp.Path.Value, err)
			}
			switch {
			case path == "encoding/json":
				stdJSON = true
			case strings.HasPrefix(path, contractGenPrefix):
				contractGen = true
			}
		}
		if stdJSON && contractGen {
			out = append(out, fmt.Sprintf("%s: imports both encoding/json and the generated contract package — stdlib JSON silently mis-serializes oneofs and enums; marshal protos with protojson [WIRE-10] (G-6, SPEC-003)", rel))
		}
		return nil
	})
	return out, err
}
