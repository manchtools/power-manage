package guardtest

// SPEC-002 M3: environment-read discovery for the env-hygiene guard
// (G-002-4, INV-18/CFG-2). Reads resolve through each file's actual os
// import — an aliased or dot import cannot evade, and a same-named
// symbol from an unrelated package is not flagged — and are attributed
// to their enclosing declaration; the allowlist is keyed by that
// identity.

import (
	"fmt"
	"go/ast"
	"go/token"
)

// envReadSite is one discovered read of the process environment.
type envReadSite struct {
	Pos  string // "<rel-file>:<line>" of the call
	Key  string // "<rel-file>:<enclosing-decl>" — the allowlist key
	Func string // the os function called
}

// envReadFuncs is the test-owned ban set: the spec's
// Getenv/LookupEnv/Environ [INV-18] plus ExpandEnv, which reads the
// environment identically. Writes are not config inputs. Recorded
// ceiling: syscall/x-sys env access and indirect references
// (f := os.Getenv; f(...)) are not matched — the BannedCalls ceiling
// class.
var envReadFuncs = map[string]bool{
	"Getenv": true, "LookupEnv": true, "Environ": true, "ExpandEnv": true,
}

// envReadAllowlist keys the sanctioned readers by declaration identity;
// every entry states why it may read the environment [CFG-2].
var envReadAllowlist = map[string]string{
	"sdk/config/config.go:applyEnv": "the INV-18 loader's single environment pass — reads derived PM_* names and rejects strays (SPEC-002 §3.5); the SPEC-004 Runner child-env builder joins here when it lands",
}

// envReadSites returns every process-environment read in non-test Go
// files under root, attributed to its enclosing declaration.
func envReadSites(root string) ([]envReadSite, error) {
	var sites []envReadSite
	err := walkGoFiles(root, false, func(rel string, fset *token.FileSet, file *ast.File) error {
		names, dot := importAliases(file, "os")
		if len(names) == 0 && !dot {
			return nil
		}
		for _, decl := range file.Decls {
			for _, u := range declUnits(decl) {
				ast.Inspect(u.node, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					var fn string
					switch f := unwrapExpr(call.Fun).(type) {
					case *ast.Ident:
						if dot && envReadFuncs[f.Name] {
							fn = f.Name
						}
					case *ast.SelectorExpr:
						if id, ok := f.X.(*ast.Ident); ok && names[id.Name] && envReadFuncs[f.Sel.Name] {
							fn = f.Sel.Name
						}
					}
					if fn != "" {
						sites = append(sites, envReadSite{
							Pos:  fmt.Sprintf("%s:%d", rel, fset.Position(call.Pos()).Line),
							Key:  rel + ":" + u.name,
							Func: fn,
						})
					}
					return true
				})
			}
		}
		return nil
	})
	return sites, err
}
