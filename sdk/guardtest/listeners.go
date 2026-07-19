package guardtest

// SPEC-001 M2: listener/serve call-site discovery and the boundary-registry
// join (G-001-2). Package functions resolve through each file's actual
// imports (importAliases + unwrapExpr, astban.go); serve-family METHOD
// calls are matched by name on any receiver that is not an imported
// package name.
// ponytail: method matching is name-only (recorded ceiling — a local var
// shadowing an import alias, or an innocent method named Serve, needs
// go/types to resolve); any hit either registers against its boundary or
// renames.

import (
	"fmt"
	"go/ast"
	"go/token"
	"path"
	"sort"
	"strconv"
)

// ListenerRegistrations is the G-001-2 registration API: owning specs map
// each listener/serve call site ("<repo-rel-file>:<enclosing-func>") to
// exactly one boundary ID from Boundaries as their listeners land. One
// registration covers every listen call inside that function (recorded
// ceiling: a function serving two boundaries cannot be expressed — split
// the function).
var ListenerRegistrations = map[string]string{}

// ListenerSite is one discovered listen/serve call site.
type ListenerSite struct {
	Pos string // "<rel-file>:<line>" of the call
	Key string // "<rel-file>:<enclosing-func>" — the registration key
}

// listenerPkgFuncs are the listener-creating package functions, resolved
// through imports of the keyed import path.
var listenerPkgFuncs = map[string]map[string]bool{
	"net": {"Listen": true, "ListenTCP": true, "ListenUDP": true, "ListenIP": true,
		"ListenUnix": true, "ListenUnixgram": true, "ListenPacket": true, "FileListener": true},
	"crypto/tls": {"Listen": true, "NewListener": true},
	"net/http":   {"ListenAndServe": true, "ListenAndServeTLS": true, "Serve": true, "ServeTLS": true},
}

// serveMethodNames are matched as METHOD calls on non-package receivers —
// (*http.Server).ListenAndServe, net.ListenConfig.Listen, grpc-style
// Serve(lis), and any custom server.
var serveMethodNames = map[string]bool{
	"Listen": true, "ListenAndServe": true, "ListenAndServeTLS": true,
	"Serve": true, "ServeTLS": true,
}

// ListenerSites discovers every listener/serve call site in non-test Go
// files under root (testdata and hidden directories excluded by the shared
// walk).
func ListenerSites(root string) ([]ListenerSite, error) {
	var sites []ListenerSite
	err := walkGoFiles(root, false, func(rel string, fset *token.FileSet, file *ast.File) error {
		type pkgRef struct {
			names map[string]bool
			dot   bool
			funcs map[string]bool
		}
		var refs []pkgRef
		for p, funcs := range listenerPkgFuncs {
			names, dot := importAliases(file, p)
			if len(names) > 0 || dot {
				refs = append(refs, pkgRef{names, dot, funcs})
			}
		}
		imported := map[string]bool{}
		for _, imp := range file.Imports {
			switch {
			case imp.Name == nil:
				if p, uerr := strconv.Unquote(imp.Path.Value); uerr == nil {
					imported[path.Base(p)] = true
				}
			case imp.Name.Name != "." && imp.Name.Name != "_":
				imported[imp.Name.Name] = true
			}
		}
		for _, decl := range file.Decls {
			name, body := declNameAndNode(decl)
			if body == nil {
				continue
			}
			ast.Inspect(body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				flagged := false
				switch f := unwrapExpr(call.Fun).(type) {
				case *ast.Ident:
					for _, r := range refs {
						if r.dot && r.funcs[f.Name] {
							flagged = true
						}
					}
				case *ast.SelectorExpr:
					if id, ok := f.X.(*ast.Ident); ok {
						for _, r := range refs {
							if r.names[id.Name] && r.funcs[f.Sel.Name] {
								flagged = true
							}
						}
						if !flagged && !imported[id.Name] && serveMethodNames[f.Sel.Name] {
							flagged = true
						}
					} else if serveMethodNames[f.Sel.Name] {
						flagged = true
					}
				}
				if flagged {
					sites = append(sites, ListenerSite{
						Pos: fmt.Sprintf("%s:%d", rel, fset.Position(call.Pos()).Line),
						Key: rel + ":" + name,
					})
				}
				return true
			})
		}
		return nil
	})
	return sites, err
}

// declNameAndNode returns the registration name and inspectable node for a
// top-level declaration: a function's name and body, or a var/const spec's
// first name (closures assigned at file scope register under the var name).
func declNameAndNode(decl ast.Decl) (string, ast.Node) {
	switch d := decl.(type) {
	case *ast.FuncDecl:
		if d.Body == nil {
			return "", nil
		}
		return d.Name.Name, d.Body
	case *ast.GenDecl:
		for _, spec := range d.Specs {
			if vs, ok := spec.(*ast.ValueSpec); ok && len(vs.Names) > 0 && len(vs.Values) > 0 {
				return vs.Names[0].Name, d
			}
		}
	}
	return "", nil
}

// boundaryJoinViolations is the exact-set join: every site registered
// against a known boundary, every registration backed by a live site.
func boundaryJoinViolations(sites []ListenerSite, regs, boundaries map[string]string) []string {
	var out []string
	live := map[string]bool{}
	for _, s := range sites {
		live[s.Key] = true
		b, ok := regs[s.Key]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("%s: unregistered listener/serve call site — register %q in guardtest.ListenerRegistrations against exactly one boundary B1–B11", s.Pos, s.Key))
		case boundaries[b] == "":
			out = append(out, fmt.Sprintf("%s: site %q registered against unknown boundary %q — Boundaries is the normative set", s.Pos, s.Key, b))
		}
	}
	for key, b := range regs {
		if !live[key] {
			out = append(out, fmt.Sprintf("%s: orphan registration (%s) — no matching listener call site; the surface moved under it", key, b))
		}
	}
	sort.Strings(out)
	return out
}
