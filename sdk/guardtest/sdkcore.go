package guardtest

// SPEC-004 M1 sdk-core scans (G-3..G-7, G-9), composed from the astban
// primitives. The future-package prefixes (redos, crypto, fsafe) are
// recorded here BEFORE those packages exist so their guards fail closed on
// day one: code cannot grow outside a chokepoint that is already the only
// allowed location.

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"
)

// Sanctioned package prefixes under the sdk root (plan choices 4, 5, 7).
const (
	redosPkgDir  = "redos"  // SDK-6 ReDoS chokepoint, lands M2
	cryptoPkgDir = "crypto" // SDK-13 AEAD/hash surface, lands M5
	fsafePkgDir  = "fsafe"  // SDK-7 fd-anchored helpers, lands M3
)

// randJitterAllow is the INV-8 jitter allowlist — empty until the jitter
// package lands (M2); each addition carries its rationale here.
var randJitterAllow []string

// regexCompileAllowlist sanctions compile sites outside the redos
// chokepoint, keyed by "file:decl" identity so a moved or renamed site
// loses its exemption (never by whole file). The guard also fails on
// orphaned keys.
var regexCompileAllowlist = map[string]string{
	"guardtest/secrets.go:secretNameRe":       "compile-time literal owned by the guard suite itself — never operator input; the chokepoint governs capability packages",
	"guardtest/secrets.go:secretPathSuffixRe": "compile-time literal owned by the guard suite itself — never operator input; the chokepoint governs capability packages",
}

// regexCompileFns is the regexp constructor family (SDK-6): all four
// compile entry points — the POSIX variants must not slip the net.
var regexCompileFns = map[string]bool{
	"Compile":          true,
	"CompilePOSIX":     true,
	"MustCompile":      true,
	"MustCompilePOSIX": true,
}

// hashImportPaths is the SDK-13 hash/MAC construction surface confined to
// the crypto package at M1 (import-level; per-construction framing arms
// at M5).
var hashImportPaths = []string{"crypto/sha256", "crypto/sha512", "crypto/hmac"}

// mutationBannedCalls is the SDK-7 path-based mutation set banned outside
// fsafe. Recorded ceiling: os.OpenFile stays legal — it is the fd-anchored
// primitive itself; clobber-flag inspection anchors on the fsafe prefix at
// M3.
var mutationBannedCalls = []string{
	"Chmod", "Chown", "Lchown", "Rename", "Remove", "RemoveAll",
	"Truncate", "WriteFile", "Symlink", "Link", "Mkdir", "MkdirAll",
	"Create", "CreateTemp", "MkdirTemp", "Chtimes",
}

// sdkGoFiles lists the non-test Go files under root — the scanned-file
// population backing the matches-zero floors of the M1 guards.
func sdkGoFiles(root string) ([]string, error) {
	var out []string
	err := walkGoFiles(root, false, func(rel string, _ *token.FileSet, _ *ast.File) error {
		out = append(out, rel)
		return nil
	})
	return out, err
}

// randomnessViolations is G-3: both math/rand generations banned outside
// the jitter allowlist.
func randomnessViolations(root string) ([]string, error) {
	v1, err := BannedImports(root, "math/rand", randJitterAllow...)
	if err != nil {
		return nil, err
	}
	v2, err := BannedImports(root, "math/rand/v2", randJitterAllow...)
	if err != nil {
		return nil, err
	}
	return append(v1, v2...), nil
}

// clockViolations is G-9: no unabstracted time.Now under root (a seam-less
// SetDeadline is caught at its time.Now argument).
func clockViolations(root string) ([]string, error) {
	return BannedCalls(root, "time", "Now")
}

// hashImportViolations is G-5's M1 form: hash/MAC package imports outside
// the crypto dir.
func hashImportViolations(root string) ([]string, error) {
	var out []string
	for _, p := range hashImportPaths {
		v, err := BannedImports(root, p, cryptoPkgDir)
		if err != nil {
			return nil, err
		}
		out = append(out, v...)
	}
	return out, nil
}

// mutationChokepointViolations is G-7: the banned os mutation set outside
// the fsafe prefix.
func mutationChokepointViolations(root string) ([]string, error) {
	var out []string
	for _, fn := range mutationBannedCalls {
		v, err := BannedCalls(root, "os", fn, fsafePkgDir)
		if err != nil {
			return nil, err
		}
		out = append(out, v...)
	}
	return out, nil
}

// regexChokepointViolations is G-4: every regexp constructor call outside
// the redos prefix, resolved through the file's real imports (alias and
// dot included). It returns the violations and ALL discovered site keys
// ("file:decl") — the guard uses the latter for its population floor and
// its orphaned-allowlist check. allow maps site keys to their rationale.
func regexChokepointViolations(root string, allow map[string]string) ([]string, []string, error) {
	var out, sites []string
	err := walkGoFiles(root, false, func(rel string, fset *token.FileSet, file *ast.File) error {
		if pathAllowed(rel, []string{redosPkgDir}) {
			return nil
		}
		names, dot := importAliases(file, "regexp")
		if len(names) == 0 && !dot {
			return nil
		}
		matched := func(call *ast.CallExpr) bool {
			switch f := unwrapExpr(call.Fun).(type) {
			case *ast.Ident:
				return dot && regexCompileFns[f.Name]
			case *ast.SelectorExpr:
				id, ok := f.X.(*ast.Ident)
				return ok && names[id.Name] && regexCompileFns[f.Sel.Name]
			}
			return false
		}
		inspect := func(n ast.Node, declName string) {
			ast.Inspect(n, func(m ast.Node) bool {
				call, ok := m.(*ast.CallExpr)
				if !ok || !matched(call) {
					return true
				}
				key := rel + ":" + declName
				sites = append(sites, key)
				if _, sanctioned := allow[key]; !sanctioned {
					out = append(out, fmt.Sprintf("%s:%d: regexp compile outside the redos chokepoint (SDK-6)", rel, fset.Position(call.Pos()).Line))
				}
				return true
			})
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				// Methods key receiver-qualified (probe.rx) so a same-named
				// package var can never share or steal their exemption.
				name := d.Name.Name
				if d.Recv != nil && len(d.Recv.List) > 0 {
					name = recvTypeName(d.Recv.List[0].Type) + "." + name
				}
				inspect(d, name)
			case *ast.GenDecl:
				// Keyed per ValueSpec, not per block: one var's exemption
				// must not cover its neighbors.
				for _, spec := range d.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok && len(vs.Names) > 0 {
						inspect(vs, vs.Names[0].Name)
					}
				}
			}
		}
		return nil
	})
	return out, sites, err
}

// recvTypeName names a method receiver's base type, peeling pointers,
// parens, and generic instantiation.
func recvTypeName(e ast.Expr) string {
	for {
		switch t := e.(type) {
		case *ast.StarExpr:
			e = t.X
		case *ast.ParenExpr:
			e = t.X
		case *ast.IndexExpr:
			e = t.X
		case *ast.IndexListExpr:
			e = t.X
		case *ast.Ident:
			return t.Name
		default:
			return "?"
		}
	}
}

// aadAPIViolations is G-6: every exported function or method under
// cryptoRoot whose name contains Seal or Open must carry a parameter named
// aad. AST walk by design (plan choice 6): it covers violation fixtures a
// reflection walk could never link, and fails closed — a renamed AAD
// parameter is flagged, never silently passed. Returns the violations and
// the discovered surface for the population floor.
func aadAPIViolations(cryptoRoot string) ([]string, []string, error) {
	var out, fns []string
	err := walkGoFiles(cryptoRoot, false, func(rel string, fset *token.FileSet, file *ast.File) error {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				name := d.Name.Name
				if !d.Name.IsExported() || !sealOpenName(name) {
					continue
				}
				fns = append(fns, rel+":"+name)
				if !funcTypeHasAAD(d.Type) {
					out = append(out, fmt.Sprintf("%s:%d: exported %s has no aad parameter — no nil-AAD API exists (SDK-13)", rel, fset.Position(d.Pos()).Line, name))
				}
			case *ast.GenDecl:
				// Interface methods declare API surface too (review
				// finding, PR #20). An embedded interface is decided at
				// its own declaration; embedding one from another package
				// would hide it — the proto-purity and hash-import bans
				// keep foreign seal/open interfaces out of sdk/crypto.
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					it, ok := ts.Type.(*ast.InterfaceType)
					if !ok || it.Methods == nil {
						continue
					}
					for _, m := range it.Methods.List {
						ft, ok := m.Type.(*ast.FuncType)
						if !ok || len(m.Names) == 0 {
							continue
						}
						name := m.Names[0].Name
						if !ast.IsExported(name) || !sealOpenName(name) {
							continue
						}
						fns = append(fns, rel+":"+ts.Name.Name+"."+name)
						if !funcTypeHasAAD(ft) {
							out = append(out, fmt.Sprintf("%s:%d: interface method %s.%s has no aad parameter — no nil-AAD API exists (SDK-13)", rel, fset.Position(m.Pos()).Line, ts.Name.Name, name))
						}
					}
				}
			}
		}
		return nil
	})
	return out, fns, err
}

// sealOpenName reports whether name belongs to the seal/open surface.
func sealOpenName(name string) bool {
	return strings.Contains(name, "Seal") || strings.Contains(name, "Open")
}

// funcTypeHasAAD reports whether the signature carries a parameter named
// aad — the surface contract; a renamed AAD parameter is a violation by
// design (fail closed).
func funcTypeHasAAD(ft *ast.FuncType) bool {
	if ft.Params == nil {
		return false
	}
	for _, field := range ft.Params.List {
		for _, id := range field.Names {
			if id.Name == "aad" {
				return true
			}
		}
	}
	return false
}
