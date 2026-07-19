package guardtest

// Portable AST guards (SPEC-000 AC-7): parse-level scans over non-test .go
// files, for owning specs to apply to their modules. All scans resolve
// names through each file's actual imports — an alias does not hide a
// banned symbol, and a same-named symbol from an unrelated package is not
// flagged. Violations are "relpath:line: message"; allow arguments are
// slash-relative path prefixes under root.
//
// ponytail: resolution is syntactic (recorded M2 ceiling) — a local
// declaration shadowing a dot-imported symbol, or a package whose name
// differs from its import-path base, is not resolved; move to go/types if
// that ever bites.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// walkGoFiles visits every parsed .go file under root (test files only
// when testFiles is set), skipping testdata and hidden directories below
// root so fixture trees never leak into a real scan.
func walkGoFiles(root string, testFiles bool, visit func(rel string, fset *token.FileSet, file *ast.File) error) error {
	fset := token.NewFileSet()
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if p != root && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") != testFiles {
			return nil
		}
		file, err := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return fmt.Errorf("rel %s: %w", p, err)
		}
		return visit(filepath.ToSlash(rel), fset, file)
	})
}

// importAliases returns the local identifiers bound to an import of
// importPath in file, and whether a dot-import makes its symbols resolve
// unqualified. A blank import binds no name.
func importAliases(file *ast.File, importPath string) (names map[string]bool, dotImported bool) {
	names = map[string]bool{}
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != importPath {
			// An unquotable path literal cannot be the wanted import.
			continue
		}
		switch {
		case imp.Name == nil:
			names[path.Base(importPath)] = true
		case imp.Name.Name == ".":
			dotImported = true
		case imp.Name.Name == "_":
		default:
			names[imp.Name.Name] = true
		}
	}
	return names, dotImported
}

func pathAllowed(rel string, allow []string) bool {
	for _, a := range allow {
		a = strings.TrimSuffix(a, "/")
		if rel == a || strings.HasPrefix(rel, a+"/") {
			return true
		}
	}
	return false
}

// unwrapExpr peels parenthesization and explicit generic instantiation:
// (pkg.Fn)(), pkg.Fn[T](), and (pkg.Fn[T])() all still denote pkg.Fn.
func unwrapExpr(e ast.Expr) ast.Expr {
	for {
		switch w := e.(type) {
		case *ast.ParenExpr:
			e = w.X
		case *ast.IndexExpr:
			e = w.X
		case *ast.IndexListExpr:
			e = w.X
		default:
			return e
		}
	}
}

// BannedCalls returns every call of pkgPath.fn outside allowed prefixes —
// e.g. ("time", "Now") for the clock seam (a seam-less SetDeadline is
// caught at its time.Now argument), ("context", "Background") for request
// paths.
// Recorded ceiling: an indirect reference (f := pkg.Fn; f(), or pkg.Fn
// passed as a value) is not syntactically detectable at the call site —
// per-value enforcement is the owning spec's behavioral guard.
func BannedCalls(root, pkgPath, fn string, allow ...string) ([]string, error) {
	var out []string
	err := walkGoFiles(root, false, func(rel string, fset *token.FileSet, file *ast.File) error {
		if pathAllowed(rel, allow) {
			return nil
		}
		names, dot := importAliases(file, pkgPath)
		if len(names) == 0 && !dot {
			return nil
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			flagged := false
			switch f := unwrapExpr(call.Fun).(type) {
			case *ast.Ident:
				flagged = dot && f.Name == fn
			case *ast.SelectorExpr:
				id, ok := f.X.(*ast.Ident)
				flagged = ok && names[id.Name] && f.Sel.Name == fn
			}
			if flagged {
				out = append(out, fmt.Sprintf("%s:%d: banned call %s.%s", rel, fset.Position(call.Pos()).Line, pkgPath, fn))
			}
			return true
		})
		return nil
	})
	return out, err
}

// BannedImports returns every import of importPath outside allowed
// prefixes — e.g. ("math/rand") with a jitter allowlist (INV-8; ban
// "math/rand/v2" with a second call), or ("encoding/json") for
// protojson-only (INV-16; import-level ceiling — per-value proto
// enforcement is the owning spec's behavioral guard).
func BannedImports(root, importPath string, allow ...string) ([]string, error) {
	var out []string
	err := walkGoFiles(root, false, func(rel string, fset *token.FileSet, file *ast.File) error {
		if pathAllowed(rel, allow) {
			return nil
		}
		for _, imp := range file.Imports {
			if p, uerr := strconv.Unquote(imp.Path.Value); uerr == nil && p == importPath {
				out = append(out, fmt.Sprintf("%s:%d: banned import %s", rel, fset.Position(imp.Pos()).Line, importPath))
			}
		}
		return nil
	})
	return out, err
}

// SentinelComparisons returns every errors.Is call and ==/!= comparison
// against the named sentinels (map of import path to identifier names,
// e.g. {"database/sql": {"ErrNoRows"}}) outside allowed prefixes — the
// INV-13 ban on raw sentinel recognition outside the recognizer package.
func SentinelComparisons(root string, sentinels map[string][]string, allow ...string) ([]string, error) {
	var out []string
	err := walkGoFiles(root, false, func(rel string, fset *token.FileSet, file *ast.File) error {
		if pathAllowed(rel, allow) {
			return nil
		}
		type ref struct {
			names map[string]bool
			dot   bool
			syms  map[string]bool
		}
		var refs []ref
		for p, syms := range sentinels {
			names, dot := importAliases(file, p)
			if len(names) == 0 && !dot {
				continue
			}
			set := map[string]bool{}
			for _, s := range syms {
				set[s] = true
			}
			refs = append(refs, ref{names, dot, set})
		}
		if len(refs) == 0 {
			return nil
		}
		isSentinel := func(e ast.Expr) bool {
			switch x := unwrapExpr(e).(type) {
			case *ast.SelectorExpr:
				id, ok := x.X.(*ast.Ident)
				if !ok {
					return false
				}
				for _, r := range refs {
					if r.names[id.Name] && r.syms[x.Sel.Name] {
						return true
					}
				}
			case *ast.Ident:
				for _, r := range refs {
					if r.dot && r.syms[x.Name] {
						return true
					}
				}
			}
			return false
		}
		errNames, errDot := importAliases(file, "errors")
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BinaryExpr:
				if (x.Op == token.EQL || x.Op == token.NEQ) && (isSentinel(x.X) || isSentinel(x.Y)) {
					out = append(out, fmt.Sprintf("%s:%d: raw sentinel comparison — use the recognizer (INV-13)", rel, fset.Position(x.Pos()).Line))
				}
			case *ast.CallExpr:
				isErrorsIs := false
				switch f := x.Fun.(type) {
				case *ast.SelectorExpr:
					id, ok := f.X.(*ast.Ident)
					isErrorsIs = ok && errNames[id.Name] && f.Sel.Name == "Is"
				case *ast.Ident:
					isErrorsIs = errDot && f.Name == "Is"
				}
				if isErrorsIs && len(x.Args) == 2 && isSentinel(x.Args[1]) {
					out = append(out, fmt.Sprintf("%s:%d: errors.Is against a raw sentinel — use the recognizer (INV-13)", rel, fset.Position(x.Pos()).Line))
				}
			}
			return true
		})
		return nil
	})
	return out, err
}

// EnumSwitchesWithoutErroringDefault returns every switch statement that
// has a case resolving to a constant imported from one of the generated
// enum import-path prefixes but lacks a default clause containing a
// return or panic (INV-2). The proto-descriptor exhaustiveness guard
// (WIRE-4, SPEC-003) is the deeper companion check.
// ponytail: "erroring" is approximated as any-return-or-panic, and
// dot-imported enum packages are not matched; tighten with go/types if
// that bites.
func EnumSwitchesWithoutErroringDefault(root string, enumPkgPrefixes []string, allow ...string) ([]string, error) {
	var out []string
	err := walkGoFiles(root, false, func(rel string, fset *token.FileSet, file *ast.File) error {
		if pathAllowed(rel, allow) {
			return nil
		}
		enumPkgs := map[string]bool{}
		for _, imp := range file.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}
			for _, pre := range enumPkgPrefixes {
				if !strings.HasPrefix(p, pre) {
					continue
				}
				switch {
				case imp.Name == nil:
					enumPkgs[path.Base(p)] = true
				case imp.Name.Name != "." && imp.Name.Name != "_":
					enumPkgs[imp.Name.Name] = true
				}
			}
		}
		if len(enumPkgs) == 0 {
			return nil
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			enumSwitch := false
			var deflt *ast.CaseClause
			for _, stmt := range sw.Body.List {
				cc, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				if cc.List == nil {
					deflt = cc
					continue
				}
				for _, e := range cc.List {
					if sel, ok := e.(*ast.SelectorExpr); ok {
						if id, ok := sel.X.(*ast.Ident); ok && enumPkgs[id.Name] {
							enumSwitch = true
						}
					}
				}
			}
			if enumSwitch && (deflt == nil || !returnsOrPanics(deflt)) {
				out = append(out, fmt.Sprintf("%s:%d: enum switch without an erroring default (INV-2)", rel, fset.Position(sw.Pos()).Line))
			}
			return true
		})
		return nil
	})
	return out, err
}

// returnsOrPanics reports whether the clause body itself contains a return
// statement or a panic call. Nested function literals are not descended
// into — their returns do not make the enclosing clause error.
func returnsOrPanics(cc *ast.CaseClause) bool {
	found := false
	for _, s := range cc.Body {
		ast.Inspect(s, func(n ast.Node) bool {
			if _, ok := n.(*ast.FuncLit); ok {
				return false
			}
			switch x := n.(type) {
			case *ast.ReturnStmt:
				found = true
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "panic" {
					found = true
				}
			}
			return !found
		})
		if found {
			return true
		}
	}
	return false
}
