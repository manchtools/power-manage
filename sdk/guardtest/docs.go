package guardtest

// SPEC-002 M4: config read-site discovery (G-002-6, INV-18). A knob the
// docs generator renders but nothing ever reads is dead configuration —
// it must be read or deleted.

import (
	"fmt"
	"go/ast"
	"go/token"
	"path"
	"sort"
)

// collectStructDecls parses every Go file under root (tests included) and
// returns struct type declarations grouped by package directory.
func collectStructDecls(root string) (map[string]map[string]structDecl, error) {
	structs := map[string]map[string]structDecl{}
	err := walkAllGoFiles(root, func(rel string, fset *token.FileSet, file *ast.File) error {
		dir := path.Dir(rel)
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if st, ok := ts.Type.(*ast.StructType); ok {
					if structs[dir] == nil {
						structs[dir] = map[string]structDecl{}
					}
					structs[dir][ts.Name.Name] = structDecl{rel, fset, st}
				}
			}
		}
		return nil
	})
	return structs, err
}

// ConfigReadViolations locates structName's declaration under root and
// returns a violation for every section key that no `.Section.Key`
// selector chain under root (tests included) ever touches. A section
// whose type the AST cannot resolve (cross-package) is its own
// violation — its keys would otherwise go unchecked (fail closed).
// ponytail: recorded ceilings — matching is a syntactic name chain, so
// an unrelated same-named chain or an assignment counts as the read,
// while a section copied to a local (`s := c.Tuning; s.Knob`) or an
// embedded key read promoted (`c.Knob` for an embedded section) breaks
// the chain and over-flags.
func ConfigReadViolations(root, structName string) ([]string, error) {
	structs, err := collectStructDecls(root)
	if err != nil {
		return nil, err
	}
	var sd structDecl
	var pkg string
	found := 0
	for dir, decls := range structs {
		if d, ok := decls[structName]; ok {
			sd, pkg, found = d, dir, found+1
		}
	}
	if found != 1 {
		return nil, fmt.Errorf("struct %s declared %d time(s) under %s — the read-site scan needs exactly one subject", structName, found, root)
	}
	type key struct{ section, name string }
	unread := map[key]bool{}
	var out []string
	for _, f := range sd.st.Fields.List {
		nested, nestedName, _ := resolveNested(f.Type, structs[pkg])
		if nested == nil {
			// derive accepts any struct-kinded section, but a
			// cross-package type is un-enumerable from this package's
			// AST — flag it rather than silently skip its keys. A
			// non-struct field also lands here; derive rejects that at
			// boot, so the message stays accurate for real configs.
			for _, sec := range f.Names {
				out = append(out, fmt.Sprintf("%s.%s: section type is not resolvable in the struct's package — its keys cannot be checked for read sites; declare section types next to the config struct [INV-18]", structName, sec.Name))
			}
			continue
		}
		secNames := make([]string, 0, len(f.Names))
		for _, sec := range f.Names {
			secNames = append(secNames, sec.Name)
		}
		if len(secNames) == 0 && nestedName != "" { // embedded named section
			secNames = append(secNames, nestedName)
		}
		for _, sec := range secNames {
			for _, kf := range nested.Fields.List {
				for _, kn := range kf.Names {
					unread[key{sec, kn.Name}] = true
				}
			}
		}
	}
	err = walkAllGoFiles(root, func(rel string, _ *token.FileSet, file *ast.File) error {
		ast.Inspect(file, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if inner, ok := sel.X.(*ast.SelectorExpr); ok {
					delete(unread, key{inner.Sel.Name, sel.Sel.Name})
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	for k := range unread {
		out = append(out, fmt.Sprintf("%s.%s.%s: no read site under %s — an unread knob is dead configuration; read it or delete it [INV-18]", structName, k.section, k.name, root))
	}
	sort.Strings(out)
	return out, nil
}
