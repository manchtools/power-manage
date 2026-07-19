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
// selector chain under root (tests included) ever touches.
// ponytail: recorded ceilings — matching is a syntactic name chain, so an
// unrelated same-named chain or an assignment counts as the read, and a
// section copied to a local (`s := c.Tuning; s.Knob`) breaks the chain
// and over-flags; embedded sections are not enumerated (the loader's
// derive rejects shapes beyond the two-level model anyway).
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
	for _, f := range sd.st.Fields.List {
		nested, _, _ := resolveNested(f.Type, structs[pkg])
		if nested == nil {
			continue // not a section struct — derive fails boot on this shape
		}
		for _, sec := range f.Names {
			for _, kf := range nested.Fields.List {
				for _, kn := range kf.Names {
					unread[key{sec.Name, kn.Name}] = true
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
	var out []string
	for k := range unread {
		out = append(out, fmt.Sprintf("%s.%s.%s: no read site under %s — an unread knob is dead configuration; read it or delete it [INV-18]", structName, k.section, k.name, root))
	}
	sort.Strings(out)
	return out, nil
}
