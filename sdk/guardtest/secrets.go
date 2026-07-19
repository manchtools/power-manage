package guardtest

// SPEC-002 M3: secret-indirection discovery (G-002-7, INV-18/AC-7).
// Subjects are struct types named *Config — fields chased through inline
// structs and same-package named section types — and literal-named
// string flags. ponytail: recorded ceilings — a secret struct not named
// *Config, a cross-package section type, a FlagSet method registration,
// and a non-literal flag name are not matched; the naming convention and
// per-binary review are the second line until a flag library lands.

import (
	"fmt"
	"go/ast"
	"go/token"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// secretNameRe is the test-owned threat model: unqualified secret
// families plus qualified key material. Bare "key" is deliberately
// excluded — SortKey/KeyPrefix-style names are not secrets.
var secretNameRe = regexp.MustCompile(`(?i)(token|secret|passw(or)?d|passphrase|credential|(api|private|signing|master|encryption|tls|host|ssh)[_-]?key)`)

// secretPathSuffixRe marks the sanctioned path-indirection forms.
var secretPathSuffixRe = regexp.MustCompile(`(?i)[_-]?(file|path)$`)

// secretValueName reports whether name denotes an inline secret VALUE:
// it matches the pattern set and is not the path form.
func secretValueName(name string) bool {
	return secretNameRe.MatchString(name) && !secretPathSuffixRe.MatchString(name)
}

// structDecl is one struct type declaration and where it lives.
type structDecl struct {
	rel  string
	fset *token.FileSet
	st   *ast.StructType
}

// secretIndirectionViolations walks Go files under root (tests included)
// and returns AC-7 violations plus the subjects scanned (*Config structs
// and literal-named string flags).
func secretIndirectionViolations(root string) (violations, subjects []string, err error) {
	structs := map[string]map[string]structDecl{} // package dir → type name
	err = walkAllGoFiles(root, func(rel string, fset *token.FileSet, file *ast.File) error {
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
		names, dot := importAliases(file, "flag")
		if len(names) == 0 && !dot {
			return nil
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var fn string
			switch f := unwrapExpr(call.Fun).(type) {
			case *ast.Ident:
				if dot {
					fn = f.Name
				}
			case *ast.SelectorExpr:
				if id, ok := f.X.(*ast.Ident); ok && names[id.Name] {
					fn = f.Sel.Name
				}
			}
			var nameArg ast.Expr
			switch {
			case fn == "String" && len(call.Args) == 3:
				nameArg = call.Args[0]
			case fn == "StringVar" && len(call.Args) == 4:
				nameArg = call.Args[1]
			}
			if nameArg == nil {
				return true
			}
			lit, ok := unwrapExpr(nameArg).(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			flagName, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			subjects = append(subjects, fmt.Sprintf("%s: flag %q", rel, flagName))
			if secretValueName(flagName) {
				violations = append(violations, fmt.Sprintf("%s:%d: flag %q takes a secret on argv — it sits in shell history and ps output for its whole validity; use %q [INV-18]",
					rel, fset.Position(call.Pos()).Line, flagName, flagName+"-file"))
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	for _, decls := range structs {
		for name, sd := range decls {
			if !strings.HasSuffix(name, "Config") {
				continue
			}
			subjects = append(subjects, sd.rel+": struct "+name)
			checkSecretFields(name, sd, decls, map[string]bool{name: true}, &violations)
		}
	}
	sort.Strings(violations)
	sort.Strings(subjects)
	return violations, subjects, nil
}

// checkSecretFields flags secret-pattern fields that are not path-typed,
// chasing inline structs and same-package named section types.
func checkSecretFields(prefix string, sd structDecl, decls map[string]structDecl, seen map[string]bool, violations *[]string) {
	for _, f := range sd.st.Fields.List {
		nested, nestedName, nestedDecl := resolveNested(f.Type, decls)
		fieldNames := make([]string, 0, len(f.Names))
		for _, id := range f.Names {
			fieldNames = append(fieldNames, id.Name)
		}
		if len(fieldNames) == 0 && nestedName != "" { // embedded named struct
			fieldNames = append(fieldNames, nestedName)
		}
		for _, fname := range fieldNames {
			if secretValueName(fname) {
				*violations = append(*violations, fmt.Sprintf("%s:%d: field %s.%s matches the secret pattern set — path indirection only (%sFile) [INV-18]",
					sd.rel, sd.fset.Position(f.Pos()).Line, prefix, fname, fname))
			}
		}
		if nested == nil || (nestedName != "" && seen[nestedName]) {
			continue
		}
		if nestedName != "" {
			seen[nestedName] = true
		}
		sub := sd
		if nestedDecl != nil {
			sub = *nestedDecl
		}
		sub.st = nested
		for _, fname := range fieldNames {
			checkSecretFields(prefix+"."+fname, sub, decls, seen, violations)
		}
		if nestedName != "" {
			// The cycle guard is path-scoped: unwind so a sibling field
			// sharing this section type still gets its own walk.
			delete(seen, nestedName)
		}
	}
}

// resolveNested returns the struct type a field descends into: an inline
// struct, or a same-package named struct with its declaration
// (cross-package section types are a recorded ceiling).
func resolveNested(t ast.Expr, decls map[string]structDecl) (*ast.StructType, string, *structDecl) {
	switch tt := t.(type) {
	case *ast.StructType:
		return tt, "", nil
	case *ast.Ident:
		if nd, ok := decls[tt.Name]; ok {
			return nd.st, tt.Name, &nd
		}
	case *ast.StarExpr:
		return resolveNested(tt.X, decls)
	}
	return nil, "", nil
}
