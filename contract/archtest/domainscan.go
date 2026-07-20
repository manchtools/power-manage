package archtest

// AST discovery for the SPEC-003 G-5 signature-domain guard. The contract's
// signature domains are exported constants in the contract/sign package
// (`<Type>SignatureDomain`, plan choice 4). G-5 must enumerate them from
// ground-truth source — a hand list would let a domain ship without its
// constant, or a constant drift from the [WIRE-14] formula, unnoticed. The
// scan reads the .go source rather than importing the package so this helper
// compiles even before contract/sign exists (the caller's Discover floor is
// what fails loudly then).

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// SignatureDomainConst is one discovered domain constant: its Go identifier
// and the string literal it binds.
type SignatureDomainConst struct {
	Name  string
	Value string
}

// signPackageDir locates the contract/sign package source directory. `go test`
// runs with the working directory set to the package under test
// (contract/archtest); the sign package is a sibling under the contract
// module root, found by walking up to the go.mod that owns both.
func signPackageDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return filepath.Join(dir, "sign"), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found walking up from the working directory — run the guard from inside the contract module")
		}
		dir = parent
	}
}

// ScanSignatureDomains AST-parses the non-test .go files of the contract/sign
// package and returns every top-level const whose identifier ends in
// "SignatureDomain", paired with its string-literal value, sorted by name.
// A missing package directory yields zero constants (not an error) so the
// caller's matches-zero Discover floor is what fails — distinguishing "the
// domains have not been implemented yet / the walk broke" from "the scan
// itself errored".
func ScanSignatureDomains() ([]SignatureDomainConst, error) {
	dir, err := signPackageDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	var out []SignatureDomainConst
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", name, err)
		}
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range vs.Names {
					if !strings.HasSuffix(ident.Name, "SignatureDomain") {
						continue
					}
					if i >= len(vs.Values) {
						return nil, fmt.Errorf("const %s ends in SignatureDomain but binds no value — a domain constant must be an explicit string literal", ident.Name)
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						return nil, fmt.Errorf("const %s is not bound to a string literal — a domain constant must be a plain string for the AST scan to read", ident.Name)
					}
					val, err := strconv.Unquote(lit.Value)
					if err != nil {
						return nil, fmt.Errorf("unquoting const %s value %q: %w", ident.Name, lit.Value, err)
					}
					out = append(out, SignatureDomainConst{Name: ident.Name, Value: val})
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
