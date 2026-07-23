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
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
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

// SignatureSite is one direct production call to a shared signing operation.
type SignatureSite struct {
	Operation string
	File      string
	Function  string
}

var sharedSignatureOperations = map[string]bool{
	"SignCommand":   true,
	"VerifyCommand": true,
	"SignResult":    true,
	"VerifyResult":  true,
}

var sharedSignatureBypassHelpers = map[string]bool{
	"CommandDomain":   true,
	"CommandPreimage": true,
	"ResultDomain":    true,
	"ResultPreimage":  true,
}

var rawSignaturePrimitives = map[string]map[string]bool{
	"crypto": {
		"SignMessage": true,
	},
	"crypto/ecdsa": {
		"Sign":       true,
		"SignASN1":   true,
		"Verify":     true,
		"VerifyASN1": true,
	},
	"crypto/ed25519": {
		"Sign":              true,
		"Verify":            true,
		"VerifyWithOptions": true,
	},
	"crypto/rsa": {
		"SignPKCS1v15":   true,
		"SignPSS":        true,
		"VerifyPKCS1v15": true,
		"VerifyPSS":      true,
	},
}

// approvedRawSignatureSites is the exact owner registry for formats that the
// shared command/result envelope helpers cannot represent. JWT ES256 requires
// the JOSE 64-byte R||S encoding, rather than ASN.1 ECDSA signatures.
var approvedRawSignatureSites = map[string]SignatureSite{
	"ecdsa.Sign": {
		Operation: "ecdsa.Sign",
		File:      "server/internal/auth/tokens.go",
		Function:  "Signer.mint",
	},
	"ecdsa.Verify": {
		Operation: "ecdsa.Verify",
		File:      "server/internal/auth/tokens.go",
		Function:  "Verifier.verify",
	},
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

// ScanSignatureSites inventories direct references to the four shared
// signature operations in the server and agent production trees. Indirection
// and dot imports are violations because they make an exact chokepoint count
// ambiguous and can hide an unreviewed signing path.
func ScanSignatureSites(root string) ([]SignatureSite, []string, error) {
	imports := newSignatureImporter()
	cryptoPackage, err := imports.Import("crypto")
	if err != nil {
		return nil, nil, fmt.Errorf("load crypto package for signature-site scan: %w", err)
	}
	signerObject := cryptoPackage.Scope().Lookup("Signer")
	if signerObject == nil {
		return nil, nil, fmt.Errorf("crypto.Signer is missing from the type-checker import")
	}
	signerInterface, ok := signerObject.Type().Underlying().(*types.Interface)
	if !ok {
		return nil, nil, fmt.Errorf("crypto.Signer has unexpected type %T", signerObject.Type().Underlying())
	}
	signerInterface.Complete()
	messageSignerObject := cryptoPackage.Scope().Lookup("MessageSigner")
	if messageSignerObject == nil {
		return nil, nil, fmt.Errorf("crypto.MessageSigner is missing from the type-checker import")
	}
	messageSignerInterface, ok := messageSignerObject.Type().Underlying().(*types.Interface)
	if !ok {
		return nil, nil, fmt.Errorf("crypto.MessageSigner has unexpected type %T", messageSignerObject.Type().Underlying())
	}
	messageSignerInterface.Complete()

	var sites []SignatureSite
	var violations []string
	for _, module := range []string{"agent", "server"} {
		moduleRoot := filepath.Join(root, module)
		if _, err := os.Stat(moduleRoot); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, nil, fmt.Errorf("stat %s: %w", moduleRoot, err)
		}
		packageFiles := make(map[string][]string)
		err := filepath.WalkDir(moduleRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if path != moduleRoot && (entry.Name() == "testdata" || entry.Name() == "vendor" || strings.HasPrefix(entry.Name(), ".")) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			packageFiles[filepath.Dir(path)] = append(packageFiles[filepath.Dir(path)], path)
			return nil
		})
		if err != nil {
			return nil, nil, fmt.Errorf("discover %s signature sites: %w", module, err)
		}
		packageDirs := make([]string, 0, len(packageFiles))
		for dir := range packageFiles {
			packageDirs = append(packageDirs, dir)
		}
		sort.Strings(packageDirs)
		for _, dir := range packageDirs {
			paths := packageFiles[dir]
			sort.Strings(paths)
			packageSites, packageViolations, err := scanSignaturePackage(root, paths, imports, signerInterface, messageSignerInterface)
			if err != nil {
				return nil, nil, fmt.Errorf("scan %s signature sites: %w", module, err)
			}
			sites = append(sites, packageSites...)
			violations = append(violations, packageViolations...)
		}
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].Operation != sites[j].Operation {
			return sites[i].Operation < sites[j].Operation
		}
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Function < sites[j].Function
	})
	sort.Strings(violations)
	return sites, violations, nil
}

type signatureImporter struct {
	fallback types.Importer
	packages map[string]*types.Package
}

func newSignatureImporter() *signatureImporter {
	return &signatureImporter{
		fallback: importer.Default(),
		packages: make(map[string]*types.Package),
	}
}

func (i *signatureImporter) Import(importPath string) (*types.Package, error) {
	if pkg := i.packages[importPath]; pkg != nil {
		return pkg, nil
	}
	pkg, err := i.fallback.Import(importPath)
	if err != nil {
		// Workspace packages need not be installed in the compiler export-data
		// cache. A completed empty package is enough to resolve its import name;
		// this scan only type-checks stdlib crypto method sets.
		pkg = types.NewPackage(importPath, filepath.Base(importPath))
		pkg.MarkComplete()
	}
	i.packages[importPath] = pkg
	return pkg, nil
}

func scanSignaturePackage(
	root string,
	paths []string,
	imports types.Importer,
	signerInterface *types.Interface,
	messageSignerInterface *types.Interface,
) ([]SignatureSite, []string, error) {
	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(paths))
	relativePaths := make(map[*ast.File]string, len(paths))
	var violations []string
	for _, path := range paths {
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("parse %s: %w", path, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil, nil, fmt.Errorf("make %s relative to %s: %w", path, root, err)
		}
		rel = filepath.ToSlash(rel)
		files = append(files, file)
		relativePaths[file] = rel
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return nil, nil, fmt.Errorf("unquote import in %s: %w", rel, err)
			}
			if spec.Name != nil && spec.Name.Name == "." && guardedSignatureImport(importPath) {
				line := fset.Position(spec.Pos()).Line
				violations = append(violations, fmt.Sprintf("%s:%d: dot import of %s hides signature ownership", rel, line, importPath))
			}
		}
	}

	parents := make(map[ast.Node]ast.Node)
	for _, file := range files {
		var stack []ast.Node
		ast.Inspect(file, func(node ast.Node) bool {
			if node == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			if len(stack) > 0 {
				parents[node] = stack[len(stack)-1]
			}
			stack = append(stack, node)
			return true
		})
	}
	typeInfo := &types.Info{
		Selections: make(map[*ast.SelectorExpr]*types.Selection),
		Types:      make(map[ast.Expr]types.TypeAndValue),
		Uses:       make(map[*ast.Ident]types.Object),
	}
	config := types.Config{
		Importer: imports,
		Error:    func(error) {},
	}
	_, typeCheckErr := config.Check("signature/site/scan", fset, files, typeInfo)

	var sites []SignatureSite
	for _, file := range files {
		rel := relativePaths[file]
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			line := fset.Position(selector.Pos()).Line
			importPath := selectorImportPath(typeInfo, selector)
			if importPath == "github.com/manchtools/power-manage/contract/sign" {
				switch {
				case sharedSignatureOperations[selector.Sel.Name]:
					// Counted below after checking that this is a direct call.
				case sharedSignatureBypassHelpers[selector.Sel.Name] || strings.HasSuffix(selector.Sel.Name, "SignatureDomain"):
					violations = append(violations, fmt.Sprintf("%s:%d: direct contract/sign.%s reference bypasses the approved signature chokepoints", rel, line, selector.Sel.Name))
					return true
				default:
					return true
				}
			} else if rawSignaturePrimitives[importPath][selector.Sel.Name] {
				operation := strings.TrimPrefix(importPath, "crypto/") + "." + selector.Sel.Name
				function := enclosingFunction(selector, parents)
				site := SignatureSite{Operation: operation, File: rel, Function: function}
				expected, approved := approvedRawSignatureSites[operation]
				parent := parents[selector]
				call, direct := parent.(*ast.CallExpr)
				if approved && direct && call.Fun == selector && site == expected {
					sites = append(sites, site)
					return true
				}
				violations = append(violations, fmt.Sprintf(
					"%s:%d: raw %s signature primitive bypasses the approved owner",
					rel,
					line,
					operation,
				))
				return true
			} else if selector.Sel.Name == "Sign" || selector.Sel.Name == "SignMessage" {
				interfaceName := "crypto.Signer.Sign"
				signatureInterface := signerInterface
				if selector.Sel.Name == "SignMessage" {
					interfaceName = "crypto.MessageSigner.SignMessage"
					signatureInterface = messageSignerInterface
				}
				selection := typeInfo.Selections[selector]
				if selection == nil {
					reason := ""
					if typeCheckErr != nil {
						reason = " after partial type-check failure"
					}
					violations = append(violations, fmt.Sprintf("%s:%d: unresolved %s reference%s cannot be proven unrelated to %s", rel, line, selector.Sel.Name, reason, interfaceName))
				} else if signerType(selection.Recv(), signatureInterface) {
					violations = append(violations, fmt.Sprintf("%s:%d: raw %s reference bypasses contract/sign", rel, line, interfaceName))
				}
				return true
			} else {
				return true
			}
			parent := parents[selector]
			if call, ok := parent.(*ast.CallExpr); !ok || call.Fun != selector {
				category := "indirect"
				if _, ok := parent.(*ast.ParenExpr); ok {
					category = "parenthesized"
				}
				violations = append(violations, fmt.Sprintf("%s:%d: %s reference to contract/sign.%s", rel, line, category, selector.Sel.Name))
				return true
			}
			function := enclosingFunction(selector, parents)
			if function == "" {
				violations = append(violations, fmt.Sprintf("%s:%d: contract/sign.%s call is outside a named function", rel, line, selector.Sel.Name))
				return true
			}
			sites = append(sites, SignatureSite{Operation: selector.Sel.Name, File: rel, Function: function})
			return true
		})
	}
	return sites, violations, nil
}

func signerType(candidate types.Type, signerInterface *types.Interface) bool {
	if types.Implements(candidate, signerInterface) {
		return true
	}
	if _, alreadyPointer := candidate.(*types.Pointer); alreadyPointer {
		return false
	}
	return types.Implements(types.NewPointer(candidate), signerInterface)
}

func guardedSignatureImport(importPath string) bool {
	if importPath == "github.com/manchtools/power-manage/contract/sign" {
		return true
	}
	_, guarded := rawSignaturePrimitives[importPath]
	return guarded
}

func selectorImportPath(info *types.Info, selector *ast.SelectorExpr) string {
	qualifier, ok := selector.X.(*ast.Ident)
	if !ok {
		return ""
	}
	pkgName, ok := info.Uses[qualifier].(*types.PkgName)
	if !ok {
		return ""
	}
	return pkgName.Imported().Path()
}

func enclosingFunction(node ast.Node, parents map[ast.Node]ast.Node) string {
	for parent := parents[node]; parent != nil; parent = parents[parent] {
		declaration, ok := parent.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if declaration.Recv == nil || len(declaration.Recv.List) == 0 {
			return declaration.Name.Name
		}
		return receiverTypeName(declaration.Recv.List[0].Type) + "." + declaration.Name.Name
	}
	return ""
}

func receiverTypeName(expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return receiverTypeName(typed.X)
	case *ast.IndexExpr:
		return receiverTypeName(typed.X)
	case *ast.IndexListExpr:
		return receiverTypeName(typed.X)
	default:
		return "<unknown>"
	}
}
