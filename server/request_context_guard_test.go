package server_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/guardtest"
)

var detachedContextAllowlist = map[string]string{
	"internal/pki/server.go#Serve": "bounded TLS shutdown after the serving context is cancelled",
}

var requestPathPackages = []string{
	"server/internal/auth",
	"server/internal/control",
	"server/internal/gateway",
	"server/internal/pki",
}

func TestGuard_RequestPathsDoNotCreateBackgroundContexts(t *testing.T) {
	root := guardtest.RepoRoot(t)
	files := guardtest.Discover(t, "server request-path Go files", 35, func() ([]string, error) {
		return productionGoFiles(root, requestPathPackages)
	})
	if len(files) == 0 {
		t.Fatal("request-path discovery returned no files")
	}
	var violations []string
	for _, requestPath := range requestPathPackages {
		// BannedCalls uses guardtest's production-file mode; the independent
		// census above supplies the matches-zero floor for the same paths.
		found, err := guardtest.BannedCalls(
			filepath.Join(root, requestPath),
			"context",
			"Background",
		)
		if err != nil {
			t.Fatalf("scan %s: %v", requestPath, err)
		}
		for _, violation := range found {
			violations = append(violations, requestPath+"/"+violation)
		}
	}
	if len(violations) > 0 {
		t.Fatalf("request paths create background contexts: %s", strings.Join(violations, "; "))
	}
}

func TestRequestContextBackgroundGuard_FixtureDetected(t *testing.T) {
	root := guardtest.RepoRoot(t)
	guardtest.RequireViolation(
		t,
		"request-path context.Background ban",
		func(path string) ([]string, error) {
			return guardtest.BannedCalls(path, "context", "Background")
		},
		filepath.Join(root, "sdk/guardtest/testdata/astban/ctxbg"),
	)
}

func TestGuard_DetachedContextsAreBoundedAndAllowlisted(t *testing.T) {
	root := guardtest.RepoRoot(t)
	uses, err := detachedContextUses(root, requestPathPackages)
	if err != nil {
		t.Fatalf("discover detached contexts: %v", err)
	}
	keys := guardtest.Discover(t, "detached request contexts", 1, func() ([]string, error) {
		keys := make([]string, len(uses))
		for index, use := range uses {
			keys[index] = use.key
		}
		return keys, nil
	})
	if !slices.Equal(keys, []string{"internal/pki/server.go#Serve"}) {
		t.Fatalf("detached context functions = %v; want exact allowlist", keys)
	}
	for _, use := range uses {
		rationale := strings.TrimSpace(detachedContextAllowlist[use.key])
		if rationale == "" {
			t.Errorf("%s has no detached-context rationale", use.key)
		}
		if !use.directTimeoutParent {
			t.Errorf("%s:%d context.WithoutCancel is not the direct parent of context.WithTimeout", use.path, use.line)
		}
	}
	for key, rationale := range detachedContextAllowlist {
		if strings.TrimSpace(rationale) == "" {
			t.Errorf("%s has an empty detached-context rationale", key)
		}
		if !slices.Contains(keys, key) {
			t.Errorf("detached-context allowlist entry %s is stale", key)
		}
	}
}

func TestDetachedContextGuard_FixtureDetected(t *testing.T) {
	root := t.TempDir()
	requestPath := filepath.Join(root, "request")
	if err := os.Mkdir(requestPath, 0o700); err != nil {
		t.Fatalf("create detached-context fixture directory: %v", err)
	}
	fixture := []byte(`package request

import "context"

func handle(ctx context.Context) {
	_ = context.WithoutCancel(ctx)
}

func handleAlias(ctx context.Context) {
	detach := context.WithoutCancel
	_ = detach(ctx)
}
`)
	if err := os.WriteFile(filepath.Join(requestPath, "bad.go"), fixture, 0o600); err != nil {
		t.Fatalf("write detached-context fixture: %v", err)
	}
	uses, err := detachedContextUses(root, []string{"request"})
	if err != nil {
		t.Fatalf("scan detached-context fixture: %v", err)
	}
	if len(uses) != 2 {
		t.Fatalf("detached-context fixture uses = %+v; want direct and aliased uses", uses)
	}
	for _, use := range uses {
		if use.directTimeoutParent {
			t.Errorf("detached-context fixture use = %+v; want unbounded use", use)
		}
	}
	if !strings.HasSuffix(uses[0].key, "#handle") || !strings.HasSuffix(uses[1].key, "#handleAlias") {
		t.Errorf("detached-context fixture keys = %v, %v; want handle and handleAlias", uses[0].key, uses[1].key)
	}
}

type detachedContextUse struct {
	key                 string
	path                string
	line                int
	directTimeoutParent bool
}

func productionGoFiles(root string, paths []string) ([]string, error) {
	var files []string
	for _, requestPath := range paths {
		base := filepath.Join(root, requestPath)
		err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if path != base && (entry.Name() == "testdata" || strings.HasPrefix(entry.Name(), ".")) {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(entry.Name(), ".go") && !strings.HasSuffix(entry.Name(), "_test.go") {
				relative, err := filepath.Rel(root, path)
				if err != nil {
					return err
				}
				files = append(files, filepath.ToSlash(relative))
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	slices.Sort(files)
	return files, nil
}

func detachedContextUses(root string, paths []string) ([]detachedContextUse, error) {
	var uses []detachedContextUse
	fileset := token.NewFileSet()
	for _, requestPath := range paths {
		base := filepath.Join(root, requestPath)
		err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				if path != base && (entry.Name() == "testdata" || strings.HasPrefix(entry.Name(), ".")) {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fileset, path, nil, 0)
			if err != nil {
				return fmt.Errorf("parse %s: %w", path, err)
			}
			contextImports := contextAliases(file)
			if len(contextImports) == 0 {
				return nil
			}
			relative, err := filepath.Rel(filepath.Join(root, "server"), path)
			if err != nil {
				return err
			}
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Body == nil {
					continue
				}
				functionAliases := contextFunctionAliases(function.Body, contextImports)
				ast.Inspect(function.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok || !isWithoutCancelCall(call, contextImports, functionAliases) {
						return true
					}
					position := fileset.Position(call.Pos())
					uses = append(uses, detachedContextUse{
						key:                 filepath.ToSlash(relative) + "#" + function.Name.Name,
						path:                filepath.ToSlash(relative),
						line:                position.Line,
						directTimeoutParent: directlyWrappedByTimeout(file, call, contextImports),
					})
					return true
				})
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	slices.SortFunc(uses, func(left, right detachedContextUse) int {
		return strings.Compare(left.key, right.key)
	})
	return uses, nil
}

func contextAliases(file *ast.File) map[string]bool {
	aliases := map[string]bool{}
	for _, imported := range file.Imports {
		if imported.Path.Value != `"context"` {
			continue
		}
		if imported.Name == nil {
			aliases["context"] = true
		} else if imported.Name.Name == "." {
			aliases["."] = true
		} else if imported.Name.Name != "_" {
			aliases[imported.Name.Name] = true
		}
	}
	return aliases
}

func isContextCall(call *ast.CallExpr, aliases map[string]bool, name string) bool {
	if identifier, ok := call.Fun.(*ast.Ident); ok {
		return aliases["."] && identifier.Name == name
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != name {
		return false
	}
	identifier, ok := selector.X.(*ast.Ident)
	return ok && aliases[identifier.Name]
}

func isWithoutCancelCall(call *ast.CallExpr, contextImports, functionAliases map[string]bool) bool {
	if isContextCall(call, contextImports, "WithoutCancel") {
		return true
	}
	identifier, ok := call.Fun.(*ast.Ident)
	return ok && functionAliases[identifier.Name]
}

func contextFunctionAliases(node ast.Node, contextImports map[string]bool) map[string]bool {
	aliases := map[string]bool{}
	for changed := true; changed; {
		changed = false
		ast.Inspect(node, func(node ast.Node) bool {
			switch statement := node.(type) {
			case *ast.AssignStmt:
				if len(statement.Lhs) != len(statement.Rhs) {
					return true
				}
				for index, left := range statement.Lhs {
					identifier, ok := left.(*ast.Ident)
					if ok && !aliases[identifier.Name] &&
						isWithoutCancelValue(statement.Rhs[index], contextImports, aliases) {
						aliases[identifier.Name] = true
						changed = true
					}
				}
			case *ast.ValueSpec:
				if len(statement.Names) != len(statement.Values) {
					return true
				}
				for index, name := range statement.Names {
					if !aliases[name.Name] &&
						isWithoutCancelValue(statement.Values[index], contextImports, aliases) {
						aliases[name.Name] = true
						changed = true
					}
				}
			}
			return true
		})
	}
	return aliases
}

func isWithoutCancelValue(expression ast.Expr, contextImports, functionAliases map[string]bool) bool {
	switch typed := expression.(type) {
	case *ast.ParenExpr:
		return isWithoutCancelValue(typed.X, contextImports, functionAliases)
	case *ast.Ident:
		return (contextImports["."] && typed.Name == "WithoutCancel") || functionAliases[typed.Name]
	case *ast.SelectorExpr:
		identifier, ok := typed.X.(*ast.Ident)
		return ok && contextImports[identifier.Name] && typed.Sel.Name == "WithoutCancel"
	default:
		return false
	}
}

func directlyWrappedByTimeout(file *ast.File, target *ast.CallExpr, aliases map[string]bool) bool {
	direct := false
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || !isContextCall(call, aliases, "WithTimeout") || len(call.Args) == 0 {
			return true
		}
		if call.Args[0] == target {
			direct = true
		}
		return true
	})
	return direct
}
