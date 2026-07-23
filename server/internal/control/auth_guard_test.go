package control

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/guardtest"
)

func TestGuard_ControlHandlersUseNoCookies(t *testing.T) {
	var violations []string
	guardtest.Discover(t, "control HTTP handler surfaces", 1, func() ([]string, error) {
		handlers, found, err := scanControlHTTPHandlers(".")
		violations = found
		return make([]string, handlers), err
	})
	if len(violations) != 0 {
		t.Fatalf("control cookie API usage: %s", strings.Join(violations, "; "))
	}
}

func TestGuard_ControlHandlersUseNoCookies_Liveness(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatalf("create nested no-cookie guard fixture: %v", err)
	}
	fixture := `package fixture
import "net/http"
func NewHTTPHandler() http.Handler {
	return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
}
func forbiddenCookieAccess(writer http.ResponseWriter, request *http.Request) {
	_, _ = request.Cookie("session")
	_ = request.Header["Cookie"]
	_ = writer.Header()["Set-Cookie"]
	headers := writer.Header()
	_ = headers["Set-Cookie"]
	decoy := map[string]string{"Cookie": "not an HTTP header"}
	_ = decoy["Cookie"]
}
`
	if err := os.WriteFile(filepath.Join(nested, "handler.go"), []byte(fixture), 0o600); err != nil {
		t.Fatalf("write no-cookie guard fixture: %v", err)
	}
	guardtest.RequireViolation(t, "control no-cookie scan", func(root string) ([]string, error) {
		_, violations, err := scanControlHTTPHandlers(root)
		return violations, err
	}, root)
	handlers, violations, err := scanControlHTTPHandlers(root)
	if err != nil {
		t.Fatalf("scan no-cookie guard fixture: %v", err)
	}
	want := []string{
		"handler.go:7 Cookie",
		"handler.go:8 header index",
		"handler.go:9 header index",
		"handler.go:11 header index",
	}
	if handlers != 1 || !slices.Equal(violations, want) {
		t.Fatalf("no-cookie fixture scan = (%d handlers, %v); want (1, %v)", handlers, violations, want)
	}
}

func scanControlHTTPHandlers(root string) (int, []string, error) {
	var paths []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return 0, nil, fmt.Errorf("walk control Go files: %w", err)
	}
	if len(paths) == 0 {
		return 0, nil, errors.New("no control Go files discovered")
	}
	fileset := token.NewFileSet()
	var handlers int
	var violations []string
	for _, path := range paths {
		file, err := parser.ParseFile(fileset, path, nil, 0)
		if err != nil {
			return 0, nil, fmt.Errorf("parse %s: %w", path, err)
		}
		httpAliases := make(map[string]bool)
		for _, imported := range file.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return 0, nil, fmt.Errorf("parse import in %s: %w", path, err)
			}
			if importPath != "net/http" {
				continue
			}
			name := "http"
			if imported.Name != nil {
				name = imported.Name.Name
			}
			httpAliases[name] = true
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && isHTTPHandlerSurface(function, httpAliases) {
				handlers++
			}
		}
		headerAliases := make(map[string]bool)
		ast.Inspect(file, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if ok {
				for index, right := range assignment.Rhs {
					if index >= len(assignment.Lhs) || !isHeaderExpression(right) {
						continue
					}
					if identifier, ok := assignment.Lhs[index].(*ast.Ident); ok {
						headerAliases[identifier.Name] = true
					}
				}
			}
			index, ok := node.(*ast.IndexExpr)
			if ok && isCookieIndex(index, headerAliases) {
				position := fileset.Position(index.Pos())
				violations = append(violations, fmt.Sprintf("%s:%d header index", filepath.Base(path), position.Line))
				return true
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !isCookieCall(selector, call.Args, httpAliases) {
				return true
			}
			position := fileset.Position(call.Pos())
			violations = append(violations, fmt.Sprintf("%s:%d %s", filepath.Base(path), position.Line, selector.Sel.Name))
			return true
		})
	}
	return handlers, violations, nil
}

func isCookieIndex(index *ast.IndexExpr, headerAliases map[string]bool) bool {
	literal, ok := index.Index.(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return false
	}
	header, err := strconv.Unquote(literal.Value)
	if err != nil || (!strings.EqualFold(header, "cookie") && !strings.EqualFold(header, "set-cookie")) {
		return false
	}
	if identifier, ok := index.X.(*ast.Ident); ok {
		return headerAliases[identifier.Name]
	}
	return isHeaderExpression(index.X)
}

func isHeaderExpression(expression ast.Expr) bool {
	switch expression := expression.(type) {
	case *ast.SelectorExpr:
		return expression.Sel.Name == "Header"
	case *ast.CallExpr:
		selector, ok := expression.Fun.(*ast.SelectorExpr)
		return ok && selector.Sel.Name == "Header"
	default:
		return false
	}
}

func isHTTPHandlerSurface(function *ast.FuncDecl, httpAliases map[string]bool) bool {
	if function.Type.Results != nil {
		for _, field := range function.Type.Results.List {
			selector, ok := field.Type.(*ast.SelectorExpr)
			if ok {
				owner, ownerOK := selector.X.(*ast.Ident)
				if ownerOK && httpAliases[owner.Name] && (selector.Sel.Name == "Handler" || selector.Sel.Name == "HandlerFunc") {
					return true
				}
			}
		}
	}
	return function.Name.Name == "ServeHTTP"
}

func isCookieCall(selector *ast.SelectorExpr, arguments []ast.Expr, httpAliases map[string]bool) bool {
	if selector.Sel.Name == "Cookie" || selector.Sel.Name == "Cookies" || selector.Sel.Name == "AddCookie" {
		return true
	}
	if selector.Sel.Name == "SetCookie" {
		owner, ok := selector.X.(*ast.Ident)
		return ok && httpAliases[owner.Name]
	}
	if len(arguments) == 0 {
		return false
	}
	literal, ok := arguments[0].(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return false
	}
	header, err := strconv.Unquote(literal.Value)
	return err == nil && (strings.EqualFold(header, "cookie") || strings.EqualFold(header, "set-cookie"))
}
