package pki

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/sdk/guardtest"
)

// TestGuard_PkiLifecycleHandlersUseDeviceLock is GUARD-006-4: every
// descriptor-discovered PkiService lifecycle handler must enter the shared
// transaction-scoped device advisory-lock capability.
func TestGuard_PkiLifecycleHandlersUseDeviceLock(t *testing.T) {
	service := powermanagev1.File_powermanage_v1_pki_proto.Services().ByName("PkiService")
	discovered := guardtest.Discover(t, "PkiService lifecycle handlers", 2, func() ([]string, error) {
		if service == nil {
			return nil, errors.New("PkiService descriptor is absent")
		}
		handlers := make([]string, 0, service.Methods().Len())
		for i := 0; i < service.Methods().Len(); i++ {
			handlers = append(handlers, string(service.Methods().Get(i).Name()))
		}
		return handlers, nil
	})
	calls, err := lifecycleLockCalls(".")
	if err != nil {
		t.Fatalf("scan lifecycle handlers: %v", err)
	}
	for _, handler := range discovered {
		if calls[handler] == 0 {
			t.Errorf("lifecycle handler %s does not call WithDeviceLifecycleLock", handler)
		}
	}
}

func TestLifecycleLockGuard_FixtureDetected(t *testing.T) {
	root := t.TempDir()
	fixture := []byte(`package fixture
type EnrollmentService struct{}
func (s *EnrollmentService) RenewAgent() {}
`)
	if err := os.WriteFile(filepath.Join(root, "fixture.go"), fixture, 0o600); err != nil {
		t.Fatalf("write lifecycle guard fixture: %v", err)
	}
	calls, err := lifecycleLockCalls(root)
	if err != nil {
		t.Fatalf("scan lifecycle guard fixture: %v", err)
	}
	if calls["RenewAgent"] != 0 {
		t.Fatalf("unlocked fixture calls = %v; want zero", calls)
	}
}

func lifecycleLockCalls(root string) (map[string]int, error) {
	files, err := filepath.Glob(filepath.Join(root, "*.go"))
	if err != nil {
		return nil, fmt.Errorf("glob Go files: %w", err)
	}
	if len(files) == 0 {
		return nil, errors.New("no Go files discovered")
	}
	calls := make(map[string]int)
	fileset := token.NewFileSet()
	for _, path := range files {
		if filepath.Ext(path) != ".go" || filepath.Base(path) == "lifecycle_guard_test.go" {
			continue
		}
		file, err := parser.ParseFile(fileset, path, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv == nil || function.Body == nil || !enrollmentServiceReceiver(function.Recv) {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if ok && selector.Sel.Name == "WithDeviceLifecycleLock" {
					calls[function.Name.Name]++
				}
				return true
			})
		}
	}
	return calls, nil
}

func enrollmentServiceReceiver(receivers *ast.FieldList) bool {
	if receivers == nil || len(receivers.List) != 1 {
		return false
	}
	typeExpression := receivers.List[0].Type
	if pointer, ok := typeExpression.(*ast.StarExpr); ok {
		typeExpression = pointer.X
	}
	identifier, ok := typeExpression.(*ast.Ident)
	return ok && identifier.Name == "EnrollmentService"
}
