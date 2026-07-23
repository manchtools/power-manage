package pki

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/sdk/guardtest"
	"github.com/manchtools/power-manage/server/internal/auth"
)

func TestPublicPKIHandlers_ReportAuthenticationOutcomes(t *testing.T) {
	service := powermanagev1.File_powermanage_v1_pki_proto.Services().ByName("PkiService")
	methods := guardtest.Discover(t, "descriptor-classified public PkiService methods", 9, func() ([]string, error) {
		if service == nil {
			return nil, errors.New("pki service descriptor is absent")
		}
		result := make([]string, 0, service.Methods().Len())
		for index := 0; index < service.Methods().Len(); index++ {
			method := service.Methods().Get(index)
			procedure := "/" + string(service.FullName()) + "/" + string(method.Name())
			class, exists := auth.ClassifyProcedure(procedure)
			if !exists || class != auth.ProcedurePublic {
				return nil, fmt.Errorf("procedure is not classified public: %s", procedure)
			}
			result = append(result, string(method.Name()))
		}
		return result, nil
	})
	if len(methods) != 9 {
		t.Fatalf("descriptor-classified public PkiService methods = %v; want exact nine-method boundary", methods)
	}
	slices.Sort(methods)

	functions := parsePKIProductionFunctions(t)
	directHandlers := 0
	for _, method := range methods {
		declaration := functions[method]
		if declaration == nil || !pkiGuardEnrollmentServiceMethod(declaration) {
			t.Fatalf("%s has no EnrollmentService handler declaration", method)
		}
		procedureConstant := "PkiService" + method + "Procedure"
		if method == "ConfirmAgentTrustState" || method == "ConfirmGatewayTrustState" {
			assertPKIConfirmationOutcomeDelegation(t, declaration, procedureConstant)
			continue
		}
		directHandlers++
		assertPKIDirectOutcomeReport(t, declaration, procedureConstant)
	}
	if directHandlers != 7 {
		t.Fatalf("direct public PKI authentication handlers = %d; want seven plus two confirmation delegations", directHandlers)
	}

	common := functions["confirmTrustState"]
	if common == nil || !pkiGuardEnrollmentServiceMethod(common) {
		t.Fatal("confirmation authentication outcome helper is absent")
	}
	if !pkiGuardHasNamedErrorResult(common, "resultErr") || !pkiGuardHasStringParameter(common, "procedure") {
		t.Fatal("confirmTrustState must carry its procedure and final resultErr to the shared limiter")
	}
	assertPKIDeferredOutcomeCall(t, common, "procedure", false)
}

func TestPKIConfirmationOutcomeGuard_RejectsNestedReturnBypass(t *testing.T) {
	const fixtureModeEnvironment = "POWER_MANAGE_TEST_CONFIRMATION_GUARD_FIXTURE"
	if mode := os.Getenv(fixtureModeEnvironment); mode != "" {
		bypass := ""
		if mode == "bypass" {
			bypass = `
	if condition {
		return s.bypassTrustConfirmation()
	}`
		}
		source := `package fixture

func (s *EnrollmentService) ConfirmAgentTrustState(condition bool) (Response, error) {
	_ = func() (Response, error) {
		return s.functionLiteralReturn()
	}
` + bypass + `
	return s.confirmTrustState(
		ctx,
		class,
		powermanagev1connect.PkiServiceConfirmAgentTrustStateProcedure,
		request,
	)
}
`
		declaration := pkiGuardFixtureConfirmationDeclaration(t, source)
		assertPKIConfirmationOutcomeDelegation(
			t,
			declaration,
			"PkiServiceConfirmAgentTrustStateProcedure",
		)
		return
	}

	runFixture := func(mode string) ([]byte, error) {
		t.Helper()
		command := exec.Command(
			os.Args[0],
			"-test.run=^TestPKIConfirmationOutcomeGuard_RejectsNestedReturnBypass$",
			"-test.count=1",
		)
		command.Env = append(os.Environ(), fixtureModeEnvironment+"="+mode)
		return command.CombinedOutput()
	}
	if output, err := runFixture("control"); err != nil {
		t.Fatalf("guard rejected function-literal-only control fixture: %v\n%s", err, output)
	}
	output, err := runFixture("bypass")
	if err == nil {
		t.Fatalf("guard accepted a nested confirmation return bypass:\n%s", output)
	}
	if !strings.Contains(string(output), "ConfirmAgentTrustState") {
		t.Fatalf("guard bypass fixture failed outside confirmation delegation analysis: %v\n%s", err, output)
	}
}

func pkiGuardFixtureConfirmationDeclaration(t *testing.T, source string) *ast.FuncDecl {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "confirmation_fixture.go", source, 0)
	if err != nil {
		t.Fatalf("parse confirmation guard fixture: %v", err)
	}
	for _, node := range file.Decls {
		declaration, ok := node.(*ast.FuncDecl)
		if ok && declaration.Name.Name == "ConfirmAgentTrustState" {
			return declaration
		}
	}
	t.Fatal("confirmation guard fixture method is absent")
	return nil
}

func assertPKIDirectOutcomeReport(t *testing.T, declaration *ast.FuncDecl, procedureConstant string) {
	t.Helper()
	if !pkiGuardHasNamedErrorResult(declaration, "resultErr") {
		t.Fatalf("%s does not expose its final authentication result as named resultErr", declaration.Name.Name)
	}
	assertPKIDeferredOutcomeCall(t, declaration, procedureConstant, true)
}

func assertPKIDeferredOutcomeCall(
	t *testing.T,
	declaration *ast.FuncDecl,
	procedure string,
	wantSelector bool,
) {
	t.Helper()
	allCalls := pkiGuardNamedCalls(declaration.Body, "applyPublicAuthenticationLimit")
	deferredCalls := pkiGuardDeferredClosureCalls(declaration.Body, "applyPublicAuthenticationLimit")
	if len(allCalls) != 1 || len(deferredCalls) != 1 || allCalls[0] != deferredCalls[0] {
		t.Fatalf("%s authentication outcome calls = %d total, %d final-result defers; want exactly one deferred closure call",
			declaration.Name.Name, len(allCalls), len(deferredCalls))
	}
	call := deferredCalls[0]
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "applyPublicAuthenticationLimit" {
		t.Fatalf("%s outcome call does not invoke the EnrollmentService helper", declaration.Name.Name)
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || receiver.Name != "s" || len(call.Args) != 5 {
		t.Fatalf("%s outcome call has the wrong receiver or argument shape", declaration.Name.Name)
	}
	if wantSelector {
		if pkiGuardSelectorName(call.Args[0]) != procedure {
			t.Fatalf("%s outcome procedure = %s; want exact %s", declaration.Name.Name, pkiGuardSelectorName(call.Args[0]), procedure)
		}
	} else if identifier, ok := call.Args[0].(*ast.Ident); !ok || identifier.Name != procedure {
		t.Fatalf("%s outcome procedure is not the delegated %s parameter", declaration.Name.Name, procedure)
	}
	result, ok := call.Args[3].(*ast.Ident)
	if !ok || result.Name != "resultErr" {
		t.Fatalf("%s outcome call does not report named final resultErr", declaration.Name.Name)
	}
}

func assertPKIConfirmationOutcomeDelegation(
	t *testing.T,
	declaration *ast.FuncDecl,
	procedureConstant string,
) {
	t.Helper()
	if calls := pkiGuardNamedCalls(declaration.Body, "applyPublicAuthenticationLimit"); len(calls) != 0 {
		t.Fatalf("%s bypasses the common confirmation outcome path", declaration.Name.Name)
	}
	returns := pkiGuardOuterReturns(declaration.Body)
	if len(returns) != 1 || len(returns[0].Results) != 1 {
		t.Fatalf("%s outer returns = %d; want one direct confirmation delegation", declaration.Name.Name, len(returns))
	}
	call, ok := returns[0].Results[0].(*ast.CallExpr)
	if !ok || pkiGuardCallName(call) != "confirmTrustState" {
		t.Fatalf("%s outer return does not directly delegate to confirmTrustState", declaration.Name.Name)
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		t.Fatalf("%s confirmation delegation is not a method call", declaration.Name.Name)
	}
	receiver, ok := selector.X.(*ast.Ident)
	if !ok || receiver.Name != "s" {
		t.Fatalf("%s confirmation delegation has the wrong receiver", declaration.Name.Name)
	}
	procedureArguments := 0
	for _, argument := range call.Args {
		if pkiGuardSelectorName(argument) == procedureConstant {
			procedureArguments++
		}
	}
	if procedureArguments != 1 {
		t.Fatalf("%s passes exact %s %d times; want once", declaration.Name.Name, procedureConstant, procedureArguments)
	}
}

func pkiGuardOuterReturns(body *ast.BlockStmt) []*ast.ReturnStmt {
	var returns []*ast.ReturnStmt
	ast.Inspect(body, func(node ast.Node) bool {
		switch current := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			returns = append(returns, current)
			return false
		default:
			return true
		}
	})
	return returns
}

func parsePKIProductionFunctions(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read PKI package: %v", err)
	}
	fileset := token.NewFileSet()
	functions := make(map[string]*ast.FuncDecl)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileset, entry.Name(), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		for _, node := range file.Decls {
			declaration, ok := node.(*ast.FuncDecl)
			if !ok || !pkiGuardEnrollmentServiceMethod(declaration) {
				continue
			}
			if _, exists := functions[declaration.Name.Name]; exists {
				t.Fatalf("duplicate EnrollmentService method %s", declaration.Name.Name)
			}
			functions[declaration.Name.Name] = declaration
		}
	}
	return functions
}

func pkiGuardEnrollmentServiceMethod(declaration *ast.FuncDecl) bool {
	if declaration.Recv == nil || len(declaration.Recv.List) != 1 {
		return false
	}
	receiver := declaration.Recv.List[0].Type
	if pointer, ok := receiver.(*ast.StarExpr); ok {
		receiver = pointer.X
	}
	identifier, ok := receiver.(*ast.Ident)
	return ok && identifier.Name == "EnrollmentService"
}

func pkiGuardHasNamedErrorResult(declaration *ast.FuncDecl, name string) bool {
	if declaration.Type.Results == nil {
		return false
	}
	for _, result := range declaration.Type.Results.List {
		identifier, ok := result.Type.(*ast.Ident)
		if !ok || identifier.Name != "error" {
			continue
		}
		for _, resultName := range result.Names {
			if resultName.Name == name {
				return true
			}
		}
	}
	return false
}

func pkiGuardHasStringParameter(declaration *ast.FuncDecl, name string) bool {
	if declaration.Type.Params == nil {
		return false
	}
	for _, parameter := range declaration.Type.Params.List {
		identifier, ok := parameter.Type.(*ast.Ident)
		if !ok || identifier.Name != "string" {
			continue
		}
		for _, parameterName := range parameter.Names {
			if parameterName.Name == name {
				return true
			}
		}
	}
	return false
}

func pkiGuardDeferredClosureCalls(body *ast.BlockStmt, name string) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(body, func(node ast.Node) bool {
		deferStatement, ok := node.(*ast.DeferStmt)
		if !ok {
			return true
		}
		closure, ok := deferStatement.Call.Fun.(*ast.FuncLit)
		if !ok {
			return false
		}
		calls = append(calls, pkiGuardNamedCalls(closure.Body, name)...)
		return false
	})
	return calls
}

func pkiGuardNamedCalls(node ast.Node, name string) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(node, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && pkiGuardCallName(call) == name {
			calls = append(calls, call)
		}
		return true
	})
	return calls
}

func pkiGuardCallName(call *ast.CallExpr) string {
	switch function := call.Fun.(type) {
	case *ast.Ident:
		return function.Name
	case *ast.SelectorExpr:
		return function.Sel.Name
	default:
		return ""
	}
}

func pkiGuardSelectorName(expression ast.Expr) string {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	return selector.Sel.Name
}
