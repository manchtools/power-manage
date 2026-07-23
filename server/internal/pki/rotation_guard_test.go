package pki

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	powermanagev1 "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/sdk/guardtest"
)

func TestGuard_PkiRotationPhasesFencesAndState(t *testing.T) {
	assertRotationGuardLiveness(t)
	coverage, err := scanPKIRotationCoverage(".")
	if err != nil {
		t.Fatalf("scan PKI rotation coverage: %v", err)
	}
	phases := guardtest.Discover(t, "RotationPhase constants", 4, func() ([]string, error) {
		return coverage.phases, nil
	})
	wantPhases := []string{
		"RotationPhaseMigrate", "RotationPhaseRetire", "RotationPhaseStable", "RotationPhaseTrust",
	}
	slices.Sort(phases)
	if !slices.Equal(phases, wantPhases) {
		t.Fatalf("rotation phases = %v; want exact four-phase graph %v", phases, wantPhases)
	}
	issuanceSites := guardtest.Discover(t, "agent and gateway certificate issuance sites", 4, func() ([]string, error) {
		return coverage.issuanceSites, nil
	})
	slices.Sort(issuanceSites)
	wantIssuanceSites := []string{
		"enrollment.go:EnrollAgent:issueAgentCertificate", "gateway.go:EnrollGateway:issueGatewayCertificate",
		"gateway.go:RenewGateway:issueGatewayCertificate", "renewal.go:RenewAgent:issueAgentCertificate",
	}
	if !slices.Equal(issuanceSites, wantIssuanceSites) {
		t.Fatalf("certificate issuance sites = %v; want exact agent/gateway enroll+renew set %v", issuanceSites, wantIssuanceSites)
	}
	crlSites := guardtest.Discover(t, "agent and gateway CRL signing sites", 2, func() ([]string, error) {
		return coverage.crlSigningSites, nil
	})
	slices.Sort(crlSites)
	wantCRLSites := []string{"crl.go:sign:SignAgentRevocationList", "crl.go:sign:SignGatewayRevocationList"}
	if !slices.Equal(crlSites, wantCRLSites) {
		t.Fatalf("CRL signing sites = %v; want exact class signer set %v", crlSites, wantCRLSites)
	}
	transitions := guardtest.Discover(t, "rotation transition methods", 5, func() ([]string, error) {
		return coverage.transitionMethods, nil
	})
	slices.Sort(transitions)
	if !slices.Equal(transitions, []string{"Abort", "BeginTrust", "Migrate", "Normalize", "Retire"}) {
		t.Fatalf("rotation transitions = %v; want exact state-changing API", transitions)
	}
	confirmationEvents := guardtest.Discover(t, "leaf and consumer confirmation event types", 4, func() ([]string, error) {
		return coverage.confirmationEvents, nil
	})
	slices.Sort(confirmationEvents)
	wantConfirmationEvents := []string{
		"AgentConsumerTrustConfirmed", "AgentLeafTrustConfirmed",
		"GatewayConsumerTrustConfirmed", "GatewayLeafTrustConfirmed",
	}
	confirmationSites := guardtest.Discover(t, "trust confirmation persistence sites", 2, func() ([]string, error) {
		return coverage.confirmationSites, nil
	})
	slices.Sort(confirmationSites)
	if !slices.Equal(confirmationSites, []string{
		"confirmation.go:ConfirmAgentTrustState", "confirmation.go:ConfirmGatewayTrustState",
	}) {
		t.Fatalf("trust confirmation sites = %v; want exact public reporter-class handlers", confirmationSites)
	}
	confirmationPersistenceSites := guardtest.Discover(t, "trust confirmation persistence call sites", 4, func() ([]string, error) {
		return coverage.confirmationPersistenceSites, nil
	})
	slices.Sort(confirmationPersistenceSites)
	wantConfirmationPersistenceSites := expectedConfirmationPersistenceSites()
	if !slices.Equal(confirmationPersistenceSites, wantConfirmationPersistenceSites) {
		t.Fatalf("trust confirmation persistence calls = %v; want exact leaf/consumer × reporter-handler set %v",
			confirmationPersistenceSites, wantConfirmationPersistenceSites)
	}
	if !slices.Equal(confirmationEvents, wantConfirmationEvents) {
		t.Fatalf("rotation confirmation events = %v; want exact leaf/consumer × agent/gateway set %v",
			confirmationEvents, wantConfirmationEvents)
	}
	if len(coverage.violations) != 0 {
		t.Fatalf("rotation coverage violations: %s", strings.Join(coverage.violations, "; "))
	}

	assertIssuerScopedCRLKey(t)
	service := powermanagev1.File_powermanage_v1_pki_proto.Services().ByName("PkiService")
	procedures := guardtest.Discover(t, "public PkiService procedures", 9, func() ([]string, error) {
		if service == nil {
			return nil, errors.New("PkiService descriptor is absent")
		}
		result := make([]string, 0, service.Methods().Len())
		for index := 0; index < service.Methods().Len(); index++ {
			method := service.Methods().Get(index)
			result = append(result, "/"+string(service.FullName())+"/"+string(method.Name()))
		}
		return result, nil
	})
	slices.Sort(procedures)
	limited := guardtest.Discover(t, "public PkiService limiter entries", 9, func() ([]string, error) {
		return coverage.limitedProcedures, nil
	})
	slices.Sort(limited)
	if !slices.Equal(limited, procedures) {
		t.Fatalf("public PKI limiter registry = %v; descriptor methods = %v", limited, procedures)
	}
}

type pkiRotationCoverage struct {
	phases                       []string
	issuanceSites                []string
	crlSigningSites              []string
	transitionMethods            []string
	confirmationEvents           []string
	confirmationSites            []string
	confirmationPersistenceSites []string
	limitedProcedures            []string
	violations                   []string
}

func assertRotationGuardLiveness(t *testing.T) {
	t.Helper()
	assertConfirmationPersistenceGuardDeletion(t)
	root := t.TempDir()
	source := `package fixture

type RotationManager struct{}

func mixedIssuance() {
	withIssuanceFences(func() {
		issueAgentCertificate()
		AppendEvent()
	})
	issueAgentCertificate()
}

func badCRL() {
	SignAgentRevocationList()
	CompareAndSwapCRL(ctx, class, sequence)
	CRLWorkReceipt(ctx, class, source)
}

func ConfirmAgentTrustState() {
	RecordLeafTrustConfirmation()
}

func (m *RotationManager) BeginTrust() {
	if condition { publishSnapshot() }
	withExclusiveRotationFence(func() { AppendEvent() })
}
`
	if err := os.WriteFile(filepath.Join(root, "fixture.go"), []byte(source), 0o600); err != nil {
		t.Fatalf("write guard liveness fixture: %v", err)
	}
	coverage, err := scanPKIRotationCoverage(root)
	if err != nil {
		t.Fatalf("scan guard liveness fixture: %v", err)
	}
	wantViolationFragments := []string{
		"mixedIssuance:issueAgentCertificate does not hold",
		"badCRL:SignAgentRevocationList does not retain",
		"badCRL:CompareAndSwapCRL does not key",
		"badCRL:CRLWorkReceipt does not key",
		"ConfirmAgentTrustState persists confirmation outside",
		"BeginTrust does not publish",
	}
	joined := strings.Join(coverage.violations, "\n")
	for _, fragment := range wantViolationFragments {
		if !strings.Contains(joined, fragment) {
			t.Fatalf("GUARD-006-7 liveness fixture did not trip %q; violations:\n%s", fragment, joined)
		}
	}
	if len(coverage.issuanceSites) != 2 {
		t.Fatalf("per-call issuance discovery found %d sites; one fenced call must not mask one unfenced call", len(coverage.issuanceSites))
	}
}

func assertConfirmationPersistenceGuardDeletion(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	source := `package fixture

func ConfirmAgentTrustState() {
	withTrustStateFences(func() {
		RecordLeafTrustConfirmation()
		RecordConsumerTrustConfirmation()
		AppendEvent()
	})
}

func ConfirmGatewayTrustState() {
	withTrustStateFences(func() {
		RecordLeafTrustConfirmation()
		RecordConsumerTrustConfirmation()
		AppendEvent()
	})
}
`
	path := filepath.Join(root, "confirmation.go")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatalf("write confirmation guard liveness fixture: %v", err)
	}
	want := expectedConfirmationPersistenceSites()
	coverage, err := scanPKIRotationCoverage(root)
	if err != nil {
		t.Fatalf("scan complete confirmation persistence fixture: %v", err)
	}
	slices.Sort(coverage.confirmationPersistenceSites)
	if !slices.Equal(coverage.confirmationPersistenceSites, want) {
		t.Fatalf("complete confirmation persistence fixture = %v; want %v", coverage.confirmationPersistenceSites, want)
	}

	withoutOneSite := strings.Replace(source, "RecordConsumerTrustConfirmation()", "removedConsumerConfirmationPersistence()", 1)
	if err := os.WriteFile(path, []byte(withoutOneSite), 0o600); err != nil {
		t.Fatalf("delete one confirmation persistence call in liveness fixture: %v", err)
	}
	coverage, err = scanPKIRotationCoverage(root)
	if err != nil {
		t.Fatalf("scan confirmation persistence deletion fixture: %v", err)
	}
	slices.Sort(coverage.confirmationPersistenceSites)
	if slices.Equal(coverage.confirmationPersistenceSites, want) || len(coverage.confirmationPersistenceSites) != len(want)-1 {
		t.Fatalf("deleting one confirmation persistence call left guard set %v; want an exact-set failure against %v", coverage.confirmationPersistenceSites, want)
	}
}

func expectedConfirmationPersistenceSites() []string {
	return []string{
		"confirmation.go:ConfirmAgentTrustState:RecordConsumerTrustConfirmation",
		"confirmation.go:ConfirmAgentTrustState:RecordLeafTrustConfirmation",
		"confirmation.go:ConfirmGatewayTrustState:RecordConsumerTrustConfirmation",
		"confirmation.go:ConfirmGatewayTrustState:RecordLeafTrustConfirmation",
	}
}

func scanPKIRotationCoverage(root string) (pkiRotationCoverage, error) {
	var coverage pkiRotationCoverage
	fileset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if path != root && (entry.Name() == "testdata" || strings.HasPrefix(entry.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fileset, path, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		for _, declaration := range file.Decls {
			switch value := declaration.(type) {
			case *ast.GenDecl:
				discoverRotationConstants(&coverage, value)
				discoverPublicProcedureLimits(&coverage, value)
			case *ast.FuncDecl:
				if value.Body == nil {
					continue
				}
				location := filepath.Base(path) + ":" + value.Name.Name
				for _, call := range namedCalls(value.Body, "issueAgentCertificate", "issueGatewayCertificate") {
					callSite := location + ":" + callName(call)
					coverage.issuanceSites = append(coverage.issuanceSites, callSite)
					if !callInsideFenceWithCommit(value.Body, call, "withIssuanceFences", "AppendEvent", "AppendGatewayEvent") {
						coverage.violations = append(coverage.violations, callSite+" does not hold canonical shared agent+gateway fences through its own event append")
					}
				}
				for _, call := range namedCalls(value.Body, "SignAgentRevocationList", "SignGatewayRevocationList") {
					callSite := location + ":" + callName(call)
					coverage.crlSigningSites = append(coverage.crlSigningSites, callSite)
					if !callInsideFenceWithCommit(value.Body, call, "withCRLIssuerFence", "CompareAndSwapCRL") {
						coverage.violations = append(coverage.violations, callSite+" does not retain the issuer-class shared fence through its own CRL state commit")
					}
				}
				for _, call := range namedCalls(value.Body, "LatestCRL", "CurrentCRLs", "CRLWorkReceipt", "CompareAndSwapCRL") {
					minimum := 3
					if callName(call) == "CRLWorkReceipt" || callName(call) == "CompareAndSwapCRL" {
						minimum = 4
					}
					if len(call.Args) < minimum {
						coverage.violations = append(coverage.violations, location+":"+callName(call)+" does not key CRL state/receipt by exact class and issuer")
					}
					if (callName(call) == "CRLWorkReceipt" || callName(call) == "CompareAndSwapCRL") &&
						!callInsideNamedFence(value.Body, call, "withCRLIssuerFence") {
						coverage.violations = append(coverage.violations, location+":"+callName(call)+" is outside the issuer-class fence")
					}
				}
				for _, call := range namedCalls(value.Body, "RecordLeafTrustConfirmation", "RecordConsumerTrustConfirmation") {
					coverage.confirmationPersistenceSites = append(coverage.confirmationPersistenceSites, location+":"+callName(call))
					if !callInsideFenceWithCommit(value.Body, call, "withTrustStateFences", "AppendEvent", "AppendEvents") {
						coverage.violations = append(coverage.violations, location+" persists confirmation outside canonical reporter+claimed fences")
					}
				}
				if value.Name.Name == "ConfirmAgentTrustState" || value.Name.Name == "ConfirmGatewayTrustState" {
					coverage.confirmationSites = append(coverage.confirmationSites, location)
				}
				if rotationManagerReceiver(value.Recv) && slices.Contains([]string{"BeginTrust", "Abort", "Migrate", "Retire", "Normalize"}, value.Name.Name) {
					coverage.transitionMethods = append(coverage.transitionMethods, value.Name.Name)
					appendCalls := namedCalls(value.Body, "AppendEvent", "AppendEvents")
					if len(appendCalls) == 0 {
						coverage.violations = append(coverage.violations, location+" does not append its phase event under the target-class exclusive fence")
					}
					for _, call := range appendCalls {
						if !callInsideNamedFence(value.Body, call, "withExclusiveRotationFence") {
							coverage.violations = append(coverage.violations, location+" has a phase event append outside the target-class exclusive fence")
						}
					}
					if !transitionPublishesAfterFencedAppend(value.Body) {
						coverage.violations = append(coverage.violations, location+" does not publish its immutable snapshot after durable event append")
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return pkiRotationCoverage{}, err
	}
	coverage.phases = uniqueSorted(coverage.phases)
	coverage.transitionMethods = uniqueSorted(coverage.transitionMethods)
	coverage.confirmationEvents = uniqueSorted(coverage.confirmationEvents)
	coverage.confirmationSites = uniqueSorted(coverage.confirmationSites)
	coverage.confirmationPersistenceSites = uniqueSorted(coverage.confirmationPersistenceSites)
	coverage.limitedProcedures = uniqueSorted(coverage.limitedProcedures)
	return coverage, nil
}

func discoverPublicProcedureLimits(coverage *pkiRotationCoverage, declaration *ast.GenDecl) {
	if declaration.Tok != token.VAR {
		return
	}
	for _, specification := range declaration.Specs {
		value, ok := specification.(*ast.ValueSpec)
		if !ok || len(value.Names) != 1 || value.Names[0].Name != "publicProcedureLimits" || len(value.Values) != 1 {
			continue
		}
		literal, ok := value.Values[0].(*ast.CompositeLit)
		if !ok {
			continue
		}
		for _, element := range literal.Elts {
			pair, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			selector, ok := pair.Key.(*ast.SelectorExpr)
			if !ok || !strings.HasPrefix(selector.Sel.Name, "PkiService") || !strings.HasSuffix(selector.Sel.Name, "Procedure") {
				continue
			}
			method := strings.TrimSuffix(strings.TrimPrefix(selector.Sel.Name, "PkiService"), "Procedure")
			coverage.limitedProcedures = append(coverage.limitedProcedures, "/powermanage.v1.PkiService/"+method)
		}
	}
}

func discoverRotationConstants(coverage *pkiRotationCoverage, declaration *ast.GenDecl) {
	if declaration.Tok != token.CONST {
		return
	}
	rotationGroup := false
	for _, specification := range declaration.Specs {
		value, ok := specification.(*ast.ValueSpec)
		if !ok {
			continue
		}
		if identifier, ok := value.Type.(*ast.Ident); ok {
			rotationGroup = identifier.Name == "RotationPhase"
		}
		for index, name := range value.Names {
			if rotationGroup && strings.HasPrefix(name.Name, "RotationPhase") {
				coverage.phases = append(coverage.phases, name.Name)
			}
			if index < len(value.Values) {
				literal, ok := value.Values[index].(*ast.BasicLit)
				if ok && literal.Kind == token.STRING {
					eventName := strings.Trim(literal.Value, "\"")
					if strings.HasSuffix(eventName, "TrustConfirmed") {
						coverage.confirmationEvents = append(coverage.confirmationEvents, eventName)
					}
				}
			}
		}
	}
}

func insideFenceCallback(body *ast.BlockStmt, fence string, required, commit []string) bool {
	found := false
	ast.Inspect(body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || callName(call) != fence {
			return true
		}
		for _, argument := range call.Args {
			callback, ok := argument.(*ast.FuncLit)
			if !ok {
				continue
			}
			if callsAny(callback.Body, required...) == 0 {
				continue
			}
			if len(commit) != 0 && callsAny(callback.Body, commit...) == 0 {
				continue
			}
			found = true
		}
		return !found
	})
	return found
}

func namedCalls(node ast.Node, names ...string) []*ast.CallExpr {
	allowed := make(map[string]struct{}, len(names))
	for _, name := range names {
		allowed[name] = struct{}{}
	}
	var result []*ast.CallExpr
	ast.Inspect(node, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok {
			if _, wanted := allowed[callName(call)]; wanted {
				result = append(result, call)
			}
		}
		return true
	})
	return result
}

func callInsideFenceWithCommit(body *ast.BlockStmt, target *ast.CallExpr, fence string, commitNames ...string) bool {
	for _, fenceCall := range namedCalls(body, fence) {
		for _, argument := range fenceCall.Args {
			callback, ok := argument.(*ast.FuncLit)
			if !ok || !nodeContainsExactCall(callback.Body, target) {
				continue
			}
			ordered := false
			ast.Inspect(callback.Body, func(node ast.Node) bool {
				block, ok := node.(*ast.BlockStmt)
				if !ok || !nodeContainsExactCall(block, target) {
					return true
				}
				targetIndex := topLevelStatementContaining(block, target)
				if targetIndex >= 0 {
					for _, statement := range block.List[targetIndex+1:] {
						if guaranteedStatementCalls(statement, commitNames...) {
							ordered = true
							return false
						}
					}
				}
				return !ordered
			})
			if ordered {
				return true
			}
		}
	}
	return false
}

func callInsideNamedFence(body *ast.BlockStmt, target *ast.CallExpr, fence string) bool {
	for _, fenceCall := range namedCalls(body, fence) {
		for _, argument := range fenceCall.Args {
			callback, ok := argument.(*ast.FuncLit)
			if ok && nodeContainsExactCall(callback.Body, target) {
				return true
			}
		}
	}
	return false
}

func nodeContainsExactCall(node ast.Node, target *ast.CallExpr) bool {
	found := false
	ast.Inspect(node, func(node ast.Node) bool {
		if node == target {
			found = true
			return false
		}
		return !found
	})
	return found
}

func topLevelStatementContaining(body *ast.BlockStmt, target *ast.CallExpr) int {
	for index, statement := range body.List {
		if nodeContainsExactCall(statement, target) {
			return index
		}
	}
	return -1
}

func guaranteedStatementCalls(statement ast.Stmt, names ...string) bool {
	var node ast.Node = statement
	if branch, ok := statement.(*ast.IfStmt); ok {
		node = branch.Init
		if node == nil {
			return false
		}
	}
	return callsAny(node, names...) > 0
}

func transitionPublishesAfterFencedAppend(body *ast.BlockStmt) bool {
	fenceIndex := -1
	for index, statement := range body.List {
		for _, call := range namedCalls(statement, "withExclusiveRotationFence") {
			if insideFenceCallback(&ast.BlockStmt{List: []ast.Stmt{statement}}, "withExclusiveRotationFence", []string{"AppendEvent", "AppendEvents"}, nil) {
				fenceIndex = index
				_ = call
				break
			}
		}
	}
	if fenceIndex < 0 {
		return false
	}
	for _, statement := range body.List[fenceIndex+1:] {
		if guaranteedStatementCalls(statement, "publishSnapshot") {
			return true
		}
	}
	return false
}

func callsAny(node ast.Node, names ...string) int {
	allowed := make(map[string]struct{}, len(names))
	for _, name := range names {
		allowed[name] = struct{}{}
	}
	count := 0
	ast.Inspect(node, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok {
			if _, wanted := allowed[callName(call)]; wanted {
				count++
			}
		}
		return true
	})
	return count
}

func callName(call *ast.CallExpr) string {
	switch function := call.Fun.(type) {
	case *ast.Ident:
		return function.Name
	case *ast.SelectorExpr:
		return function.Sel.Name
	default:
		return ""
	}
}

func rotationManagerReceiver(receivers *ast.FieldList) bool {
	if receivers == nil || len(receivers.List) != 1 {
		return false
	}
	typeExpression := receivers.List[0].Type
	if pointer, ok := typeExpression.(*ast.StarExpr); ok {
		typeExpression = pointer.X
	}
	identifier, ok := typeExpression.(*ast.Ident)
	return ok && identifier.Name == "RotationManager"
}

func assertIssuerScopedCRLKey(t *testing.T) {
	t.Helper()
	migration, err := os.ReadFile(filepath.Join("..", "store", "migrations", "013_issuer_scoped_crl_state.sql"))
	if err != nil {
		t.Fatalf("read issuer-scoped CRL migration: %v", err)
	}
	normalized := strings.ToLower(strings.Join(strings.Fields(string(migration)), " "))
	if !strings.Contains(normalized, "issuer_fingerprint") ||
		(!strings.Contains(normalized, "primary key (certificate_class, issuer_fingerprint)") &&
			!strings.Contains(normalized, "primary key(certificate_class, issuer_fingerprint)")) {
		t.Fatal("CRL state primary key is not the exact certificate-class + issuer-fingerprint tuple")
	}
	queries, err := os.ReadFile(filepath.Join("..", "store", "queries", "crl.sql"))
	if err != nil {
		t.Fatalf("read CRL queries: %v", err)
	}
	discovered := 0
	for _, block := range strings.Split(string(queries), "-- name: ") {
		normalizedBlock := strings.ToLower(strings.Join(strings.Fields(block), " "))
		if !strings.Contains(normalizedBlock, "crl_state") && !strings.Contains(normalizedBlock, "crl_work_receipts") {
			continue
		}
		discovered++
		if !strings.Contains(normalizedBlock, "certificate_class") || !strings.Contains(normalizedBlock, "issuer_fingerprint") {
			t.Fatalf("issuer-scoped CRL state/receipt query omits exact class+issuer identity: %q", block)
		}
		if where := strings.Index(normalizedBlock, " where "); where >= 0 {
			predicate := normalizedBlock[where:]
			if !strings.Contains(predicate, "certificate_class") || !strings.Contains(predicate, "issuer_fingerprint") {
				t.Fatalf("CRL state/receipt predicate is not keyed by exact class+issuer tuple: %q", block)
			}
		}
	}
	if discovered == 0 {
		t.Fatal("issuer-scoped CRL state/receipt query discovery matched zero blocks")
	}
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	return slices.Sorted(maps.Keys(seen))
}
