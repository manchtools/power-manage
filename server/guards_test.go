package server_test

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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/guardtest"
)

var notFoundSentinels = map[string][]string{
	"database/sql":            {"ErrNoRows"},
	"github.com/jackc/pgx/v5": {"ErrNoRows"},
}

// Guards: INV-13.
func TestGuard_SentinelComparisons(t *testing.T) {
	violations, err := guardtest.SentinelComparisons(
		".",
		notFoundSentinels,
		"internal/store/errors.go",
	)
	if err != nil {
		t.Fatalf("scan server sentinel comparisons: %v", err)
	}
	if len(violations) > 0 {
		t.Fatalf("raw not-found sentinel comparisons: %s", strings.Join(violations, "; "))
	}
	guardtest.Discover(t, "store.IsNotFound call sites", 1, func() ([]string, error) {
		return make([]string, countRecognizerCalls(t, ".")), nil
	})
}

func TestSentinelComparisonGuard_FixtureDetected(t *testing.T) {
	guardtest.RequireViolation(t, "server sentinel comparison", func(root string) ([]string, error) {
		return guardtest.SentinelComparisons(root, notFoundSentinels)
	}, "testdata/guards/sentinel")
	violations, err := guardtest.SentinelComparisons(
		"testdata/guards/sentinel",
		notFoundSentinels,
	)
	if err != nil {
		t.Fatalf("scan planted sentinel fixture: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("planted sentinel violations = %v; want exactly one", violations)
	}
}

// Guards: INV-12.
func TestGuard_ProjectionWritesOnlyFromProjectors(t *testing.T) {
	// These are the only generated projection mutations sanctioned by ES-2;
	// each owner is the projector or reset function that may call it.
	allowed := map[string]string{
		"UpsertInventorySnapshot":                       "projectInventorySnapshot",
		"UpsertInventoryTombstone":                      "projectInventoryTombstone",
		"ResetInventorySnapshots":                       "resetInventorySnapshots",
		"UpsertRegistrationToken":                       "projectRegistrationTokenMint",
		"ProjectRegistrationTokenConsume":               "projectRegistrationTokenConsume",
		"ProjectRegistrationTokenDisable":               "projectRegistrationTokenDisable",
		"ResetRegistrationTokens":                       "resetRegistrationTokens",
		"UpsertDeviceEnrollment":                        "projectAgentEnrollment",
		"UpdateDeviceRenewal":                           "projectAgentCertificateRenewal",
		"UpdateDeviceLifecycleState":                    "projectAgentLifecycleState",
		"InsertCertificateRevocation":                   "projectCertificateRevocation",
		"ResetAgentCertificateRevocations":              "resetDevices",
		"ResetDevices":                                  "resetDevices",
		"UpsertGatewayEnrollment":                       "projectGatewayEnrollment",
		"UpdateGatewayRenewal":                          "projectGatewayRenewal",
		"UpdateGatewayLifecycleState":                   "projectGatewayRevocation",
		"ResetGatewayCertificateRevocations":            "resetGateways",
		"ResetGateways":                                 "resetGateways",
		"InsertPersonalAccessToken":                     "projectPersonalAccessTokenMint",
		"ProjectPersonalAccessTokenRevocation":          "projectPersonalAccessTokenRevocation",
		"ResetPersonalAccessTokens":                     "resetPersonalAccessTokens",
		"InsertUser":                                    "projectUserCreation",
		"InsertOIDCIdentity":                            "projectOIDCIdentityLink",
		"AdvanceUserProjectionVersion":                  "projectOIDCIdentityLink",
		"AdvanceUserProjectionVersionForBootstrapAdmin": "projectBootstrapAdminRoleGrant",
		"InsertBootstrapLogin":                          "projectBootstrapLoginMint",
		"ConsumeBootstrapLogin":                         "projectBootstrapLoginConsume",
		"ResetBootstrapLogins":                          "resetBootstrapLogins",
		"ResetOIDCIdentities":                           "resetUsers",
		"ResetUsers":                                    "resetUsers",
		"InsertSCIMProvider":                            "projectSCIMProviderCreated",
		"RotateSCIMProviderToken":                       "projectSCIMProviderTokenRotated",
		"DisableSCIMProvider":                           "projectSCIMProviderDisabled",
		"ResetSCIMProviders":                            "resetSCIMProviders",
		"InsertSCIMIdentity":                            "projectSCIMIdentityLinked",
		"DeleteSCIMIdentity":                            "projectSCIMIdentityUnlinked",
		"AdvanceUserProjectionVersionForSCIM":           "advanceSCIMUser",
		"DeleteSCIMGroupMembershipsForUser":             "projectSCIMUserDeprovisioned",
		"DeleteUserProjection":                          "projectSCIMUserDeprovisioned",
		"ResetSCIMIdentities":                           "resetUsers",
		"InsertSCIMGroup":                               "projectSCIMGroupCreated",
		"UpdateSCIMGroup":                               "projectSCIMGroupUpdated",
		"AdvanceSCIMGroupProjectionVersion":             "projectSCIMGroupMembershipsReplaced",
		"DeleteSCIMGroup":                               "projectSCIMGroupDeleted",
		"DeleteSCIMGroupMembers":                        "projectSCIMGroupMembershipsReplaced",
		"InsertSCIMGroupMember":                         "projectSCIMGroupMembershipsReplaced",
		"ResetSCIMGroupMembers":                         "resetSCIMGroups",
		"ResetSCIMGroups":                               "resetSCIMGroups",
	}
	var violations []string
	guardtest.Discover(t, "projection mutation call sites", 30, func() ([]string, error) {
		var discovered int
		var err error
		violations, discovered, err = scanProjectionWrites(
			".",
			map[string]bool{
				"certificate_revocations": true,
				"bootstrap_logins":        true,
				"devices":                 true,
				"gateways":                true,
				"inventory_snapshots":     true,
				"oidc_identities":         true,
				"personal_access_tokens":  true,
				"registration_tokens":     true,
				"scim_group_members":      true,
				"scim_groups":             true,
				"scim_identities":         true,
				"scim_providers":          true,
				"users":                   true,
			},
			allowed,
		)
		return make([]string, discovered), err
	})
	if len(violations) > 0 {
		t.Fatalf("projection writes outside projectors: %s", strings.Join(violations, "; "))
	}
}

func TestProjectionWriteGuard_FixtureDetected(t *testing.T) {
	guardtest.RequireViolation(t, "projection write ownership", func(root string) ([]string, error) {
		violations, _, err := scanProjectionWrites(
			root,
			map[string]bool{"inventory_snapshots": true},
			map[string]string{"UpsertInventorySnapshot": "projectInventorySnapshot"},
		)
		return violations, err
	}, "testdata/guards/projection")
	violations, discovered, err := scanProjectionWrites(
		"testdata/guards/projection",
		map[string]bool{"inventory_snapshots": true},
		map[string]string{"UpsertInventorySnapshot": "projectInventorySnapshot"},
	)
	if err != nil {
		t.Fatalf("scan planted projection-write fixture: %v", err)
	}
	if discovered != 1 || len(violations) != 1 {
		t.Fatalf("planted projection scan = (%d, %v); want one discovered violation", discovered, violations)
	}
}

func TestProjectionWriteGuard_RejectsSameNamedUnrelatedReceiver(t *testing.T) {
	violations, discovered, err := scanProjectionWrites(
		"testdata/guards/projection_same_name",
		map[string]bool{"inventory_snapshots": true},
		map[string]string{"UpsertInventorySnapshot": "projectInventorySnapshot"},
	)
	if err != nil {
		t.Fatalf("scan same-named mutation fixture: %v", err)
	}
	if discovered != 0 ||
		len(violations) != 1 ||
		!strings.Contains(violations[0], "does not use the generated query receiver") {
		t.Fatalf("same-named mutation scan = (%d, %v); want one receiver violation",
			discovered, violations)
	}
}

// Guards: TM-3.
func TestGuard_WorkerDiscipline(t *testing.T) {
	var violations []string
	guardtest.Discover(t, "work-queue worker functions", 2, func() ([]string, error) {
		var discovered int
		var err error
		// ES-8 requires both the drain loop and its panic boundary to retain the
		// worker lifecycle protections checked by this guard.
		violations, discovered, err = scanWorkerDiscipline(".", map[string][]string{
			"internal/store/work.go": {"RunOnce", "invokeWorkHandler"},
		})
		return make([]string, discovered), err
	})
	if len(violations) > 0 {
		t.Fatalf("worker-discipline violations: %s", strings.Join(violations, "; "))
	}
}

func TestWorkerDisciplineGuard_FixtureDetected(t *testing.T) {
	guardtest.RequireViolation(t, "worker discipline", func(root string) ([]string, error) {
		violations, _, err := scanWorkerDiscipline(root, map[string][]string{"bad.go": {"RunOnce"}})
		return violations, err
	}, "testdata/guards/worker")
	violations, discovered, err := scanWorkerDiscipline(
		"testdata/guards/worker",
		map[string][]string{"bad.go": {"RunOnce"}},
	)
	if err != nil {
		t.Fatalf("scan planted worker fixture: %v", err)
	}
	if discovered != 1 || len(violations) != 4 {
		t.Fatalf("planted worker scan = (%d, %v); want four discipline violations", discovered, violations)
	}
}

// Guards: INV-12.
func TestGuard_StaticSQLInventory(t *testing.T) {
	var violations []string
	guardtest.Discover(t, "static sqlc queries", 1, func() ([]string, error) {
		var queries int
		var err error
		violations, queries, err = scanDirectDatabaseCalls(".", directDatabaseCallAllowlist)
		return make([]string, queries), err
	})
	if len(violations) > 0 {
		t.Fatalf("database calls outside the static query inventory: %s", strings.Join(violations, "; "))
	}
}

func TestStaticSQLGuard_FixtureDetected(t *testing.T) {
	guardtest.RequireViolation(t, "static SQL inventory", func(root string) ([]string, error) {
		violations, _, err := scanDirectDatabaseCalls(root, nil)
		return violations, err
	}, "testdata/guards/dynamic_sql")
	violations, _, err := scanDirectDatabaseCalls("testdata/guards/dynamic_sql", nil)
	if err != nil {
		t.Fatalf("scan planted dynamic-SQL fixture: %v", err)
	}
	if len(violations) != 1 {
		t.Fatalf("planted dynamic-SQL violations = %v; want exactly one", violations)
	}
}

func TestStaticSQLGuard_AllowlistIsExact(t *testing.T) {
	const root = "testdata/guards/dynamic_sql"
	violations, _, err := scanDirectDatabaseCalls(root, map[string]int{"bad.go:Exec": 1})
	if err != nil {
		t.Fatalf("scan exact direct-database exemption: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("exact direct-database exemption violations = %v; want none", violations)
	}

	violations, _, err = scanDirectDatabaseCalls(root, map[string]int{"bad.go:Exec": 2})
	if err != nil {
		t.Fatalf("scan mismatched direct-database exemption: %v", err)
	}
	const want = "direct-database allowlist bad.go:Exec matched 1 calls; want 2"
	if len(violations) != 1 || violations[0] != want {
		t.Fatalf("mismatched direct-database exemption violations = %v; want %q", violations, want)
	}
}

func countRecognizerCalls(t *testing.T, root string) int {
	t.Helper()
	count := 0
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
		files, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(files, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch function := call.Fun.(type) {
			case *ast.Ident:
				if function.Name == "IsNotFound" {
					count++
				}
			case *ast.SelectorExpr:
				if function.Sel.Name == "IsNotFound" {
					count++
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("count store.IsNotFound call sites: %v", err)
	}
	return count
}

var (
	queryHeaderPattern          = regexp.MustCompile(`(?m)^-- name: ([A-Za-z][A-Za-z0-9_]*)\s+:[a-z]+\s*$`)
	mutationPattern             = regexp.MustCompile(`(?i)\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(?:"?public"?\.)?"?([a-z_][a-z0-9_]*)"?`)
	generatedQueryPackage       = "github.com/manchtools/power-manage/server/internal/store/generated"
	directDatabaseCallAllowlist = map[string]int{
		// Template-cloned test databases require dynamically named CREATE and
		// DROP statements. The exact two Exec sites are test infrastructure,
		// not production persistence.
		"internal/testpostgres/harness.go:Exec": 2,
	}
)

func scanProjectionWrites(
	root string,
	projectionTables map[string]bool,
	allowed map[string]string,
) ([]string, int, error) {
	if len(projectionTables) == 0 || len(allowed) == 0 {
		return nil, 0, fmt.Errorf("projection-write guard registry is empty")
	}
	var violations []string
	queryDir := filepath.Join(root, "internal", "store", "queries")
	queryMethods, queryDirExists, err := projectionMutationQueries(queryDir, projectionTables)
	if err != nil {
		return nil, 0, err
	}
	if queryDirExists {
		if len(queryMethods) == 0 {
			violations = append(violations, "query inventory discovered zero projection mutations")
		}
		for method, table := range queryMethods {
			if _, ok := allowed[method]; !ok {
				violations = append(violations, fmt.Sprintf("query %s mutates projection table %s without an owner", method, table))
			}
		}
		for method := range allowed {
			if _, ok := queryMethods[method]; !ok {
				violations = append(violations, fmt.Sprintf("allowed projection mutation %s is absent from query inventory", method))
			}
		}
	}

	discovered := 0
	seen := make(map[string]int)
	typeImporter := newProjectionGuardImporter()
	err = filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if filePath != root && (entry.Name() == "testdata" || entry.Name() == "generated" || strings.HasPrefix(entry.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(filePath, ".go") || strings.HasSuffix(filePath, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filePath, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", filePath, err)
		}
		rel, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		typeInfo := &types.Info{
			Types:      make(map[ast.Expr]types.TypeAndValue),
			Defs:       make(map[*ast.Ident]types.Object),
			Uses:       make(map[*ast.Ident]types.Object),
			Selections: make(map[*ast.SelectorExpr]*types.Selection),
		}
		typeConfig := types.Config{
			Importer: typeImporter,
			Error:    func(error) {},
		}
		_, _ = typeConfig.Check(file.Name.Name, fset, []*ast.File{file}, typeInfo)
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				return true
			}
			for _, match := range mutationPattern.FindAllStringSubmatch(value, -1) {
				if projectionTables[strings.ToLower(match[1])] {
					violations = append(violations, fmt.Sprintf("%s:%d: raw projection SQL for %s", rel, fset.Position(literal.Pos()).Line, match[1]))
				}
			}
			return true
		})
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				owner, ok := allowed[selector.Sel.Name]
				if !ok {
					return true
				}
				if !isGeneratedQueryReceiver(selector.X, typeInfo) {
					violations = append(violations, fmt.Sprintf(
						"%s:%d: same-named mutation %s does not use the generated query receiver",
						rel,
						fset.Position(call.Pos()).Line,
						selector.Sel.Name,
					))
					return true
				}
				discovered++
				seen[selector.Sel.Name]++
				if function.Name.Name != owner {
					violations = append(violations, fmt.Sprintf("%s:%d: %s called from %s; want %s", rel, fset.Position(call.Pos()).Line, selector.Sel.Name, function.Name.Name, owner))
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	if queryDirExists {
		for method := range allowed {
			if seen[method] != 1 {
				violations = append(violations, fmt.Sprintf("projection mutation %s has %d call sites; want 1", method, seen[method]))
			}
		}
	}
	sort.Strings(violations)
	return violations, discovered, nil
}

func isGeneratedQueryReceiver(
	expression ast.Expr,
	info *types.Info,
) bool {
	if info == nil {
		return false
	}
	receiverType := info.TypeOf(expression)
	pointer, ok := receiverType.(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := pointer.Elem().(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return false
	}
	return named.Obj().Name() == "Queries" &&
		named.Obj().Pkg().Path() == generatedQueryPackage
}

type projectionGuardImporter struct {
	fallback  types.Importer
	generated *types.Package
}

func newProjectionGuardImporter() projectionGuardImporter {
	pkg := types.NewPackage(generatedQueryPackage, "generated")
	queriesName := types.NewTypeName(token.NoPos, pkg, "Queries", nil)
	queries := types.NewNamed(queriesName, types.NewStruct(nil, nil), nil)
	pkg.Scope().Insert(queriesName)
	emptyInterface := types.NewInterfaceType(nil, nil)
	emptyInterface.Complete()
	parameters := types.NewTuple(types.NewParam(token.NoPos, pkg, "db", emptyInterface))
	results := types.NewTuple(types.NewParam(
		token.NoPos,
		pkg,
		"",
		types.NewPointer(queries),
	))
	pkg.Scope().Insert(types.NewFunc(
		token.NoPos,
		pkg,
		"New",
		types.NewSignatureType(nil, nil, nil, parameters, results, false),
	))
	pkg.MarkComplete()
	return projectionGuardImporter{
		fallback:  importer.Default(),
		generated: pkg,
	}
}

func (i projectionGuardImporter) Import(path string) (*types.Package, error) {
	if path == generatedQueryPackage {
		return i.generated, nil
	}
	return i.fallback.Import(path)
}

func projectionMutationQueries(
	queryDir string,
	projectionTables map[string]bool,
) (map[string]string, bool, error) {
	entries, err := os.ReadDir(queryDir)
	if os.IsNotExist(err) {
		return map[string]string{}, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read query inventory %s: %w", queryDir, err)
	}
	methods := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		path := filepath.Join(queryDir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, true, fmt.Errorf("read query file %s: %w", path, err)
		}
		headers := queryHeaderPattern.FindAllSubmatchIndex(content, -1)
		for index, header := range headers {
			end := len(content)
			if index+1 < len(headers) {
				end = headers[index+1][0]
			}
			method := string(content[header[2]:header[3]])
			for _, mutation := range mutationPattern.FindAllSubmatch(content[header[1]:end], -1) {
				table := strings.ToLower(string(mutation[1]))
				if !projectionTables[table] {
					continue
				}
				if prior, ok := methods[method]; ok && prior != table {
					return nil, true, fmt.Errorf("query %s mutates multiple projection tables", method)
				}
				methods[method] = table
			}
		}
	}
	return methods, true, nil
}

func scanWorkerDiscipline(
	root string,
	workerFiles map[string][]string,
) ([]string, int, error) {
	if len(workerFiles) == 0 {
		return nil, 0, fmt.Errorf("worker-discipline registry is empty")
	}
	var violations []string
	discovered := 0
	for relativePath, functionNames := range workerFiles {
		if len(functionNames) == 0 {
			return nil, 0, fmt.Errorf("worker file %s has zero registered functions", relativePath)
		}
		path := filepath.Join(root, filepath.FromSlash(relativePath))
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil, 0, fmt.Errorf("parse worker file %s: %w", path, err)
		}
		contextNames := map[string]bool{}
		for _, imported := range file.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil || importPath != "context" || (imported.Name != nil && imported.Name.Name == "_") {
				continue
			}
			if imported.Name == nil {
				contextNames["context"] = true
			} else if imported.Name.Name != "." {
				contextNames[imported.Name.Name] = true
			}
		}
		wanted := make(map[string]bool, len(functionNames))
		for _, name := range functionNames {
			wanted[name] = true
		}
		found := make(map[string]bool, len(functionNames))
		hasWithoutCancel := false
		hasTimeout := false
		hasRecover := false
		hasAdvisoryLock := false
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil || !wanted[function.Name.Name] {
				continue
			}
			discovered++
			found[function.Name.Name] = true
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch callee := call.Fun.(type) {
				case *ast.Ident:
					if callee.Name == "recover" {
						hasRecover = true
					}
				case *ast.SelectorExpr:
					if callee.Sel.Name == "TryWorkQueueLock" {
						hasAdvisoryLock = true
					}
					identifier, ok := callee.X.(*ast.Ident)
					if !ok || !contextNames[identifier.Name] {
						return true
					}
					switch callee.Sel.Name {
					case "WithoutCancel":
						hasWithoutCancel = true
					case "WithTimeout":
						hasTimeout = true
					}
				}
				return true
			})
		}
		for name := range wanted {
			if !found[name] {
				violations = append(violations, fmt.Sprintf("%s: registered worker function %s is missing", relativePath, name))
			}
		}
		if !hasWithoutCancel {
			violations = append(violations, relativePath+": worker lacks context.WithoutCancel")
		}
		if !hasTimeout {
			violations = append(violations, relativePath+": worker lacks context.WithTimeout")
		}
		if !hasRecover {
			violations = append(violations, relativePath+": worker lacks recover")
		}
		if !hasAdvisoryLock {
			violations = append(violations, relativePath+": worker lacks Postgres advisory lock")
		}
	}
	sort.Strings(violations)
	return violations, discovered, nil
}

func scanDirectDatabaseCalls(root string, allowlist map[string]int) ([]string, int, error) {
	queries := 0
	queryDir := filepath.Join(root, "internal", "store", "queries")
	entries, err := os.ReadDir(queryDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, 0, fmt.Errorf("read static query inventory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(queryDir, entry.Name()))
		if err != nil {
			return nil, 0, fmt.Errorf("read static query file %s: %w", entry.Name(), err)
		}
		queries += len(queryHeaderPattern.FindAll(content, -1))
	}

	databaseMethods := map[string]bool{
		"Exec":            true,
		"ExecContext":     true,
		"Query":           true,
		"QueryContext":    true,
		"QueryRow":        true,
		"QueryRowContext": true,
	}
	var violations []string
	allowlistHits := make(map[string]int, len(allowlist))
	err = filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if filePath != root && (entry.Name() == "testdata" || entry.Name() == "generated" || strings.HasPrefix(entry.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(filePath, ".go") || strings.HasSuffix(filePath, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, filePath, nil, 0)
		if err != nil {
			return fmt.Errorf("parse %s: %w", filePath, err)
		}
		rel, err := filepath.Rel(root, filePath)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !databaseMethods[selector.Sel.Name] {
				return true
			}
			key := filepath.ToSlash(rel) + ":" + selector.Sel.Name
			if _, ok := allowlist[key]; ok {
				allowlistHits[key]++
				return true
			}
			violations = append(violations, fmt.Sprintf(
				"%s:%d: direct %s call bypasses the static sqlc query inventory",
				filepath.ToSlash(rel),
				fset.Position(call.Pos()).Line,
				selector.Sel.Name,
			))
			return true
		})
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	for key, want := range allowlist {
		if got := allowlistHits[key]; got != want {
			violations = append(violations, fmt.Sprintf(
				"direct-database allowlist %s matched %d calls; want %d",
				key,
				got,
				want,
			))
		}
	}
	sort.Strings(violations)
	return violations, queries, nil
}
