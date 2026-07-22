package archtest

// SPEC-003 G-7 deny-list guard (TestGuard_DenyList, AC-11, [WIRE-30], plan
// choice 11). Two scans, both self-discovering with matches-zero protection:
//   - a descriptor scan over every contract proto file (Discover floor 11 —
//     the post-M5 steady-state proto-file count: current 12 minus the deleted
//     scim/export protos plus the new artifact.proto, per operator commit
//     e9b8c29; the scan fails if it processes zero, or fewer than that, files)
//     flagging the banned field names, banned RPC name, and reserved-backend
//     enum-value tokens [WIRE-30] names;
//   - an AST import scan across all four workspace modules (Discover floor 4)
//     flagging the banned middle-tier dependencies (Asynq, Valkey/Redis
//     clients) whose Postgres-/stream-based replacements TM-1 mandates.
// Reintroducing any banned shape is a BUILD failure here, not a review comment.

import (
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// bannedFieldNames are the [WIRE-30] field-name bans: a self-asserted identity
// token, and the JSON second-representation of signed content. device_id /
// gateway_id are NOT here — they are legitimate ADDRESSING fields (choice 11);
// the deny-list bans only the two unambiguous names.
var bannedFieldNames = map[string]bool{
	"auth_token":       true, // self-asserted identity; identity is the mTLS cert ([WIRE-18])
	"params_canonical": true, // a second representation lets executed bytes diverge from verified ([WIRE-14])
}

// pkiAuthenticationFieldNames are forbidden throughout every PkiService
// request closure (GUARD-006-3). device_id and gateway_id remain legal as
// addressing fields elsewhere; on the unauthenticated PKI boundary they would
// be self-asserted identity inputs.
var pkiAuthenticationFieldNames = map[string]bool{
	"auth_token": true,
	"device_id":  true,
	"gateway_id": true,
}

// bannedRPCNames are the [WIRE-30] RPC bans. The sole agent-upgrade path is the
// signed AGENT_UPDATE action (AG-16); a dedicated trigger RPC is one of the
// drifting update paths the deny-list deletes.
var bannedRPCNames = map[string]bool{
	"TriggerAgentUpdate": true,
}

// reservedBackendTokens are the [WIRE-4]/[WIRE-30] reserved-backend markers: an
// enum value naming a backend with no implementation is dead contract surface.
// Matched as a full underscore-delimited component of the SCREAMING_SNAKE value
// name (so INIT_S6 flags but a value merely containing "s6" as a substring does
// not — avoids false positives on the two-character tokens).
var reservedBackendTokens = []string{
	"GELI", "CGD", // encryption backends
	"CONNMAN", "WPA_SUPPLICANT", "IWD", // network backends
	"OPENRC", "RUNIT", "S6", // init backends
	"DOAS", // privilege backend
}

// bannedImportPrefixes are the [WIRE-30] middle-tier dependency bans: Asynq and
// the Valkey/Redis client families. A queue/registry holding state a restart
// can lose violates TM-1; the replacement is Postgres- or stream-based. This is
// a test-owned threat model — a new client family needs a new prefix here.
var bannedImportPrefixes = []string{
	"github.com/hibiken/asynq",
	"github.com/valkey-io/valkey-go",
	"github.com/redis/go-redis",
	"github.com/go-redis/redis",
	"github.com/gomodule/redigo",
}

// TestGuard_DenyList is G-7 over the real contract + workspace (AC-11).
//
// INV-7 scope: the schema half — auth_token (a plaintext self-asserted
// credential on the wire) and the [WIRE-30] plaintext-secret shapes cannot
// return to the contract; sealed transport is the only secret carriage
// ([WIRE-23/24]). Runtime redaction and audit halves arm with SPEC-011/015
// — extend there, never weaken here. TM-1 scope: the banned middle-tier
// dependencies (Asynq, Valkey/Redis) whose restart-losable state TM-1
// forbids are unimportable in all four modules; the total storage
// classification half arms with SPEC-005.
//
// Guards: INV-7, TM-1.
func TestGuard_DenyList(t *testing.T) {
	files := Discover(t, "contract proto files", 11, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(ContractPackage), nil
	})
	Discover(t, "contract messages visited by the identity-field deny-list", 1, func() ([]protoreflect.MessageDescriptor, error) {
		return allMessages(files), nil
	})
	for _, v := range bannedFieldNameViolations(files) {
		t.Errorf("%s (G-7, [WIRE-30], SPEC-003)", v)
	}
	pkiViolations, err := pkiAuthenticationFieldViolations(files, "PkiService")
	if err != nil {
		t.Fatalf("GUARD-006-3 PkiService request discovery: %v", err)
	}
	for _, v := range pkiViolations {
		t.Errorf("%s (GUARD-006-3, [WIRE-18], SPEC-006)", v)
	}
	for _, v := range bannedRPCViolations(files) {
		t.Errorf("%s (G-7, [WIRE-30], SPEC-003)", v)
	}
	for _, v := range bannedEnumValueViolations(files) {
		t.Errorf("%s (G-7, [WIRE-30], SPEC-003)", v)
	}

	root := archtestRepoRoot(t)
	mods := Discover(t, "in-repo modules from go.work", 4, func() ([]string, error) {
		return workspaceModuleDirs(root)
	})
	for _, mod := range mods {
		v, err := goImportViolations(mod, bannedImportPrefixes)
		if err != nil {
			t.Fatalf("import scan of %s: %v", mod, err)
		}
		for _, s := range v {
			t.Errorf("%s (G-7, [WIRE-30], TM-1, SPEC-003)", s)
		}
	}
}

// TestGuard_DenyList_Liveness plants each descriptor family in the fixture
// package (banned field names, a banned RPC, a reserved-backend enum value) and
// asserts each is flagged EXACTLY, while the clean siblings pass — proof the
// deny-list can still go red for every descriptor family.
func TestGuard_DenyList_Liveness(t *testing.T) {
	files := Discover(t, "fixture proto files", 1, func() ([]protoreflect.FileDescriptor, error) {
		return packageFiles(fixturePackage), nil
	})

	requireExactPrefixes(t, "banned field names", bannedFieldNameViolations(files), []string{
		"powermanage.fixture.v1.FixtureDenyCamel.authToken",
		"powermanage.fixture.v1.FixtureDenyFields.auth_token",
		"powermanage.fixture.v1.FixtureDenyFields.params_canonical",
		"powermanage.fixture.v1.FixturePkiIdentityRequest.auth_token",
	}, []string{"clean_token"})

	pkiViolations, err := pkiAuthenticationFieldViolations(files, "FixtureService")
	if err != nil {
		t.Fatalf("GUARD-006-3 fixture service discovery: %v", err)
	}
	requireExactPrefixes(t, "PkiService authentication fields", pkiViolations, []string{
		"powermanage.fixture.v1.FixturePkiIdentityNested.gateway_id",
		"powermanage.fixture.v1.FixturePkiIdentityRequest.auth_token",
		"powermanage.fixture.v1.FixturePkiJSONAlias.claimed_identity",
		"powermanage.fixture.v1.FixturePkiIdentityRequest.device_id",
	}, []string{"FixtureAddressingFields", "tagged_id", "clean_token"})

	requireExactPrefixes(t, "banned RPC names", bannedRPCViolations(files), []string{
		"powermanage.fixture.v1.FixtureService.TriggerAgentUpdate",
	}, []string{".Do"})

	requireExactPrefixes(t, "reserved-backend enum values", bannedEnumValueViolations(files), []string{
		"powermanage.fixture.v1.FixtureBadEnum.FIXTURE_BAD_ENUM_BACKEND_OPENRC",
	}, []string{"FIXTURE_BAD_ENUM_ACTIVE", "FIXTURE_BAD_ENUM_OTHER", "FIXTURE_GOOD_ENUM"})
}

// TestGuard_DenyList_ImportLiveness plants two banned dependency families in a
// testdata tree (Asynq, a Valkey client) beside a clean Postgres sibling; the
// import scan must flag exactly the two banned files. The tree lives under
// testdata, so the Go toolchain never compiles it and the banned modules are
// never real dependencies.
func TestGuard_DenyList_ImportLiveness(t *testing.T) {
	// Discover the planted violations directly (floor 1 = the scan MUST still be
	// able to go red; also satisfies G-000-3 — the guard calls Discover in body).
	got := Discover(t, "planted banned imports in the fixture tree", 1, func() ([]string, error) {
		return goImportViolations("testdata/bannedimports", bannedImportPrefixes)
	})
	requireExactPrefixes(t, "banned imports", got, []string{
		"cache/cache.go",
		"dispatch/queue.go",
	}, []string{"clean/clean.go"})
}

// TestDenyListSets_ThreatModel keeps the ban sets honest: each is non-empty
// (matches-zero on the threat model itself), the component matcher catches real
// backend values without over-matching two-character tokens, and the import
// prefixes classify each banned family while leaving the sanctioned Postgres /
// stdlib replacements clean.
func TestDenyListSets_ThreatModel(t *testing.T) {
	if len(bannedFieldNames) == 0 || len(pkiAuthenticationFieldNames) == 0 || len(bannedRPCNames) == 0 || len(reservedBackendTokens) == 0 || len(bannedImportPrefixes) == 0 {
		t.Fatal("a deny-list ban set is empty — the threat model lost its subjects (G-7)")
	}
	// The component matcher flags real backend values...
	for _, v := range []string{"ENCRYPTION_BACKEND_GELI", "SERVICE_MANAGER_OPENRC", "INIT_S6", "NETWORK_WPA_SUPPLICANT", "PRIV_DOAS"} {
		if reservedBackendToken(v) == "" {
			t.Errorf("value %q carries a reserved backend token but the matcher missed it", v)
		}
	}
	// ...without over-matching a mere substring of a two-character token.
	for _, v := range []string{"STATE_PROCESSED", "MODE_OS64", "RESULT_UNSPECIFIED", "DIRECTION_INPUT"} {
		if tok := reservedBackendToken(v); tok != "" {
			t.Errorf("clean value %q matched reserved token %q — the component matcher over-flags", v, tok)
		}
	}
	for _, imp := range []string{
		"github.com/hibiken/asynq",
		"github.com/valkey-io/valkey-go/valkeycompat",
		"github.com/redis/go-redis/v9",
	} {
		if bannedImportPrefix(imp) == "" {
			t.Errorf("banned dependency import %q not classified — the prefix set lost a family", imp)
		}
	}
	for _, imp := range []string{"database/sql", "github.com/jackc/pgx/v5", "github.com/manchtools/power-manage/contract/gen/go/powermanage/v1"} {
		if tok := bannedImportPrefix(imp); tok != "" {
			t.Errorf("sanctioned import %q classified via %q — the import scan over-matches", imp, tok)
		}
	}
}

// ---------------------------------------------------------------------------
// descriptor scans
// ---------------------------------------------------------------------------

// canonicalFieldToken lowers a field name and strips underscores so the
// snake, camel, and screaming spellings of a banned name all collide with
// its canonical form — proto3 accepts non-snake field names, and a
// case-only compare would accept authToken while banning auth_token
// (review finding, PR #19 round 1).
func canonicalFieldToken(name string) string {
	return strings.ReplaceAll(strings.ToLower(name), "_", "")
}

func bannedFieldNameViolations(files []protoreflect.FileDescriptor) []string {
	canon := make(map[string]bool, len(bannedFieldNames))
	for name := range bannedFieldNames {
		canon[canonicalFieldToken(name)] = true
	}
	var out []string
	for _, md := range allMessages(files) {
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			if fieldMatchesCanonicalName(f, canon) {
				out = append(out, fmt.Sprintf("%s: field or JSON name is on the [WIRE-30] deny-list — self-asserted identity comes only from the mTLS cert, and signed content has ONE deterministic representation", f.FullName()))
			}
		}
	}
	sort.Strings(out)
	return out
}

func pkiAuthenticationFieldViolations(files []protoreflect.FileDescriptor, serviceName protoreflect.Name) ([]string, error) {
	service, err := findService(files, serviceName)
	if err != nil {
		return nil, err
	}

	seen := make(map[protoreflect.FullName]protoreflect.MessageDescriptor)
	methods := service.Methods()
	for i := 0; i < methods.Len(); i++ {
		for _, message := range messageClosure(files, methods.Get(i).Input()) {
			seen[message.FullName()] = message
		}
	}

	canon := make(map[string]bool, len(pkiAuthenticationFieldNames))
	for name := range pkiAuthenticationFieldNames {
		canon[canonicalFieldToken(name)] = true
	}
	var out []string
	for _, message := range seen {
		fields := message.Fields()
		for i := 0; i < fields.Len(); i++ {
			field := fields.Get(i)
			if fieldMatchesCanonicalName(field, canon) {
				out = append(out, fmt.Sprintf("%s: PkiService request field self-asserts authentication identity — authorization comes from the operation credential and issued certificate, never device_id, gateway_id, or auth_token", field.FullName()))
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func fieldMatchesCanonicalName(field protoreflect.FieldDescriptor, denied map[string]bool) bool {
	return denied[canonicalFieldToken(string(field.Name()))] ||
		denied[canonicalFieldToken(field.JSONName())]
}

func bannedRPCViolations(files []protoreflect.FileDescriptor) []string {
	var out []string
	for _, fd := range files {
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			ms := svcs.Get(i).Methods()
			for j := 0; j < ms.Len(); j++ {
				m := ms.Get(j)
				if bannedRPCNames[string(m.Name())] {
					out = append(out, fmt.Sprintf("%s: RPC name is on the [WIRE-30] deny-list — the sole agent-upgrade path is the signed AGENT_UPDATE action (AG-16)", m.FullName()))
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func bannedEnumValueViolations(files []protoreflect.FileDescriptor) []string {
	var out []string
	for _, ed := range enums(files) {
		vals := ed.Values()
		for i := 0; i < vals.Len(); i++ {
			v := vals.Get(i)
			if tok := reservedBackendToken(string(v.Name())); tok != "" {
				out = append(out, fmt.Sprintf("%s.%s: enum value names reserved backend %q — a value with no implementation is dead contract surface ([WIRE-4]/[WIRE-30])", ed.FullName(), v.Name(), tok))
			}
		}
	}
	sort.Strings(out)
	return out
}

// reservedBackendToken returns the reserved token that appears as a full
// underscore-delimited component of the SCREAMING_SNAKE enum value name, or "".
func reservedBackendToken(valueName string) string {
	padded := "_" + strings.ToUpper(valueName) + "_"
	for _, tok := range reservedBackendTokens {
		if strings.Contains(padded, "_"+tok+"_") {
			return tok
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// import scan (own harness — contract cannot import sdk/guardtest, INV-19)
// ---------------------------------------------------------------------------

func bannedImportPrefix(imp string) string {
	for _, p := range bannedImportPrefixes {
		if imp == p || strings.HasPrefix(imp, p+"/") {
			return p
		}
	}
	return ""
}

// goImportViolations parses every .go file (tests included — a test importing a
// banned module links the same code) under root, skipping testdata and hidden
// subdirectories so a fixture tree never leaks into a real scan, and returns a
// violation per banned import.
func goImportViolations(root string, prefixes []string) ([]string, error) {
	var out []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if p != root && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		file, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parse %s: %w", p, err)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return fmt.Errorf("rel %s: %w", p, err)
		}
		for _, imp := range file.Imports {
			path, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil {
				continue
			}
			if tok := bannedImportPrefix(path); tok != "" {
				out = append(out, fmt.Sprintf("%s:%d: imports banned dependency %q (family %s) — dispatch/registry/cache have Postgres- or stream-based replacements; a middle tier holding losable state violates TM-1 ([WIRE-30])",
					filepath.ToSlash(rel), fset.Position(imp.Path.Pos()).Line, path, tok))
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// workspaceModuleDirs returns the module directories named by the repo's
// go.work use directives — the self-discovering population for the import
// scan (floor 4). It parses ONLY use directives (single-line and block),
// strips comments first, and accepts every legal path form (./-relative,
// bare relative, quoted, absolute): a missed form would silently exempt a
// module from the scan (fail-open), and a comment or replace token taken
// for a module would poison the walk (review finding, PR #19 round 1).
func workspaceModuleDirs(root string) ([]string, error) {
	src, err := os.ReadFile(filepath.Join(root, "go.work"))
	if err != nil {
		return nil, fmt.Errorf("reading go.work: %w", err)
	}
	var dirs []string
	inUseBlock := false
	for _, line := range strings.Split(string(src), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		var path string
		switch {
		case inUseBlock:
			if line == ")" {
				inUseBlock = false
				continue
			}
			path = line
		case line == "use (":
			inUseBlock = true
			continue
		case strings.HasPrefix(line, "use "):
			path = strings.TrimSpace(strings.TrimPrefix(line, "use "))
		default:
			continue
		}
		if path == "" {
			continue
		}
		if unquoted, uerr := strconv.Unquote(path); uerr == nil {
			path = unquoted
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, filepath.FromSlash(path))
		}
		dirs = append(dirs, path)
	}
	sort.Strings(dirs)
	return dirs, nil
}

// TestWorkspaceModuleDirs_Grammar enumerates the go.work input families the
// parser must decide (the matcher's grammar is the threat model): block and
// single-line use directives, quoted paths, paths WITHOUT the ./ prefix
// (legal go.work syntax — missing one silently exempts a module from the
// import scan, fail-open), absolute paths, and ./-tokens inside comments or
// replace directives (which must NOT be collected).
func TestWorkspaceModuleDirs_Grammar(t *testing.T) {
	root := t.TempDir()
	work := `go 1.26

// a comment naming ./commented must not be collected
use (
	./contract // trailing comment
	plain
	"./qu oted"
	/abs/mod
)

use ./single
use bare

replace example.com/x => ./replaced
`
	if err := os.WriteFile(filepath.Join(root, "go.work"), []byte(work), 0o600); err != nil {
		t.Fatalf("writing fixture go.work: %v", err)
	}
	got, err := workspaceModuleDirs(root)
	if err != nil {
		t.Fatalf("workspaceModuleDirs: %v", err)
	}
	want := []string{
		"/abs/mod",
		filepath.Join(root, "bare"),
		filepath.Join(root, "contract"),
		filepath.Join(root, "plain"),
		filepath.Join(root, "qu oted"),
		filepath.Join(root, "single"),
	}
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("workspaceModuleDirs = %v, want %v — every use directive is a scanned module (missing one exempts it from the import guard, fail-open) and comment/replace tokens are never modules", got, want)
	}
}

// archtestRepoRoot walks up from the test's working directory to the go.work
// directory — the repo root. contract/archtest cannot import sdk/guardtest's
// RepoRoot (INV-19), so this mirrors it.
func archtestRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		} else if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("stat %s/go.work: %v", dir, err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no go.work found walking up from the working directory — run the guard from inside the repository")
		}
		dir = parent
	}
}

// requireExactPrefixes asserts got is exactly the wanted set (each want is a
// substring that must match exactly one violation) and that no violation
// mentions any clean marker.
func requireExactPrefixes(t *testing.T, what string, got, want, cleanMarkers []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %d violations %v, want exactly %d matching %v — the guard can no longer go red for exactly the planted shapes", what, len(got), got, len(want), want)
	}
	for _, w := range want {
		n := 0
		for _, g := range got {
			if strings.Contains(g, w) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%s: want exactly one violation matching %q, got %d (all: %v)", what, w, n, got)
		}
	}
	for _, clean := range cleanMarkers {
		for _, g := range got {
			if strings.Contains(g, clean) {
				t.Errorf("%s: violation %q mentions clean marker %q — the guard over-flags", what, g, clean)
			}
		}
	}
}
