package guardtest

import (
	"path/filepath"
	"testing"
)

// TestGuard_DirectionalImports is G-002-1 (SPEC-002 AC-2): every in-repo
// import obeys the §3.3 directional allowlist — simultaneously the
// architecture and the licensing boundary. Discovery: modules from go.work,
// identities from go.mod, packages from the walk; floors ratchet per
// modulePackageFloors as specs land code.
//
// Guards: INV-19.
func TestGuard_DirectionalImports(t *testing.T) {
	root := RepoRoot(t)
	mods := Discover(t, "workspace modules from go.work", 4, func() ([]string, error) {
		return workspaceModules(root)
	})
	v, pkgs, err := directionalImportViolations(root, mods)
	if err != nil {
		t.Fatalf("scanning module imports: %v", err)
	}
	Discover(t, "Go packages across the workspace", 1, func() ([]string, error) {
		var flat []string
		for mod, dirs := range pkgs {
			for _, d := range dirs {
				flat = append(flat, mod+"/"+d)
			}
		}
		return flat, nil
	})
	for mod, floor := range modulePackageFloors {
		if len(pkgs[mod]) < floor {
			t.Errorf("module %s has %d packages, floor is %d — a code-bearing module cannot drop to zero; fix the walk, never lower the floor without a spec change", mod, len(pkgs[mod]), floor)
		}
	}
	for _, s := range v {
		t.Errorf("%s — INV-19: contract/sdk import nothing in-repo; agent/server import only contract+sdk (SPEC-002 §3.3); an agent→server import relicenses the GPL binary AGPL", s)
	}
}

// TestGuard_DirectionalImports_Liveness: the fixture workspace plants
// sdk→contract (blank import) and agent→server (aliased import — the
// licensing breach); server→contract is allowed and must stay clean.
func TestGuard_DirectionalImports_Liveness(t *testing.T) {
	scan := func(root string) ([]string, error) {
		mods, err := workspaceModules(root)
		if err != nil {
			return nil, err
		}
		v, _, err := directionalImportViolations(root, mods)
		return v, err
	}
	RequireViolation(t, "directional imports", scan, "testdata/arch/imports/ws")
	v, err := scan("testdata/arch/imports/ws")
	if err != nil {
		t.Fatalf("scanning the ws fixture: %v", err)
	}
	requireFlagged(t, v, []string{
		"sdk/cap/cap.go:5",   // sdk → contract, blank import
		"agent/run/run.go:5", // agent → server, aliased import
	}, []string{"server/core/core.go", "contract/api/api.go"})
}

// TestGuard_ProtoPurity is G-002-2 (SPEC-002 AC-3): sdk is pure OS
// mechanism — zero proto/connect/protobuf or generated-contract imports.
func TestGuard_ProtoPurity(t *testing.T) {
	root := RepoRoot(t)
	v, pkgs, err := protoPurityViolations(filepath.Join(root, "sdk"))
	if err != nil {
		t.Fatalf("scanning sdk imports: %v", err)
	}
	Discover(t, "sdk packages", 1, func() ([]string, error) {
		return pkgs, nil
	})
	for _, s := range v {
		t.Errorf("%s — SDK-0: the sdk is proto-free mechanism; move proto-aware code to the consumer or the contract", s)
	}
}

// TestGuard_ProtoPurity_Liveness: the fixture package imports one member of
// each banned family in a single import block; the clean OS-mechanism file
// must stay untouched.
func TestGuard_ProtoPurity_Liveness(t *testing.T) {
	scan := func(root string) ([]string, error) {
		v, _, err := protoPurityViolations(root)
		return v, err
	}
	RequireViolation(t, "proto purity", scan, "testdata/arch/imports/purity")
	v, err := scan("testdata/arch/imports/purity")
	if err != nil {
		t.Fatalf("scanning the purity fixture: %v", err)
	}
	requireFlagged(t, v, []string{
		"cap/proto_bad.go:5", // connectrpc.com/connect
		"cap/proto_bad.go:6", // generated contract package
		"cap/proto_bad.go:7", // protobuf runtime
	}, []string{"cap/clean.go"})
}

// TestProtoImportPrefixes_ThreatModel: one known import per banned family
// classified; look-alike innocents (the sdk itself under the shared repo
// prefix, plain stdlib and x/ imports) stay clean.
func TestProtoImportPrefixes_ThreatModel(t *testing.T) {
	classified := []string{
		"google.golang.org/protobuf/proto",
		"google.golang.org/genproto/googleapis/rpc/status",
		"google.golang.org/grpc",
		"connectrpc.com/connect",
		"buf.build/gen/go/acme/pm/protocolbuffers/go",
		"github.com/manchtools/power-manage/contract/gen/pm/v1",
	}
	for _, imp := range classified {
		if protoImportToken(imp) == "" {
			t.Errorf("banned family import %q not classified — the prefix set lost a family", imp)
		}
	}
	innocents := []string{
		"os/exec",
		"golang.org/x/sys/unix",
		"github.com/manchtools/power-manage/sdk/guardtest",
		"google.golang.org/api/option",
	}
	for _, imp := range innocents {
		if tok := protoImportToken(imp); tok != "" {
			t.Errorf("innocent import %q classified via %q — the scan overmatches", imp, tok)
		}
	}
	if len(protoImportPrefixes) == 0 {
		t.Fatal("protoImportPrefixes is empty — the threat model lost its subjects")
	}
}
