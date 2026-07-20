package guardtest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// sanctionedDrivers is the G-001-1 allowlist, keyed by module directory.
// server: pgx is the sole Postgres driver (B7; the dependency lands with
// SPEC-005). agent: modernc.org/sqlite is the pure-Go SQLite driver
// (CGO_ENABLED=0 build; lands with SPEC-013). Nothing is sanctioned for
// contract or sdk.
var sanctionedDrivers = map[string][]string{
	"server": {"github.com/jackc/pgx/v5"},
	"agent":  {"modernc.org/sqlite"},
}

// TestGuard_StorageDependencies is G-001-1 (SPEC-001 AC-1): no module may
// depend on a datastore/queue/cache/search client outside the sanctioned
// drivers — Postgres is the only server-side store, the agent's SQLite the
// only device-side one (§3.6). Floor ratchet: module discovery (4) today;
// rises to require the sanctioned drivers as SPEC-005/013 land them.
func TestGuard_StorageDependencies(t *testing.T) {
	root := RepoRoot(t)
	var mods map[string][]string
	Discover(t, "modules with go.mod", 4, func() ([]string, error) {
		m, err := ModuleRequires(root)
		if err != nil {
			return nil, err
		}
		mods = m
		dirs := make([]string, 0, len(m))
		for d := range m {
			dirs = append(dirs, d)
		}
		sort.Strings(dirs)
		return dirs, nil
	})
	for _, v := range storageDepViolations(mods, sanctionedDrivers) {
		t.Errorf("%s — a datastore/queue/cache/search client outside the sanctioned drivers (G-001-1, SPEC-001 AC-1, recorded decision §3.6); every such job has a Postgres or gateway-stream home", v)
	}
	subs, err := moduleSubstitutions(root)
	if err != nil {
		t.Fatalf("scanning for go.mod substitution directives: %v", err)
	}
	for _, v := range subs {
		t.Errorf("%s — G-001-1 classifies require paths only, so a substitution can smuggle a storage client past the deny-list; extend the classifier to resolve it before adding the directive", v)
	}
}

// TestGuard_StorageDependencies_Liveness: the fixture plants a redis require
// in block form and a replace directive; the comment-only kafka mention and
// the allowlisted pgx driver must stay clean.
func TestGuard_StorageDependencies_Liveness(t *testing.T) {
	fixtureAllow := map[string][]string{"pgmod": {"github.com/jackc/pgx/v5"}}
	scan := func(root string) ([]string, error) {
		mods, err := ModuleRequires(root)
		if err != nil {
			return nil, err
		}
		subs, err := moduleSubstitutions(root)
		if err != nil {
			return nil, err
		}
		return append(storageDepViolations(mods, fixtureAllow), subs...), nil
	}
	RequireViolation(t, "storage-dependency ban", scan, "testdata/arch/storagedeps")
	v, err := scan("testdata/arch/storagedeps")
	if err != nil {
		t.Fatalf("scanning the storagedeps fixture: %v", err)
	}
	wantParts := map[string][]string{
		"queuemod go-redis":       {"queuemod", "go-redis"},
		"replacemod substitution": {"replacemod", "replace"},
	}
	for name, parts := range wantParts {
		found := 0
		for _, viol := range v {
			if strings.Contains(viol, parts[0]) && strings.Contains(viol, parts[1]) {
				found++
			}
		}
		if found != 1 {
			t.Errorf("want exactly one %s violation, got %d in %v", name, found, v)
		}
	}
	if len(v) != len(wantParts) {
		t.Errorf("violation count = %d, want %d — cleanmod's comment-only kafka mention and pgmod's allowlisted driver must stay clean: %v", len(v), len(wantParts), v)
	}
}

// TestStorageClients_ThreatModel is the test-owned threat model for the
// deny-list: one known client per family must classify; innocents must not.
func TestStorageClients_ThreatModel(t *testing.T) {
	classified := []string{
		"github.com/jackc/pgx/v5",
		"github.com/lib/pq",
		"github.com/go-sql-driver/mysql",
		"modernc.org/sqlite",
		"github.com/mattn/go-sqlite3",
		"github.com/redis/go-redis/v9",
		"github.com/gomodule/redigo",
		"github.com/valkey-io/valkey-go",
		"github.com/segmentio/kafka-go",
		"github.com/IBM/sarama",
		"github.com/nats-io/nats.go",
		"github.com/rabbitmq/amqp091-go",
		"github.com/streadway/amqp",
		"github.com/elastic/go-elasticsearch/v8",
		"github.com/opensearch-project/opensearch-go",
		"github.com/bradfitz/gomemcache",
		"go.mongodb.org/mongo-driver",
		"go.etcd.io/etcd/client/v3",
		"go.etcd.io/bbolt",
		"github.com/dgraph-io/badger/v4",
		"github.com/syndtr/goleveldb",
		"github.com/dgraph-io/ristretto",
		"github.com/allegro/bigcache/v3",
		"github.com/gocql/gocql",
		"github.com/scylladb/scylla-go-driver",
		"github.com/apache/cassandra-gocql-driver",
		"github.com/couchbase/gocb/v2",
		"github.com/ClickHouse/clickhouse-go/v2",
		"cloud.google.com/go/spanner",
		"cloud.google.com/go/bigtable",
		"github.com/aws/aws-sdk-go-v2/service/dynamodb",
	}
	innocent := []string{
		"github.com/spf13/cobra",
		"google.golang.org/protobuf",
		"golang.org/x/mod",
		"github.com/manchtools/power-manage/contract",
	}
	for _, p := range classified {
		if len(StorageClients([]string{p})) != 1 {
			t.Errorf("%s was not classified as a storage/queue/cache/search client — the deny-list has a gap for its family", p)
		}
	}
	for _, p := range innocent {
		if v := StorageClients([]string{p}); len(v) != 0 {
			t.Errorf("innocent dependency %s was classified (%v) — the deny-list overmatches", p, v)
		}
	}
}

// TestModuleRequires_ParsesForms: single-line require, block require, and
// "// indirect" all parse; a comment-only require mention does not.
func TestModuleRequires_ParsesForms(t *testing.T) {
	mods, err := ModuleRequires("testdata/arch/storagedeps")
	if err != nil {
		t.Fatalf("parsing the storagedeps fixture: %v", err)
	}
	want := map[string][]string{
		"queuemod":   {"github.com/redis/go-redis/v9", "golang.org/x/mod"},
		"cleanmod":   {"github.com/spf13/cobra"},
		"pgmod":      {"github.com/jackc/pgx/v5"},
		"replacemod": {"github.com/spf13/cobra"},
	}
	if len(mods) != len(want) {
		t.Errorf("module count = %d (%v), want %d", len(mods), mods, len(want))
	}
	for dir, wantReqs := range want {
		got := append([]string(nil), mods[dir]...)
		sort.Strings(got)
		sort.Strings(wantReqs)
		if !slices.Equal(got, wantReqs) {
			t.Errorf("%s requires = %v, want %v — the go.mod parser missed a form or parsed a comment", dir, got, wantReqs)
		}
	}
}

// TestGuard_GatewayPurity is G-001-3 (SPEC-001 AC-3): the gateway binary's
// import closure must not reach event-store, secret-custody, or CA-key
// packages [TM-2]. Dormant (reported skip) until server/cmd/gateway exists.
//
// TM-2 scope: THIS test enforces only the custody/import half — the gateway
// binary cannot link event-store, secret-custody, or CA-key packages. The
// wire-schema half (stateless artifact relay, CRL as the only cached
// artifact — [WIRE-29], SPEC-003) is pinned separately by the contract
// frame-shape tests in contract/archtest (streams_test.go,
// artifactframes_test.go).
//
// Guards: TM-2.
func TestGuard_GatewayPurity(t *testing.T) {
	root := RepoRoot(t)
	const entry = "server/cmd/gateway"
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(entry))); errors.Is(err, fs.ErrNotExist) {
		t.Skipf("G-001-3 dormant: %s does not exist yet — the guard activates when the gateway binary lands (SPEC-012)", entry)
	}
	closure := Discover(t, "gateway binary import closure", 1, func() ([]string, error) {
		return ImportClosure(root, entry, "github.com/manchtools/power-manage/")
	})
	for _, v := range authorityViolations(closure, "server/") {
		t.Errorf("%s — the gateway holds no event store, secret custody, or CA keys [TM-2]; keep the dependency behind control", v)
	}
}

// TestGuard_GatewayPurity_Liveness keeps the scan honest while the real
// guard is dormant: the fixture's violation is transitive (cmd/gateway →
// relay → eventstore) and rides a blank import; the innocent frames package
// must stay clean.
func TestGuard_GatewayPurity_Liveness(t *testing.T) {
	scan := func(root string) ([]string, error) {
		closure, err := ImportClosure(root, "cmd/gateway", "example.com/gwpure/")
		if err != nil {
			return nil, err
		}
		return authorityViolations(closure, ""), nil
	}
	RequireViolation(t, "gateway purity", scan, "testdata/arch/gwpure")
	v, err := scan("testdata/arch/gwpure")
	if err != nil {
		t.Fatalf("scanning the gwpure fixture: %v", err)
	}
	if len(v) != 1 || !strings.Contains(v[0], "internal/eventstore") {
		t.Errorf("want exactly the transitive blank-import eventstore violation, got %v — internal/frames must stay clean", v)
	}
	closure, err := ImportClosure("testdata/arch/gwpure", "cmd/gateway", "example.com/gwpure/")
	if err != nil {
		t.Fatalf("scanning the gwpure fixture: %v", err)
	}
	if out := authorityViolations(closure, "server/"); len(out) != 0 {
		t.Errorf("out-of-scope packages were flagged (%v) — the scope prefix must confine the join", out)
	}
}

var boundaryRowRe = regexp.MustCompile(`(?m)^\| (B\d+) \|`)

// TestGuard_BoundaryRegistryParity: Boundaries and the normative §3.4 table
// are the same set, in both directions — a new listener needs a spec row
// first [ARCH-3], and an orphan registry entry means the table moved. The
// TestGuard_ prefix keeps it under the G-000-3 conformance sweep.
func TestGuard_BoundaryRegistryParity(t *testing.T) {
	root := RepoRoot(t)
	rows := Discover(t, "boundary rows in SPEC-001 §3.4", 11, func() ([]string, error) {
		src, err := os.ReadFile(filepath.Join(root, "docs", "content", "01-specs", "001-architecture-and-trust-model.md"))
		if err != nil {
			return nil, err
		}
		s := string(src)
		start := strings.Index(s, "### 3.4")
		end := strings.Index(s, "### 3.5")
		if start < 0 || end < 0 || end < start {
			return nil, fmt.Errorf("§3.4 section markers not found — the spec structure moved; fix the discovery")
		}
		var ids []string
		for _, m := range boundaryRowRe.FindAllStringSubmatch(s[start:end], -1) {
			ids = append(ids, m[1])
		}
		return ids, nil
	})
	seen := map[string]bool{}
	for _, id := range rows {
		seen[id] = true
		if _, ok := Boundaries[id]; !ok {
			t.Errorf("spec boundary %s has no entry in guardtest.Boundaries — extend the registry data with the new row", id)
		}
	}
	for id := range Boundaries {
		if !seen[id] {
			t.Errorf("guardtest.Boundaries has %s but SPEC-001 §3.4 does not — the table is normative; remove the entry or spec the boundary first", id)
		}
	}
}
