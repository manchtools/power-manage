package guardtest

// SPEC-001 M1: the machine-readable trust-boundary registry (§3.4), the
// storage-dependency classifier (G-001-1), and the import-closure walk
// (G-001-3). Discovery is file-level ground truth — go.mod files and import
// declarations — never hand-maintained lists of modules or packages.

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Boundaries is the machine-readable form of the SPEC-001 §3.4 trust-boundary
// inventory. TestBoundaryRegistry_MatchesSpec keeps it in exact-set parity
// with the normative table; G-001-2 (M2) joins listener registrations
// against it.
var Boundaries = map[string]string{
	"B1":  "Browser/CLI → Control (HTTPS + JWT ES256)",
	"B2":  "SSO callback (PKCE S256 + state + nonce, one-shot)",
	"B3":  "SCIM (per-provider bearer, bcrypt, anti-oracle)",
	"B4":  "Agent → Gateway (mTLS, SPIFFE class, CRL fail-closed)",
	"B5":  "Enrollment local socket (registration token is sole authorization)",
	"B6":  "Gateway ↔ Control (mTLS, gateway-class certs only)",
	"B7":  "Control → Postgres (mTLS verify-full, sqlc only, enc:v1 at rest)",
	"B8":  "Control → Agent commands (CA signature over exact bytes, freshness)",
	"B9":  "Agent → Control results (device-key signature)",
	"B10": "Agent/Gateway → PkiService (per-operation token / proof-of-possession)",
	"B11": "Browser → Gateway terminal WS (header token + CA-signed grant)",
}

// ModuleRequires returns, per depth-1 module directory under root (the
// verify.sh module shape), the module paths its go.mod requires. The parser
// handles gofmt-formatted go.mod only — single-line and block require
// directives, comments stripped.
// ponytail: replace directives are not classified — a replace swapping an
// innocent path for a storage client evades G-001-1; parse them if a replace
// ever appears in this repo.
func ModuleRequires(root string) (map[string][]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("reading module root %s: %w", root, err)
	}
	mods := map[string][]string{}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(root, e.Name(), "go.mod"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reading %s/go.mod: %w", e.Name(), err)
		}
		mods[e.Name()] = parseRequires(string(src))
	}
	return mods, nil
}

func parseRequires(src string) []string {
	var out []string
	inBlock := false
	for _, line := range strings.Split(src, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "require (":
			inBlock = true
		case inBlock && line == ")":
			inBlock = false
		case inBlock:
			if f := strings.Fields(line); len(f) >= 2 {
				out = append(out, f[0])
			}
		case strings.HasPrefix(line, "require "):
			if f := strings.Fields(line); len(f) >= 3 {
				out = append(out, f[1])
			}
		}
	}
	return out
}

// storageClientTokens mark datastore/queue/cache/search client libraries by
// path-segment identity (segments split further on "." and "-", so
// "go-redis", "nats.go", and "go.etcd.io" all resolve). The deny-list can
// never be complete — TestStorageClients_ThreatModel owns one known client
// per family, and a new family means a new token WITH a threat-model entry.
var storageClientTokens = map[string]bool{
	"pgx": true, "pq": true, "mysql": true, "sqlite": true, "sqlite3": true,
	"redis": true, "redigo": true, "valkey": true,
	"kafka": true, "sarama": true, "nats": true,
	"amqp": true, "amqp091": true, "rabbitmq": true,
	"elasticsearch": true, "opensearch": true,
	"memcache": true, "gomemcache": true,
	"mongo": true, "etcd": true,
	"bbolt": true, "badger": true, "goleveldb": true, "leveldb": true,
	"ristretto": true, "bigcache": true, "groupcache": true,
	// Native-client datastores with no database/sql driver to fall back on —
	// the token here is their only line of defense.
	"gocql": true, "gocb": true, "couchbase": true, "clickhouse": true,
	"scylla": true, "cassandra": true, "spanner": true, "bigtable": true,
	"dynamodb": true,
}

// StorageClients returns the subset of requires classified as
// datastore/queue/cache/search client libraries (G-001-1, SPEC-001 AC-1).
func StorageClients(requires []string) []string {
	var out []string
	for _, path := range requires {
		if storageClientToken(path) != "" {
			out = append(out, path)
		}
	}
	return out
}

func storageClientToken(modulePath string) string {
	for _, seg := range strings.Split(modulePath, "/") {
		for _, sub := range strings.FieldsFunc(seg, func(r rune) bool { return r == '.' || r == '-' }) {
			if storageClientTokens[sub] {
				return sub
			}
		}
	}
	return ""
}

// moduleSubstitutions is the fail-closed tripwire for the classifier's
// substitution blindness: G-001-1 classifies require paths only, so a
// replace/exclude directive could swap an innocent path for a storage
// client. The repo has none today; the day one appears, this fires and
// forces the classifier to learn substitutions instead of silently passing.
func moduleSubstitutions(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("reading module root %s: %w", root, err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(root, e.Name(), "go.mod"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reading %s/go.mod: %w", e.Name(), err)
		}
		for _, line := range strings.Split(string(src), "\n") {
			if i := strings.Index(line, "//"); i >= 0 {
				line = line[:i]
			}
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "replace ") || line == "replace (" ||
				strings.HasPrefix(line, "exclude ") || line == "exclude (" {
				out = append(out, fmt.Sprintf("%s: go.mod carries a replace/exclude directive", e.Name()))
				break
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// storageDepViolations joins each module's classified clients against its
// allowlist; anything not sanctioned for that exact module is a violation.
func storageDepViolations(mods, allow map[string][]string) []string {
	var out []string
	for dir, reqs := range mods {
		allowed := map[string]bool{}
		for _, a := range allow[dir] {
			allowed[a] = true
		}
		for _, c := range StorageClients(reqs) {
			if !allowed[c] {
				out = append(out, fmt.Sprintf("%s: banned storage/queue/cache/search client %s", dir, c))
			}
		}
	}
	sort.Strings(out)
	return out
}

// ImportClosure returns every in-repo package directory (slash-relative to
// root) transitively imported from the entry package directory. Non-test
// files only — the closure models the linked binary. Blank and dot imports
// count: linkage is linkage.
func ImportClosure(root, entry, modPrefix string) ([]string, error) {
	fset := token.NewFileSet()
	seen := map[string]bool{}
	queue := []string{entry}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		files, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil {
			return nil, fmt.Errorf("reading package dir %s: %w", dir, err)
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".go") || strings.HasSuffix(f.Name(), "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, filepath.Join(root, filepath.FromSlash(dir), f.Name()), nil, parser.ImportsOnly)
			if err != nil {
				return nil, fmt.Errorf("parse %s/%s: %w", dir, f.Name(), err)
			}
			for _, imp := range file.Imports {
				p, uerr := strconv.Unquote(imp.Path.Value)
				if uerr != nil || !strings.HasPrefix(p, modPrefix) {
					continue
				}
				rel := strings.TrimPrefix(p, modPrefix)
				if !seen[rel] {
					seen[rel] = true
					queue = append(queue, rel)
				}
			}
		}
	}
	closure := make([]string, 0, len(seen))
	for pkg := range seen {
		closure = append(closure, pkg)
	}
	sort.Strings(closure)
	return closure, nil
}

// authorityTokens mark, by path segment, the packages holding authority the
// gateway must never link [TM-2]: the event store, secret custody, and CA
// keys. Segment names ratchet as SPEC-002/005/006 fix the server layout —
// and the CA-key-custody token must then be chosen to EXCLUDE the PKI
// client path: the gateway is a sanctioned PkiService client (B10, cert
// renewal), so a blanket "pki" match would false-positive on activation.
var authorityTokens = map[string]bool{"eventstore": true, "secrets": true, "ca": true, "pki": true}

// authorityViolations returns the closure entries under scope that reach an
// authority package (G-001-3, SPEC-001 AC-3).
func authorityViolations(closure []string, scope string) []string {
	var out []string
	for _, pkg := range closure {
		if !strings.HasPrefix(pkg, scope) {
			continue
		}
		for _, seg := range strings.Split(pkg, "/") {
			if authorityTokens[seg] {
				out = append(out, fmt.Sprintf("%s: gateway import closure reaches an authority package (segment %q)", pkg, seg))
				break
			}
		}
	}
	return out
}
