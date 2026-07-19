package config_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/config"
	"github.com/manchtools/power-manage/sdk/guardtest"
)

// demoConfig is the loader's representative two-section struct — G-002-5's
// scanned subject until real binaries land their own structs (SPEC-002 M3,
// per-binary adoption ratchets via TestGuard_ConfigAdoption).
type demoConfig struct {
	Server struct {
		ListenAddr string `doc:"Bind address for the demo listener."`
		MaxConns   int    `doc:"Upper bound on concurrent demo connections."`
		HTTPPort   int    `doc:"Demo HTTPS port."`
	}
	Log struct {
		Verbose bool   `doc:"Emit per-request demo logging."`
		Format  string `doc:"Demo log encoding."`
	}
}

// demoDefaults returns the demo struct pre-filled with the defaults the
// committed reference documents.
func demoDefaults() demoConfig {
	var c demoConfig
	c.Server.ListenAddr = "127.0.0.1:8080"
	c.Server.MaxConns = 42
	c.Server.HTTPPort = 8443
	c.Log.Format = "json"
	return c
}

const validFile = `# demo config
[server]
listen_addr = 127.0.0.1:8080
max_conns = 42
http_port = 8443

[log]
verbose = false
format = json
`

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "demo.conf")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("writing config fixture: %v", err)
	}
	return p
}

func TestLoad_ValidFile(t *testing.T) {
	var c demoConfig
	if err := config.Load(write(t, validFile), &c); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Server.ListenAddr != "127.0.0.1:8080" || c.Server.MaxConns != 42 || c.Server.HTTPPort != 8443 {
		t.Errorf("server section not populated: %+v", c.Server)
	}
	if c.Log.Verbose || c.Log.Format != "json" {
		t.Errorf("log section not populated: %+v", c.Log)
	}
}

func TestLoad_PartialFileKeepsDefaults(t *testing.T) {
	var c demoConfig
	c.Log.Format = "json" // defaults live in the struct; the file overrides only present keys
	if err := config.Load(write(t, "[server]\nlisten_addr = :1\n"), &c); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Server.ListenAddr != ":1" || c.Log.Format != "json" {
		t.Errorf("partial file must override only present keys: %+v", c)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	var c demoConfig
	err := config.Load(filepath.Join(t.TempDir(), "absent.conf"), &c)
	if err == nil || !strings.Contains(err.Error(), "absent.conf") {
		t.Fatalf("a missing config file must fail boot naming the path, got: %v", err)
	}
}

func TestLoad_FileRejections(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wants   []string
		bans    []string
	}{
		{"unknown key", "[server]\nbogus_knob = 1\n", []string{"unknown key", "server.bogus_knob"}, nil},
		{"unknown section", "[nope]\nx = 1\n", []string{"unknown section", "nope"}, nil},
		{"malformed line", "[server]\nlisten_addr = :1\nwhat is this\n", []string{"malformed", ":3:"}, nil},
		{"duplicate key", "[server]\nmax_conns = 1\nmax_conns = 2\n", []string{"duplicate key", "server.max_conns"}, nil},
		{"duplicate section", "[server]\nmax_conns = 1\n[log]\nformat = x\n[server]\nhttp_port = 1\n", []string{"duplicate section", "server"}, nil},
		{"key before section", "listen_addr = :1\n", []string{"before any", "listen_addr"}, nil},
		{"bad int value", "[server]\nmax_conns = many\n", []string{"server.max_conns", "not an integer"}, []string{"many"}},
		{"bad bool value", "[log]\nverbose = maybe\n", []string{"log.verbose", "not a bool"}, []string{"maybe"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c demoConfig
			err := config.Load(write(t, tc.content), &c)
			if err == nil {
				t.Fatalf("Load accepted %q — INV-18: unknown or malformed config fails boot", tc.content)
			}
			for _, w := range tc.wants {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not name %q", err, w)
				}
			}
			for _, b := range tc.bans {
				if strings.Contains(err.Error(), b) {
					t.Errorf("error %q echoes the config value %q — a fat-fingered secret would land in boot logs", err, b)
				}
			}
		})
	}
}

func TestLoad_EnvRejections(t *testing.T) {
	cases := []struct {
		name   string
		envVar string
		val    string
		wants  []string
		bans   []string
	}{
		{"unknown PM_ variable", "PM_BOGUS_KNOB", "x", []string{"PM_BOGUS_KNOB", "unrecognized"}, nil},
		{"near-miss name", "PM_SERVER_LISTENADDR", ":1", []string{"PM_SERVER_LISTENADDR", "unrecognized"}, nil},
		{"bare PM_", "PM_", "x", []string{"unrecognized"}, nil},
		{"bad int value", "PM_SERVER_MAX_CONNS", "many", []string{"PM_SERVER_MAX_CONNS", "not an integer"}, []string{"many"}},
		{"bad bool value", "PM_LOG_VERBOSE", "maybe", []string{"PM_LOG_VERBOSE", "not a bool"}, []string{"maybe"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.envVar, tc.val)
			var c demoConfig
			err := config.Load(write(t, validFile), &c)
			if err == nil {
				t.Fatal("Load accepted a stray environment override — INV-18: unrecognized PM_* fails boot")
			}
			for _, w := range tc.wants {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not name %q", err, w)
				}
			}
			for _, b := range tc.bans {
				if strings.Contains(err.Error(), b) {
					t.Errorf("error %q echoes the environment value %q — a fat-fingered secret would land in boot logs", err, b)
				}
			}
		})
	}
}

func TestLoad_ForeignEnvIgnored(t *testing.T) {
	t.Setenv("PMX_NOT_OURS", "x")
	t.Setenv("NOT_PM_SERVER", "x")
	var c demoConfig
	if err := config.Load(write(t, validFile), &c); err != nil {
		t.Fatalf("non-PM_ environment must be ignored: %v", err)
	}
}

// TestGuard_ConfigRoundTrip is G-002-5 (SPEC-002 AC-4, [INV-18]): the
// override set is DERIVED from the struct and the loader accepts exactly
// that set — every derived name is proven to override its field, the
// round-trip table and the derived set match in both directions, and
// TestLoad_EnvRejections proves names outside the set abort boot.
func TestGuard_ConfigRoundTrip(t *testing.T) {
	derived := guardtest.Discover(t, "derived PM_* override names", 1, func() ([]string, error) {
		return config.EnvVars(&demoConfig{})
	})
	overrides := map[string]struct {
		val   string
		check func(c *demoConfig) bool
	}{
		"PM_SERVER_LISTEN_ADDR": {"[::1]:9999", func(c *demoConfig) bool { return c.Server.ListenAddr == "[::1]:9999" }},
		"PM_SERVER_MAX_CONNS":   {"7", func(c *demoConfig) bool { return c.Server.MaxConns == 7 }},
		"PM_SERVER_HTTP_PORT":   {"8081", func(c *demoConfig) bool { return c.Server.HTTPPort == 8081 }},
		"PM_LOG_VERBOSE":        {"true", func(c *demoConfig) bool { return c.Log.Verbose }},
		"PM_LOG_FORMAT":         {"text", func(c *demoConfig) bool { return c.Log.Format == "text" }},
	}
	for _, name := range derived {
		if _, ok := overrides[name]; !ok {
			t.Errorf("derived name %s has no round-trip row — extend the table; derivation and acceptance stay an exact set", name)
		}
	}
	for name := range overrides {
		if !slices.Contains(derived, name) {
			t.Errorf("expected override %s not derived — the mechanical derivation lost a field", name)
		}
	}
	for name, o := range overrides {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, o.val)
			var c demoConfig
			if err := config.Load(write(t, validFile), &c); err != nil {
				t.Fatalf("Load with %s set: %v", name, err)
			}
			if !o.check(&c) {
				t.Errorf("override %s=%q not applied over the file value", name, o.val)
			}
		})
	}
}

// TestDoc_GoldenMatch is AC-6's staleness mechanism: the committed
// reference is byte-diffed against a fresh render, so drift goes red.
// Defaults rendering is covered by the pre-filled values; the deliberately
// stale fixture proves the diff can go red at all.
func TestDoc_GoldenMatch(t *testing.T) {
	c := demoDefaults()
	got, err := config.Doc(&c)
	if err != nil {
		t.Fatalf("Doc: %v", err)
	}
	want, err := os.ReadFile("testdata/demo.md")
	if err != nil {
		t.Fatalf("reading the committed reference: %v", err)
	}
	if got != string(want) {
		t.Errorf("committed reference is stale — regenerate testdata/demo.md from demoConfig\ngot:\n%s\nwant:\n%s", got, want)
	}
	stale, err := os.ReadFile("testdata/demo_stale.md")
	if err != nil {
		t.Fatalf("reading the stale fixture: %v", err)
	}
	if got == string(stale) {
		t.Error("render matches the deliberately stale fixture — the freshness diff can no longer go red")
	}
}

func TestDoc_MissingTagFails(t *testing.T) {
	var c struct {
		S struct {
			Documented int `doc:"has one"`
			Bare       int
		}
	}
	if _, err := config.Doc(&c); err == nil || !strings.Contains(err.Error(), "S.Bare") || !strings.Contains(err.Error(), "doc tag") {
		t.Fatalf("an undocumented knob must fail the generator naming the key, got: %v", err)
	}
}

// TestGuard_ConfigDocs is G-002-6 (SPEC-002 AC-6, [INV-18]): the reference
// renders from the struct itself (TestDoc_GoldenMatch is the staleness
// diff), the render never loses a derived knob, and every knob has a read
// site — an unread knob is dead configuration.
func TestGuard_ConfigDocs(t *testing.T) {
	c := demoDefaults()
	rendered, err := config.Doc(&c)
	if err != nil {
		t.Fatalf("Doc: %v", err)
	}
	rows := guardtest.Discover(t, "documented demo knobs", 1, func() ([]string, error) {
		var rows []string
		for _, line := range strings.Split(rendered, "\n") {
			if strings.HasPrefix(line, "| `") {
				rows = append(rows, line)
			}
		}
		return rows, nil
	})
	names, err := config.EnvVars(&demoConfig{})
	if err != nil {
		t.Fatalf("EnvVars: %v", err)
	}
	if len(rows) != len(names) {
		t.Errorf("rendered %d knob rows, derivation has %d keys — the generator lost a knob", len(rows), len(names))
	}
	v, err := guardtest.ConfigReadViolations(filepath.Join(guardtest.RepoRoot(t), "sdk"), "demoConfig")
	if err != nil {
		t.Fatalf("scanning read sites: %v", err)
	}
	for _, s := range v {
		t.Errorf("%s", s)
	}
}

func TestEnvVars_FailClosed(t *testing.T) {
	t.Run("exact derived set", func(t *testing.T) {
		got, err := config.EnvVars(&demoConfig{})
		if err != nil {
			t.Fatalf("EnvVars: %v", err)
		}
		want := []string{"PM_LOG_FORMAT", "PM_LOG_VERBOSE", "PM_SERVER_HTTP_PORT", "PM_SERVER_LISTEN_ADDR", "PM_SERVER_MAX_CONNS"}
		if !slices.Equal(got, want) {
			t.Errorf("derived set %v, want %v", got, want)
		}
	})
	cases := []struct {
		name  string
		cfg   any
		wants []string
	}{
		{"not a pointer", demoConfig{}, []string{"pointer"}},
		{"non-struct section", &struct{ Port int }{}, []string{"section struct", "Port"}},
		{"unexported section", &struct{ server struct{ A string } }{}, []string{"unexported", "server"}},
		{"unexported key", &struct{ S struct{ a string } }{}, []string{"unexported", "S.a"}},
		{"unsupported kind", &struct{ S struct{ F float64 } }{}, []string{"unsupported", "F"}},
		{"derived-name collision", &struct {
			S struct {
				HTTPPort  int
				Http_Port int
			}
		}{}, []string{"collide"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := config.EnvVars(tc.cfg); err == nil {
				t.Fatal("EnvVars accepted an underivable struct — derivation fails closed")
			} else {
				for _, w := range tc.wants {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("error %q does not name %q", err, w)
					}
				}
			}
		})
	}
}
