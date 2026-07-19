package guardtest

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestGuard_SecretIndirection is G-002-7 (SPEC-002 AC-7, [INV-18]): a
// secret is never an inline config VALUE or an argv flag — config-struct
// fields matching the secret pattern set must be path-typed (…File/…Path),
// and no literal-named string flag takes a secret value. Subjects are
// every *Config struct across the workspace (test files included — the
// loader's own demo struct is a real subject today) and every
// literal-named string flag; the pattern set is a test-owned threat model.
func TestGuard_SecretIndirection(t *testing.T) {
	root := RepoRoot(t)
	mods := Discover(t, "workspace modules from go.work", 4, func() ([]string, error) {
		return workspaceModules(root)
	})
	var violations, subjects []string
	for _, mod := range mods {
		v, subj, err := secretIndirectionViolations(filepath.Join(root, mod))
		if err != nil {
			t.Fatalf("scanning %s for inline secrets: %v", mod, err)
		}
		for _, s := range v {
			violations = append(violations, mod+"/"+s)
		}
		for _, s := range subj {
			subjects = append(subjects, mod+"/"+s)
		}
	}
	Discover(t, "config structs and flag registrations", 1, func() ([]string, error) {
		return subjects, nil
	})
	for _, s := range violations {
		t.Errorf("%s — AC-7: secrets travel as file paths (or stdin, AG-17), never as inline values or argv", s)
	}
}

// TestGuard_SecretIndirection_Liveness: the fixture plants an inline
// secret field, a secret in a named same-package section struct, and two
// secret-named flags; the path-typed forms, the -file flags, a non-Config
// type (naming-convention ceiling, recorded), and qualified-key
// look-alikes stay clean.
func TestGuard_SecretIndirection_Liveness(t *testing.T) {
	scan := func(root string) ([]string, error) {
		v, _, err := secretIndirectionViolations(root)
		return v, err
	}
	RequireViolation(t, "secret indirection", scan, "testdata/arch/secrets")
	v, err := scan("testdata/arch/secrets")
	if err != nil {
		t.Fatalf("scanning the secrets fixture: %v", err)
	}
	requireFlagged(t, v, []string{
		"cfg.go:7",    // appConfig.Auth.Token — inline secret value
		"cfg.go:14",   // dbSection.Password via a named same-package section
		"flags.go:8",  // flag.String("auth-token")
		"flags.go:13", // flag.StringVar(..., "client-secret")
	}, []string{"cfg.go:8", "cfg.go:15", "flags.go:9", "flags.go:14", "innocent.go"})
}

// TestGuard_SecretIndirection_SiblingSections: two sibling fields of one
// section type must BOTH be walked — the recursion's cycle guard is
// path-scoped, and a visited-set that never unwinds silently skips the
// second sibling's subtree.
func TestGuard_SecretIndirection_SiblingSections(t *testing.T) {
	scan := func(root string) ([]string, error) {
		v, _, err := secretIndirectionViolations(root)
		return v, err
	}
	RequireViolation(t, "secret sibling sections", scan, "testdata/arch/secrets_siblings")
	v, err := scan("testdata/arch/secrets_siblings")
	if err != nil {
		t.Fatalf("scanning the sibling fixture: %v", err)
	}
	for _, want := range []string{"replicaConfig.ReadDB.Passphrase", "replicaConfig.WriteDB.Passphrase"} {
		n := 0
		for _, s := range v {
			if strings.Contains(s, want) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("field %s reported %d time(s), want exactly 1 — a sibling sharing the section type must not be skipped (violations: %v)", want, n, v)
		}
	}
	if len(v) != 2 {
		t.Errorf("violation count = %d, want 2: %v", len(v), v)
	}
}

// TestSecretPatterns_ThreatModel: the pattern set is the threat model — a
// new secret family means a new pattern WITH a row here; path-indirected
// forms and qualified-key look-alikes stay clean.
func TestSecretPatterns_ThreatModel(t *testing.T) {
	secrets := []string{
		"Token", "AuthToken", "Secret", "ClientSecret", "Password", "Passwd",
		"Passphrase", "Credentials", "APIKey", "PrivateKey", "SigningKey",
		"MasterKey", "EncryptionKey", "TLSKey", "HostKey", "SSHKey",
		"auth-token", "client_secret",
	}
	for _, n := range secrets {
		if !secretValueName(n) {
			t.Errorf("secret-family name %q not classified — the pattern set lost a family", n)
		}
	}
	sanctioned := []string{"TokenFile", "PrivateKeyPath", "auth-token-file", "password_file", "tls-key-path"}
	for _, n := range sanctioned {
		if secretValueName(n) {
			t.Errorf("path-indirected name %q classified — indirection is the sanctioned form", n)
		}
	}
	innocents := []string{"ListenAddr", "SortKey", "KeyPrefix", "Keyboard", "MonKey", "Format", "MaxConns"}
	for _, n := range innocents {
		if secretValueName(n) {
			t.Errorf("innocent name %q classified — the pattern set overmatches", n)
		}
	}
}
