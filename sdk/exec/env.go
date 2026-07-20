package exec

import (
	"errors"
	"fmt"
	"strings"

	"github.com/manchtools/power-manage/sdk/redos"
)

// ErrInvalidEnvVar is returned when an env entry in Command.Env is not in the
// canonical KEY=VALUE form. Surfaced as a programmer error so the bad value
// isn't silently dropped before the child runs.
var ErrInvalidEnvVar = errors.New("invalid env entry")

// ErrBlockedEnvVar is returned when an env entry's KEY is on the
// hijack-blocklist (LD_PRELOAD, PATH override, BASH_ENV, GCONV_PATH,
// etc.). Catches CVE-class injections at the SDK boundary so every
// Command.Env passed to the Runner inherits the check in one place.
var ErrBlockedEnvVar = errors.New("env var blocked by hijack-prevention allowlist")

// ErrReservedEnvVar is returned when an env entry tries to set a variable the
// Runner forces for deterministic output (the locale family + NO_COLOR). The SDK
// parses standardized tool output, so a consumer must not be able to change the
// locale/color of a command — these are imposed by the Runner, not negotiable
// ([SDK-3]).
var ErrReservedEnvVar = errors.New("env var reserved by the SDK for deterministic output")

// isReservedEnvVar reports whether name is one the Runner forces and a caller
// therefore may not set via Command.Env: the whole LC_* family, LANG, LANGUAGE
// (all neutralised by the forced LC_ALL=C), and NO_COLOR. Case-insensitive.
func isReservedEnvVar(name string) bool {
	upper := strings.ToUpper(name)
	switch upper {
	case "LANG", "LANGUAGE", "NO_COLOR":
		return true
	}
	return strings.HasPrefix(upper, "LC_")
}

// validEnvVarName matches safe environment variable names (letters, digits,
// underscore). Routed through the redos chokepoint like every SDK regex
// ([SDK-6]). Unexported — like blockedEnvVars, the policy must be immutable
// from outside; IsAllowedEnvVar is the query API.
var validEnvVarName = redos.MustVet(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// blockedEnvVars are environment variable names that must never be overridden
// because they can hijack process execution (library injection, path manipulation).
//
// The whole LD_*, BASH_FUNC_*, and DYLD_* families are blocked unconditionally by
// the prefix check in IsAllowedEnvVar, so individual LD_* keys (LD_PRELOAD,
// LD_LIBRARY_PATH, LD_AUDIT, LD_DEBUG, LD_PROFILE) and the BASH_FUNC_ prefix are
// not enumerated here — listing them would only duplicate the prefix rule. This
// map carries the names that have no covering prefix. Unexported so no importer
// can mutate the policy; IsAllowedEnvVar is the only way to query it.
var blockedEnvVars = map[string]bool{
	// glibc iconv module loading (the pkexec CVE-2021-4034 injection vector)
	"GCONV_PATH": true,
	// DNS/resolver manipulation
	"HOSTALIASES":      true,
	"RESOLV_HOST_CONF": true,
	// System utility redirection
	"GETCONF_DIR": true,
	// Interpreter library/startup injection
	"NODE_OPTIONS":  true,
	"PYTHONPATH":    true,
	"PYTHONHOME":    true,
	"PYTHONSTARTUP": true,
	"PERL5OPT":      true,
	"PERL5LIB":      true,
	"RUBYLIB":       true,
	"RUBYOPT":       true,
	// Shell/path manipulation
	"PATH":       true,
	"IFS":        true,
	"ENV":        true,
	"BASH_ENV":   true,
	"CDPATH":     true,
	"GLOBIGNORE": true,
}

// IsAllowedEnvVar returns true if the environment variable name is safe to set.
func IsAllowedEnvVar(name string) bool {
	if !validEnvVarName.MatchString(name) {
		return false
	}
	upper := strings.ToUpper(name)
	if blockedEnvVars[upper] {
		return false
	}
	// Block LD_*, BASH_FUNC_*, and DYLD_* (macOS) prefixes
	if strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "BASH_FUNC_") || strings.HasPrefix(upper, "DYLD_") {
		return false
	}
	return true
}

// validateEnvVars enforces the SDK env boundary: every entry must be
// KEY=VALUE and the key must not be on the blockedEnvVars list (PATH,
// LD_PRELOAD, BASH_ENV, GCONV_PATH, LD_LIBRARY_PATH, …). This is the one
// place the hijack check lives; the Runner runs it (via buildChildEnv)
// before composing the child env.
func validateEnvVars(envVars []string) error {
	for _, e := range envVars {
		key, _, ok := strings.Cut(e, "=")
		if !ok {
			// The entry is NOT echoed: a malformed entry may itself be a secret
			// (a value pasted where KEY=VALUE belonged), and this error reaches
			// logs.
			return fmt.Errorf("%w: env entry must be KEY=VALUE", ErrInvalidEnvVar)
		}
		if !IsAllowedEnvVar(key) {
			return fmt.Errorf("%w: refusing to forward env var %q to child (hijack-prone names like LD_PRELOAD, PATH, BASH_ENV are refused at this boundary)", ErrBlockedEnvVar, key)
		}
	}
	return nil
}

// ValidateCommandEnv checks a Command.Env slice with the EXACT rules the real
// Runner enforces before it spawns any child: each entry must be KEY=VALUE
// (ErrInvalidEnvVar), the key must not be a hijack-prone name on the blocklist
// (ErrBlockedEnvVar — PATH/LD_PRELOAD/BASH_ENV/…), and the key must not be a
// name the Runner reserves for deterministic output (ErrReservedEnvVar —
// LC_*/LANG/LANGUAGE/NO_COLOR). It is exported so exectest.FakeRunner can
// apply the identical gate, keeping the unit tier faithful to the real env
// boundary — an adversarial Command.Env is rejected the same way against a
// fake as against a real Runner.
func ValidateCommandEnv(env []string) error {
	if err := validateEnvVars(env); err != nil {
		return err
	}
	for _, e := range env {
		if key, _, _ := strings.Cut(e, "="); isReservedEnvVar(key) {
			return fmt.Errorf("%w: %q is forced by the Runner (LC_ALL=C/LANG=C/NO_COLOR=1) and may not be set via Command.Env", ErrReservedEnvVar, key)
		}
	}
	return nil
}
