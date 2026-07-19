// Package config is the shared INV-18 config loader (SPEC-002 [CFG-1]):
// each binary boots from ONE file into ONE typed struct, override names
// are derived mechanically as PM_<SECTION>_<KEY>, and anything unknown —
// file key, section, or PM_* variable — fails boot by name. The model is
// two levels deep by construction: top-level fields are section structs,
// section fields are scalar keys. The file form is the strict INI subset
// of exactly that model: `[section]`, `key = value`, `#` comments.
package config

import (
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// field locates one derived key inside the config struct.
type field struct {
	section, key int
	kind         reflect.Kind
}

// Load reads the binary's one config file at path into cfg (a pointer to
// its section-struct config) and then applies derived PM_* environment
// overrides; env wins over file, unknown anything is an error.
func Load(path string, cfg any) error {
	byEnv, byFile, sections, err := derive(cfg)
	if err != nil {
		return err
	}
	v := reflect.ValueOf(cfg)
	if err := applyFile(path, v, byFile, sections); err != nil {
		return err
	}
	return applyEnv(v, byEnv)
}

// EnvVars returns the mechanically derived PM_<SECTION>_<KEY> override
// names for cfg's type, sorted — the round-trip guard's and the M4 docs
// generator's source of truth.
func EnvVars(cfg any) ([]string, error) {
	byEnv, _, _, err := derive(cfg)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(byEnv))
	for n := range byEnv {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// Doc renders the reference documentation for cfg's type from the struct
// itself (INV-18.4): one markdown table per section with the derived file
// key, env override, kind, the passed struct's value as the default, and
// the mandatory `doc` tag. An undocumented knob fails by name.
func Doc(cfg any) (string, error) {
	if _, _, _, err := derive(cfg); err != nil {
		return "", err
	}
	v := reflect.ValueOf(cfg).Elem()
	t := v.Type()
	var b strings.Builder
	b.WriteString("One file per binary; every key can be overridden with its derived\nenvironment variable. Unknown keys and unknown `PM_*` variables fail\nboot [INV-18].\n")
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		sec := snake(sf.Name)
		fmt.Fprintf(&b, "\n## [%s]\n\n| key | env override | type | default | description |\n|---|---|---|---|---|\n", sec)
		for j := 0; j < sf.Type.NumField(); j++ {
			kf := sf.Type.Field(j)
			doc := strings.TrimSpace(kf.Tag.Get("doc"))
			if doc == "" {
				return "", fmt.Errorf("key %s.%s has no doc tag — an undocumented knob cannot ship; state what it does and why it exists [INV-18]", sf.Name, kf.Name)
			}
			key := snake(kf.Name)
			fmt.Fprintf(&b, "| `%s` | `PM_%s_%s` | %s | `%v` | %s |\n",
				key, strings.ToUpper(sec), strings.ToUpper(key), kf.Type.Kind(), v.Field(i).Field(j).Interface(), doc)
		}
	}
	return b.String(), nil
}

// derive walks cfg's two-level struct and fails closed on anything the
// model cannot express: non-struct or unexported top-level fields,
// unexported or unsupported-kind keys, and name collisions after
// snake-casing — two fields deriving the same PM_* name would make an
// override ambiguous.
func derive(cfg any) (byEnv, byFile map[string]field, sections map[string]bool, err error) {
	v := reflect.ValueOf(cfg)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return nil, nil, nil, fmt.Errorf("config target must be a pointer to a struct, got %T", cfg)
	}
	t := v.Elem().Type()
	byEnv, byFile, sections = map[string]field{}, map[string]field{}, map[string]bool{}
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if !sf.IsExported() {
			return nil, nil, nil, fmt.Errorf("unexported section field %s — the struct is the config's single source of truth [INV-18]", sf.Name)
		}
		if sf.Type.Kind() != reflect.Struct {
			return nil, nil, nil, fmt.Errorf("top-level field %s is not a section struct — the model is [section] key = value", sf.Name)
		}
		sec := snake(sf.Name)
		if sections[sec] {
			return nil, nil, nil, fmt.Errorf("derived section names collide at [%s] — rename one of the fields", sec)
		}
		sections[sec] = true
		for j := 0; j < sf.Type.NumField(); j++ {
			kf := sf.Type.Field(j)
			if !kf.IsExported() {
				return nil, nil, nil, fmt.Errorf("unexported key field %s.%s [INV-18]", sf.Name, kf.Name)
			}
			switch kf.Type.Kind() {
			case reflect.String, reflect.Int, reflect.Bool:
			default:
				return nil, nil, nil, fmt.Errorf("unsupported kind %s for key %s.%s — string, int, and bool today; a new kind lands with its first knob's rationale [INV-18]", kf.Type.Kind(), sf.Name, kf.Name)
			}
			key := snake(kf.Name)
			env := "PM_" + strings.ToUpper(sec) + "_" + strings.ToUpper(key)
			if _, dup := byEnv[env]; dup {
				return nil, nil, nil, fmt.Errorf("derived names collide at %s — rename one of the fields", env)
			}
			f := field{i, j, kf.Type.Kind()}
			byEnv[env] = f
			byFile[sec+"."+key] = f
		}
	}
	return byEnv, byFile, sections, nil
}

// snake maps CamelCase to snake_case with acronym runs intact:
// ListenAddr → listen_addr, HTTPPort → http_port. An existing underscore
// never doubles, so Http_Port collides with HTTPPort by construction —
// derive reports it.
func snake(name string) string {
	rs := []rune(name)
	var out []rune
	for i, r := range rs {
		if unicode.IsUpper(r) {
			prevUpper := i > 0 && unicode.IsUpper(rs[i-1])
			nextLower := i+1 < len(rs) && unicode.IsLower(rs[i+1])
			if i > 0 && rs[i-1] != '_' && (!prevUpper || nextLower) {
				out = append(out, '_')
			}
			r = unicode.ToLower(r)
		}
		out = append(out, r)
	}
	return string(out)
}

// applyFile parses the strict INI subset — blank lines, # comments,
// [section] headers, key = value — and rejects anything else, unknown,
// or duplicate by name [INV-18].
func applyFile(path string, v reflect.Value, byFile map[string]field, sections map[string]bool) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading the config file: %w", err)
	}
	section := ""
	seenKey, seenSec := map[string]bool{}, map[string]bool{}
	for i, line := range strings.Split(string(src), "\n") {
		ln, s := i+1, strings.TrimSpace(line)
		switch {
		case s == "" || strings.HasPrefix(s, "#"):
		case strings.HasPrefix(s, "["):
			if !strings.HasSuffix(s, "]") {
				return fmt.Errorf("%s:%d: malformed section header %q", path, ln, s)
			}
			name := strings.TrimSpace(s[1 : len(s)-1])
			if !sections[name] {
				return fmt.Errorf("%s:%d: unknown section [%s] — INV-18: unknown keys fail boot", path, ln, name)
			}
			if seenSec[name] {
				return fmt.Errorf("%s:%d: duplicate section [%s]", path, ln, name)
			}
			seenSec[name] = true
			section = name
		default:
			k, val, found := strings.Cut(s, "=")
			key := strings.TrimSpace(k)
			if !found || key == "" {
				return fmt.Errorf("%s:%d: malformed line %q — expected [section], key = value, or a # comment", path, ln, s)
			}
			if section == "" {
				return fmt.Errorf("%s:%d: key %q before any [section]", path, ln, key)
			}
			fk := section + "." + key
			f, known := byFile[fk]
			if !known {
				return fmt.Errorf("%s:%d: unknown key %s — INV-18: unknown keys fail boot", path, ln, fk)
			}
			if seenKey[fk] {
				return fmt.Errorf("%s:%d: duplicate key %s", path, ln, fk)
			}
			seenKey[fk] = true
			if err := setField(v, f, strings.TrimSpace(val), fmt.Sprintf("%s:%d: key %s", path, ln, fk)); err != nil {
				return err
			}
		}
	}
	return nil
}

// applyEnv is the repository's single sanctioned environment read
// (G-002-4): one pass over os.Environ, derived PM_* names applied over
// the file, anything else PM_-prefixed fails boot naming the variable.
func applyEnv(v reflect.Value, byEnv map[string]field) error {
	for _, kv := range os.Environ() {
		name, val, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, "PM_") {
			continue
		}
		f, known := byEnv[name]
		if !known {
			return fmt.Errorf("unrecognized environment variable %s — override names derive from the config struct as PM_<SECTION>_<KEY> [INV-18]", name)
		}
		if err := setField(v, f, val, fmt.Sprintf("environment variable %s", name)); err != nil {
			return err
		}
	}
	return nil
}

// setField parses raw per the field's kind; where names the offender for
// the boot error. The value itself is never echoed — a fat-fingered
// secret must not land in boot logs (go-security: no secrets in error
// messages).
func setField(v reflect.Value, f field, raw, where string) error {
	target := v.Elem().Field(f.section).Field(f.key)
	switch f.kind {
	case reflect.String:
		target.SetString(raw)
	case reflect.Int:
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("%s: not an integer", where)
		}
		target.SetInt(int64(n))
	case reflect.Bool:
		b, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("%s: not a bool (want true/false)", where)
		}
		target.SetBool(b)
	}
	return nil
}
