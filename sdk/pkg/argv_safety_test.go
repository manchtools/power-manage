package pkg

import (
	"context"
	"reflect"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/validate"
)

// indexOf returns the first index of want in args, or -1.
func indexOf(args []string, want string) int {
	for i, a := range args {
		if a == want {
			return i
		}
	}
	return -1
}

// TestEveryManagerMethodNeutralizesFlagShapedOperands is a self-discovering
// guard over the WHOLE Manager surface: for every method and every string (or
// variadic ...string) operand, a flag-shaped value ("-rf") must never reach the
// package manager as a parseable option. Each method satisfies this one of two
// honest ways:
//
//   - it REJECTS the value before any command runs — the package-name, the
//     local-package-path, and the search-query validators all do this (a search
//     query cannot be "--"-guarded because dnf5's `search` rejects "--", so a
//     flag-shaped query is refused instead), or
//   - the value reaches argv only AFTER a "--" end-of-options separator, so the
//     tool treats it as an operand, not a flag.
//
// The method set is discovered by reflection over the interface and the check is
// run against every backend, with a matches-zero guard so a future refactor that
// drops the operands cannot pass it vacuously. This is the package-wide analogue
// of service's TestEveryMethodRejectsUnsafeUnitNameBeforeRunner.
func TestEveryManagerMethodNeutralizesFlagShapedOperands(t *testing.T) {
	const flag = "-rf"       // flag-shaped: must never be parsed as an option
	const safe = "coreutils" // a valid package name for any non-target string param

	// Resolve every backend's binary so a method that probes PATH before
	// rejecting still reaches its validation rather than a "not found".

	mt := reflect.TypeOf((*Manager)(nil)).Elem()
	if mt.NumMethod() == 0 {
		t.Fatal("matches-zero guard: Manager has no methods")
	}
	ctxType := reflect.TypeOf((*context.Context)(nil)).Elem()
	backends := allBackends
	checked := 0

	isStringOperand := func(ft reflect.Type, p int) bool {
		pt := ft.In(p)
		if pt.Kind() == reflect.String {
			return true
		}
		return ft.IsVariadic() && p == ft.NumIn()-1 && pt.Elem().Kind() == reflect.String
	}

	for _, b := range backends {
		probe, _ := mustNew(t, b)
		for i := 0; i < mt.NumMethod(); i++ {
			name := mt.Method(i).Name
			ft := reflect.ValueOf(probe).MethodByName(name).Type()

			var targets []int
			for p := 0; p < ft.NumIn(); p++ {
				if isStringOperand(ft, p) {
					targets = append(targets, p)
				}
			}

			for _, target := range targets {
				f := newFake()
				m, err := New(b, f)
				if err != nil {
					t.Fatalf("New(%v): %v", b, err)
				}
				fn := reflect.ValueOf(m).MethodByName(name)

				args := make([]reflect.Value, ft.NumIn())
				for p := 0; p < ft.NumIn(); p++ {
					pt := ft.In(p)
					val := safe
					if p == target {
						val = flag
					}
					switch {
					case pt == ctxType:
						args[p] = reflect.ValueOf(context.Background())
					case ft.IsVariadic() && p == ft.NumIn()-1 && pt.Elem().Kind() == reflect.String:
						args[p] = reflect.ValueOf([]string{val})
					case pt.Kind() == reflect.String:
						args[p] = reflect.ValueOf(val)
					default:
						args[p] = reflect.Zero(pt)
					}
				}
				if ft.IsVariadic() {
					fn.CallSlice(args)
				} else {
					fn.Call(args)
				}

				for _, c := range f.Calls() {
					idx := indexOf(c.Args, flag)
					if idx < 0 {
						continue // this command does not carry the flag-shaped token
					}
					sep := indexOf(c.Args, pmexec.EndOfOptions)
					if sep < 0 || sep > idx {
						t.Errorf("%s.%s (operand #%d): %q reaches argv as an OPTION — no %q separator before it: %s %v",
							b, name, target, flag, pmexec.EndOfOptions, c.Name, c.Args)
					}
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("matches-zero guard: no operand-taking Manager methods were exercised")
	}
}

// TestSearch_RejectsFlagShapedQuery is the per-backend, behaviour-level companion
// to the reflective guard above: a flag-shaped query is refused on every backend
// BEFORE the package manager runs (so it can never be reparsed as an option),
// while an ordinary query reaches the tool unchanged.
func TestSearch_RejectsFlagShapedQuery(t *testing.T) {
	ctx := context.Background()
	for _, b := range allBackends {
		t.Run(b.String(), func(t *testing.T) {
			m, f := mustNew(t, b)
			if _, err := m.Search(ctx, "-rf"); err == nil {
				t.Errorf("Search(%q) = nil error, want a validation error", "-rf")
			}
			if n := len(f.Calls()); n != 0 {
				t.Errorf("Search ran %d command(s) on a flag-shaped query; want 0", n)
			}
			// A normal query still runs.
			ok(f, "")
			if _, err := m.Search(ctx, "vim"); err != nil {
				t.Errorf("Search(vim) = %v, want nil", err)
			}
			if n := len(f.Calls()); n != 1 {
				t.Errorf("Search(vim) ran %d command(s); want 1", n)
			}
		})
	}
}

// TestValidateSearchQuery covers the query validator directly.
func TestValidateSearchQuery(t *testing.T) {
	for _, q := range []string{"vim", "lib-foo", "c++", "gtk3.0", "", "x86_64"} {
		if err := validate.SearchQuery(q); err != nil {
			t.Errorf("ValidateSearchQuery(%q) = %v, want nil", q, err)
		}
	}
	for _, q := range []string{"-rf", "--installed", "-x", "vim\nrm", "a\x00b"} {
		if err := validate.SearchQuery(q); err == nil {
			t.Errorf("ValidateSearchQuery(%q) = nil, want an error", q)
		}
	}
}
