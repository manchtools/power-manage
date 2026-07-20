package redos

import (
	"errors"
	"strings"
	"testing"
)

// AC-8 / [SDK-6]: the guard rejects nested-group quantifier shapes, INCLUDING
// the doubly-nested forms that bypass a naive per-group check — the
// quantifier/alternation state must propagate from a closed group to its
// parent, or `((a+))+` sails through.
func TestVet_RejectsNestedQuantifiers(t *testing.T) {
	bad := []struct{ pattern, why string }{
		{"(a+)+", "classic nested quantifier"},
		{"(a*)*", "star-star"},
		{"(a{1,})+", "brace-unbounded inner quantifier"},
		{"((a+))+", "PARENT-STATE PROPAGATION: inner quantifier one group deeper"},
		{"((a|ab))+", "PARENT-STATE PROPAGATION: alternation one group deeper"},
		{"(a|a)+", "overlapping alternation under quantifier"},
		{"(a|ab)+", "alternation under quantifier"},
		{"(.*a){11}", "bounded repetition of an unbounded group (polynomial blowup)"},
		{"(.*a){1,11}", "upper bound drives the worst case"},
		{"((.*a)){2}", "propagated inner quantifier under bounded repeat"},
		{"a*b+c*d+e*f+", "more than 5 unbounded quantifiers"},
	}
	for _, tc := range bad {
		err := Vet(tc.pattern)
		if err == nil {
			t.Errorf("Vet(%q) = nil, want rejection (%s)", tc.pattern, tc.why)
			continue
		}
		if !errors.Is(err, ErrPathological) {
			t.Errorf("Vet(%q) = %v, want errors.Is(_, ErrPathological)", tc.pattern, err)
		}
	}
}

// The vetted grammar set — including the env-name grammar the exec package
// routes through this chokepoint — passes.
func TestVet_AcceptsVettedGrammars(t *testing.T) {
	good := []string{
		`^[a-zA-Z_][a-zA-Z0-9_]*$`, // exec.ValidEnvVarName
		`^\d{1,3}$`,
		`foo.*bar`,
		`(abc)+`,     // quantified group without inner quantifier or alternation
		`(a+)`,       // inner quantifier, group itself unquantified
		`(a|b)c`,     // alternation, not under a quantifier
		`(a|b){3}`,   // alternation under BOUNDED repeat: bounded branching
		`(ab){3}`,    // bounded repeat of a clean group
		`\(a+\)+`,    // escaped parens are literals, not a group
		`^[a-z]+@[a-z]+\.[a-z]{2,}$`, // three unbounded quantifiers, under the limit
	}
	for _, p := range good {
		if err := Vet(p); err != nil {
			t.Errorf("Vet(%q) = %v, want nil (vetted grammar)", p, err)
		}
	}
}

// AC-8: the rejection is an ERROR, not a panic — for pathological shapes AND
// for syntactically invalid patterns.
func TestCompile_ErrorNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Compile panicked: %v", r)
		}
	}()

	if re, err := Compile("(a+)+"); err == nil || re != nil {
		t.Errorf("Compile((a+)+) = (%v, %v), want (nil, ErrPathological)", re, err)
	} else if !errors.Is(err, ErrPathological) {
		t.Errorf("Compile((a+)+) err = %v, want ErrPathological", err)
	}

	if _, err := Compile("["); err == nil {
		t.Error("Compile([) = nil error, want a syntax error")
	} else if errors.Is(err, ErrPathological) {
		t.Errorf("Compile([) err = %v; a syntax error must not masquerade as pathological", err)
	}

	re, err := Compile("^ok$")
	if err != nil {
		t.Fatalf("Compile(^ok$) err = %v", err)
	}
	if !re.MatchString("ok") || re.MatchString("nope") {
		t.Error("Compile(^ok$) returned a non-functioning regexp")
	}
}

// MustVet serves the compile-time-literal use: a vetted literal yields a
// working regexp; a pathological literal panics at init (programmer error,
// caught by the first test run).
func TestMustVet_CompileTimeLiteral(t *testing.T) {
	re := MustVet(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	if !re.MatchString("GOOD_NAME") || re.MatchString("1bad") {
		t.Error("MustVet returned a non-functioning regexp for the env-name grammar")
	}

	func() {
		defer func() {
			r := recover()
			if r == nil {
				t.Error("MustVet((a+)+) did not panic; a pathological compile-time literal must fail loudly")
				return
			}
			if !strings.Contains(strings.ToLower(fmtRecover(r)), "pathological") {
				t.Errorf("MustVet panic = %v, want it to name the pathological rejection", r)
			}
		}()
		_ = MustVet("(a+)+")
	}()
}

func fmtRecover(r any) string {
	if err, ok := r.(error); ok {
		return err.Error()
	}
	if s, ok := r.(string); ok {
		return s
	}
	return ""
}
