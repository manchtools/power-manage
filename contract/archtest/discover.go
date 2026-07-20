package archtest

import "testing"

// Discover mirrors sdk/guardtest.Discover across the INV-19 import
// boundary: a guard's population comes from ground truth, and a discovery
// that returns fewer subjects than the floor FAILS — an empty walk means
// the discovery broke, not that the contract is clean.
func Discover[T any](t testing.TB, what string, floor int, fn func() ([]T, error)) []T {
	t.Helper()
	if floor < 1 {
		t.Fatalf("guard misuse: floor for %q is %d — a guard that tolerates zero subjects cannot detect its own discovery breaking", what, floor)
	}
	got, err := fn()
	if err != nil {
		t.Fatalf("discovering %s: %v", what, err)
	}
	if len(got) < floor {
		t.Fatalf("discovered %d %s, need at least %d — the discovery is broken or the population moved; fix the walk, never the floor", len(got), what, floor)
	}
	return got
}
