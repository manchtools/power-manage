package liveness

import "testing"

// Deliberate G-000-3 violation: a locally declared Discover shadows the
// harness. Must stay non-conforming — a name-only check would accept it.
func Discover(t *testing.T, desc string, floor int, discover func() ([]string, error)) []string {
	return nil
}

func TestGuard_Shadowed(t *testing.T) {
	Discover(t, "fake", 1, func() ([]string, error) { return []string{"x"}, nil })
}
