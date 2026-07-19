package liveness

import (
	"testing"

	guardtest "example.com/unrelated/guardtest"
)

// Deliberate G-000-3 violation: calls a Discover from an UNRELATED package
// that merely shares the guardtest name. Must stay non-conforming — a
// name-only check would accept it.
func TestGuard_UnrelatedImport(t *testing.T) {
	guardtest.Discover(t, "fake", 1, func() ([]string, error) { return []string{"x"}, nil })
}
