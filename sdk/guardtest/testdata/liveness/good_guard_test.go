package liveness

import (
	"testing"

	"github.com/manchtools/power-manage/sdk/guardtest"
)

// Conforming guard: qualified call resolved through the real harness import.
// Must NOT be flagged — proves the checker cannot drift into always-red.
//
// Guards: INV-19.
func TestGuard_Conforming(t *testing.T) {
	guardtest.Discover(t, "real", 1, func() ([]string, error) { return []string{"x"}, nil })
}
