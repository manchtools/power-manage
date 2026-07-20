package liveness

import (
	"testing"

	"github.com/manchtools/power-manage/contract/archtest"
)

// TestGuard_ViaArchtest enumerates through the second sanctioned harness
// (contract/archtest, INV-19 boundary) — G-000-3 must accept it.
func TestGuard_ViaArchtest(t *testing.T) {
	archtest.Discover(t, "things", 1, func() ([]string, error) {
		return []string{"thing"}, nil
	})
}
