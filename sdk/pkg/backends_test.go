package pkg

import (
	"strings"
	"testing"
)

// allBackends is the single source of truth every "for each backend" test
// iterates. TestAllBackends_CoversEnum proves it equals the Backend enum, so a
// new backend cannot ship without extending exactly this slice — which in turn
// forces its per-backend contract coverage here and, via the CI lane-parity
// guard, its real-tool container lane.
var allBackends = []Backend{Apt, Dnf, Pacman, Zypper, Flatpak}

func TestAllBackends_CoversEnum(t *testing.T) {
	// Discover the enum size from String()'s default sentinel: an implemented
	// backend has a String case, so the scan grows with the enum and a
	// hand-maintained allBackends that lags fails here (matches-zero + exact).
	n := 0
	for b := Apt; !strings.HasPrefix(b.String(), "Backend("); b++ {
		n++
		if n > 1000 {
			t.Fatal("runaway Backend enum scan — String() is missing its default sentinel")
		}
	}
	if n == 0 {
		t.Fatal("discovered zero backends")
	}
	if len(allBackends) != n {
		t.Fatalf("allBackends lists %d backends, enum has %d — add the new backend to allBackends", len(allBackends), n)
	}
	for i, b := range allBackends {
		if b != Backend(i+1) {
			t.Fatalf("allBackends[%d] = %v, want enum order %v", i, b, Backend(i+1))
		}
	}
}
