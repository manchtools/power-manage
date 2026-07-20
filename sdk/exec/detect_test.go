package exec

import (
	osexec "os/exec"
	"testing"
)

// Detect LISTS the escalation backends usable on THIS host: it lists, it never
// picks, and it never constructs a Runner. Direct needs no detection (it is
// "run as the current process"), so it is never returned.
func TestDetect_ListsOnlyInstalledSudoDoasNeverDirect(t *testing.T) {
	got := Detect(t.Context())

	for _, b := range got {
		if b == Direct {
			t.Errorf("Detect returned Direct; it must list only escalation tools (Sudo/Doas)")
		}
		if b != Sudo && b != Doas {
			t.Errorf("Detect returned unexpected backend %d", b)
		}
	}
	// No duplicates.
	seen := map[PrivilegeBackend]bool{}
	for _, b := range got {
		if seen[b] {
			t.Errorf("Detect returned duplicate backend %d", b)
		}
		seen[b] = true
	}
	// Cross-check against the host: presence in the list must agree with
	// whether the tool is actually on PATH (the expectation is derived from
	// the host independently of Detect's own probe).
	_, sudoErr := osexec.LookPath("sudo")
	if (sudoErr == nil) != seen[Sudo] {
		t.Errorf("Detect Sudo presence = %v, but sudo on PATH = %v", seen[Sudo], sudoErr == nil)
	}
	_, doasErr := osexec.LookPath("doas")
	if (doasErr == nil) != seen[Doas] {
		t.Errorf("Detect Doas presence = %v, but doas on PATH = %v", seen[Doas], doasErr == nil)
	}
}
