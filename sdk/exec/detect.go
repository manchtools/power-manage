package exec

import (
	"context"
	"os/exec"
)

// Detect lists the privilege-escalation backends usable on THIS host: Sudo if
// `sudo` is on PATH, Doas if `doas` is on PATH. It LISTS — it never picks and
// never constructs a Runner; the consumer reads the list, picks one
// explicitly, and passes it to NewRunner (capability from probing, never from
// distro switches). Direct (run as the current process, no wrapper) needs no
// detection and is never returned. A host with neither tool returns an empty
// slice — a valid result for a root-only consumer that will use Direct.
//
// The ctx is accepted for signature uniformity with the capability Detect
// functions (which stat marker files); the present probe is a pure PATH lookup.
func Detect(ctx context.Context) []PrivilegeBackend {
	_ = ctx
	var out []PrivilegeBackend
	if _, err := exec.LookPath("sudo"); err == nil {
		out = append(out, Sudo)
	}
	if _, err := exec.LookPath("doas"); err == nil {
		out = append(out, Doas)
	}
	return out
}
