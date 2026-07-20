package exec_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
)

// The Runner enforces the SDK env hijack boundary on Command.Env via
// buildChildEnv→ValidateCommandEnv: a blocked name is refused BEFORE the child
// is spawned, returning ErrBlockedEnvVar so a caller can branch (e.g. log a
// security violation) rather than treat it as a generic exec failure. These
// cases pin the breadth of the blocklist end-to-end through the real Runner.
func runnerForEnvTest(t *testing.T) pmexec.Runner {
	t.Helper()
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	return r
}

func TestRunner_RejectsBlockedEnvVars(t *testing.T) {
	blocked := []string{
		"LD_PRELOAD=/tmp/evil.so",
		"PATH=/tmp/attacker", // user-supplied PATH is blocked; use ChildPath for a curated one
		"BASH_ENV=/tmp/evil.sh",
		"GCONV_PATH=/tmp/evil",
		"LD_LIBRARY_PATH=/tmp/evil",
	}
	r := runnerForEnvTest(t)
	for _, e := range blocked {
		_, err := r.Run(context.Background(), pmexec.Command{Name: "true", Env: []string{e}})
		if !errors.Is(err, pmexec.ErrBlockedEnvVar) {
			t.Errorf("Run with Env %q err = %v, want ErrBlockedEnvVar", e, err)
		}
	}
}

func TestRunner_RejectsMalformedEnvEntry(t *testing.T) {
	r := runnerForEnvTest(t)
	_, err := r.Run(context.Background(), pmexec.Command{Name: "true", Env: []string{"NOTKEY_EQUALS_VALUE"}})
	if !errors.Is(err, pmexec.ErrInvalidEnvVar) {
		t.Fatalf("err = %v, want ErrInvalidEnvVar", err)
	}
}

// The inverse contract: a name not on the blocklist passes through and is
// visible to the child.
func TestRunner_AcceptsSafeEnvVar(t *testing.T) {
	r := runnerForEnvTest(t)
	res, err := r.Run(context.Background(), pmexec.Command{
		Name: "sh", Args: []string{"-c", `printf %s "$PM_AUDIT_TEST_MARKER"`},
		Env: []string{"PM_AUDIT_TEST_MARKER=ok"},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "ok" {
		t.Fatalf("child did not see the safe env var: stdout=%q (trimmed=%q)", res.Stdout, got)
	}
}
