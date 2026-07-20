package exec_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
)

// Command.ChildPath is the TRUSTED seam for running with a caller-curated PATH
// (the per-user fan-out). The curated path must be the PATH the child sees
// even though PATH is blocklisted from caller Env.
func runnerForChildPathTest(t *testing.T) pmexec.Runner {
	t.Helper()
	r, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatalf("NewRunner(Direct): %v", err)
	}
	return r
}

func TestRunnerChildPath_AppliesCuratedPath(t *testing.T) {
	res, err := runnerForChildPathTest(t).Run(context.Background(), pmexec.Command{
		Name: "sh", Args: []string{"-c", `printf %s "$PATH"`},
		Env:       []string{"MARKER=1"},
		ChildPath: "/curated/bin:/usr/bin",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "/curated/bin:/usr/bin" {
		t.Fatalf("child PATH = %q, want the curated value", got)
	}
}

// SECURITY: with EMPTY Env the caller's ChildPath must STILL be authoritative
// and the parent environment must NOT be inherited — an empty-env caller must
// not silently inherit the agent's (root's) full environment (including root's
// PATH), which would defeat the isolation ChildPath exists to provide. Under
// [SDK-4] this holds by construction (the env is composed, never inherited);
// this test keeps it pinned end-to-end.
func TestRunnerChildPath_EmptyEnvStillIsolates(t *testing.T) {
	t.Setenv("PM_PARENT_SECRET", "leaked-from-root")

	res, err := runnerForChildPathTest(t).Run(context.Background(), pmexec.Command{
		Name: "sh", Args: []string{"-c", `printf %s "$PATH|${PM_PARENT_SECRET:-unset}"`},
		ChildPath: "/curated/bin",
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := strings.TrimSpace(res.Stdout); got != "/curated/bin|unset" {
		t.Fatalf("empty-env curated run leaked the parent environment: got %q, want %q",
			got, "/curated/bin|unset")
	}
}

// The boundary check still applies with a curated ChildPath: a blocklisted env
// var in Env is refused, so an untrusted caller cannot smuggle one past the seam.
func TestRunnerChildPath_StillRejectsBlockedEnv(t *testing.T) {
	_, err := runnerForChildPathTest(t).Run(context.Background(), pmexec.Command{
		Name: "true", Env: []string{"LD_PRELOAD=/tmp/evil.so"}, ChildPath: "/usr/bin",
	})
	if !errors.Is(err, pmexec.ErrBlockedEnvVar) {
		t.Fatalf("err = %v, want ErrBlockedEnvVar", err)
	}
}
