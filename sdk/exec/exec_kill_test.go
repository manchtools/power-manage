package exec

import (
	"context"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// [SDK-5]: on ctx cancel the exec core SIGTERMs the child's process group and,
// if the child has not exited within killGrace, escalates to SIGKILL on the
// whole group — a SIGTERM-ignoring child must never pin the caller until it
// exits on its own (or forever). The escalation path is exercised through the
// Runner in runner_test.go (TestRunner_SIGKILLsChildThatIgnoresSIGTERM), which
// reuses the three helpers below. This file keeps those helpers, the
// well-behaved control case, and the bounded D-state fallback.

// readChildPID reads the pgid-leader PID the child shell wrote ($$).
func readChildPID(t *testing.T, pidFile string) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		b, err := os.ReadFile(pidFile)
		if err == nil {
			if pid, perr := strconv.Atoi(strings.TrimSpace(string(b))); perr == nil && pid > 0 {
				return pid
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("child never wrote its PID to %s", pidFile)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// assertProcessGroupGone polls until kill(-pid, 0) reports ESRCH (the whole
// group is gone — the AC-6 "neither child nor grandchild survives" check;
// the respawned sleep grandchildren share the group). SIGKILL delivery +
// reaping is asynchronous.
func assertProcessGroupGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := syscall.Kill(-pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("process group %d still alive after grace (kill(-pid,0)=%v) — SIGKILL never delivered", pid, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// sigtermIgnoringScript writes its pgid-leader PID, traps+ignores SIGTERM in
// the shell, and loops re-spawning sleep so the GROUP stays alive across a
// SIGTERM. A bare `sleep 30` would NOT work: the group SIGTERM also hits the
// sleep child (default disposition → it dies), the script completes and the
// shell exits — SIGKILL would never be exercised. The restart loop keeps the
// shell (which ignores SIGTERM) running until SIGKILL tears down the group,
// and the respawned sleep is the grandchild AC-6 demands dead too.
func sigtermIgnoringScript(pidFile string) string {
	return fmt.Sprintf(`echo $$ > %s; trap "" TERM; while true; do sleep 30; done`, pidFile)
}

// TestAwaitStatusOrKill_DStateFallback covers the last-resort branch: if a child
// cannot be reaped even after SIGKILL within the grace (e.g. an uninterruptible
// D-state), awaitStatusOrKill must return a best-effort snapshot rather than
// block forever. We force the branch deterministically by passing a status
// channel that NEVER delivers, so both timers fire; the real child started here
// is SIGTERM'd and SIGKILL'd by the function itself, so nothing leaks.
func TestAwaitStatusOrKill_DStateFallback(t *testing.T) {
	restore := killGrace
	killGrace = 50 * time.Millisecond
	defer func() { killGrace = restore }()

	c := osexec.Command("sleep", "60")
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := c.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	never := make(chan procStatus)

	start := time.Now()
	_ = awaitStatusOrKill(c.Process.Pid, never)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("awaitStatusOrKill blocked %v; the bounded D-state fallback did not fire", elapsed)
	}
	_ = c.Wait() // reap the SIGKILLed child
}

// TestRunner_WellBehavedChildReapsOnSIGTERM is the correct-path control: a child
// that honors SIGTERM reaps at cancel, well before the SIGKILL grace, and the
// Runner still returns ctx.Err().
func TestRunner_WellBehavedChildReapsOnSIGTERM(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := directRunner(t).Run(ctx, Command{Name: "sleep", Args: []string{"30"}}) // default disposition: dies on SIGTERM
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("well-behaved child took %v to reap on SIGTERM", elapsed)
	}
}
