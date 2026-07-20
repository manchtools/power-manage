package exec

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// This file holds the low-level execution core the injected Runner
// (runner.go) builds on: line-buffered streaming with per-stream caps and
// the [SDK-5] cancellation contract — SIGTERM the process group, bounded
// grace, SIGKILL the group, second bounded grace — implemented directly on
// os/exec + syscall (children start in their own process group via Setpgid).

// killGrace bounds how long a cancelled child has to exit on SIGTERM before
// its process group is escalated to SIGKILL. A package var (not const) so
// tests can shorten it. Without escalation a SIGTERM-ignoring child would
// pin the caller until the child exits on its own — or forever.
var killGrace = 5 * time.Second

// maxLineBytes bounds the memory a single line without a newline can pin. A
// longer "line" is delivered to the callback in maxLineBytes chunks (each
// newline-terminated) rather than accumulated unboundedly.
const maxLineBytes = 4 * MaxOutputBytes

// procStatus is the reaped (or best-effort) outcome of a child process.
type procStatus struct {
	exit int
	err  error // non-nil only for a failure to execute/reap, never a clean non-zero exit
}

// awaitStatusOrKill enforces the [SDK-5] escalation for a cancelled command:
// SIGTERM the process group, wait killGrace for the status; SIGKILL the whole
// group, wait a second killGrace; on a child that still cannot be reaped
// (e.g. an uninterruptible D-state) return a best-effort snapshot rather than
// block the caller forever. pgid is the child's process-group id (the child
// is its own group leader via Setpgid).
func awaitStatusOrKill(pgid int, statusCh <-chan procStatus) procStatus {
	// The error returns on these kills are deliberately dropped: the group may
	// already be gone (ESRCH), which is success for our purposes.
	_ = syscall.Kill(-pgid, syscall.SIGTERM)

	term := time.NewTimer(killGrace)
	defer term.Stop()
	select {
	case s := <-statusCh:
		return s
	case <-term.C:
	}

	_ = syscall.Kill(-pgid, syscall.SIGKILL)

	kill := time.NewTimer(killGrace)
	defer kill.Stop()
	select {
	case s := <-statusCh:
		return s
	case <-kill.C:
		// Even SIGKILL could not be reaped within grace. Snapshot, don't block.
		return procStatus{exit: -1}
	}
}

// runStreamingWithStdin is the shared low-level execution core: line-buffered
// streaming with a per-stream MaxOutputBytes capture cap, ctx-cancel
// SIGTERM→SIGKILL process-group escalation, and non-zero-exit-is-NOT-an-error
// semantics (the exit code is in Result; the returned error is non-nil only on
// failure to execute or ctx cancellation). env is the complete child
// environment (the Runner always composes it — there is no inherit mode).
func runStreamingWithStdin(ctx context.Context, name string, args []string, stdin io.Reader, env []string, dir string, callback OutputCallback) (*Result, error) {
	c := exec.Command(name, args...)
	if dir != "" {
		c.Dir = dir
	}
	c.Env = env
	if stdin != nil {
		c.Stdin = stdin
	}
	// The child leads its own process group so cancellation can signal the
	// whole tree (grandchildren included), not just the immediate child.
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdoutPipe, err := c.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("exec %s: stdout pipe: %w", name, err)
	}
	stderrPipe, err := c.StderrPipe()
	if err != nil {
		// Start/Wait are never reached on this path, so the stdout pipe's two
		// descriptors would otherwise leak — exactly when fds are scarce.
		_ = stdoutPipe.Close()
		return nil, fmt.Errorf("exec %s: stderr pipe: %w", name, err)
	}

	if err := c.Start(); err != nil {
		return nil, fmt.Errorf("exec %s: %w", name, err)
	}
	pgid := c.Process.Pid

	// Capture state, shared by both reader goroutines. The mutex also
	// serializes callback delivery (the OutputCallback contract).
	var (
		mu       sync.Mutex
		bufs     [2]strings.Builder
		rawBytes [2]int64
		seqs     [2]int64
	)
	streamIdx := func(s StreamType) int {
		if s == StreamStdout {
			return 0
		}
		return 1
	}
	// recordLine appends to the capture buffer — capped: a line that would
	// push the cumulative count past MaxOutputBytes is dropped entirely, and
	// the overrun is flagged with a single trailing marker on render — and
	// fires the callback with a per-stream monotonic sequence number.
	recordLine := func(stream StreamType, line string) {
		i := streamIdx(stream)
		mu.Lock()
		defer mu.Unlock()
		rawBytes[i] += int64(len(line) + 1)
		if rawBytes[i] <= int64(MaxOutputBytes) {
			bufs[i].WriteString(line + "\n")
		}
		if callback != nil {
			callback(stream, line+"\n", seqs[i])
		}
		seqs[i]++
	}

	// readLines pumps one pipe to recordLine until EOF/error. EOF arrives when
	// every process holding the write end has exited — the group SIGKILL in
	// awaitStatusOrKill is what guarantees that on the cancellation path, so
	// this read path needs no ctx select of its own. A final unterminated line
	// is delivered newline-terminated (pinned by the runner tests and mirrored
	// by exectest's replay).
	readLines := func(r io.Reader, stream StreamType) {
		br := bufio.NewReaderSize(r, 64*1024)
		var partial strings.Builder
		for {
			chunk, rerr := br.ReadSlice('\n')
			if len(chunk) > 0 {
				if chunk[len(chunk)-1] == '\n' {
					line := string(chunk[:len(chunk)-1])
					if partial.Len() > 0 {
						line = partial.String() + line
						partial.Reset()
					}
					recordLine(stream, line)
				} else {
					partial.Write(chunk)
					if partial.Len() >= maxLineBytes {
						recordLine(stream, partial.String())
						partial.Reset()
					}
				}
			}
			if rerr != nil && !errors.Is(rerr, bufio.ErrBufferFull) {
				if partial.Len() > 0 {
					recordLine(stream, partial.String())
				}
				return
			}
		}
	}

	var readers sync.WaitGroup
	readers.Add(2)
	go func() {
		defer readers.Done()
		readLines(stdoutPipe, StreamStdout)
	}()
	go func() {
		defer readers.Done()
		readLines(stderrPipe, StreamStderr)
	}()

	// Buffered so the wait goroutine never leaks when the D-state fallback
	// abandons the channel.
	statusCh := make(chan procStatus, 1)
	go func() {
		// os/exec contract: all pipe reads complete before Wait (Wait closes
		// the pipes).
		readers.Wait()
		werr := c.Wait()
		var ee *exec.ExitError
		if werr != nil && !errors.As(werr, &ee) {
			statusCh <- procStatus{exit: -1, err: fmt.Errorf("exec %s: wait: %w", name, werr)}
			return
		}
		statusCh <- procStatus{exit: c.ProcessState.ExitCode()}
	}()

	var status procStatus
	var runErr error
	select {
	case status = <-statusCh:
		runErr = status.err
	case <-ctx.Done():
		status = awaitStatusOrKill(pgid, statusCh)
		runErr = ctx.Err()
	}

	// On the fallback path the readers may still be live; the mutex keeps the
	// render consistent (late lines after the snapshot are lost by design).
	mu.Lock()
	stdout := bufs[0].String()
	if rawBytes[0] > int64(MaxOutputBytes) {
		stdout += truncationMarker
	}
	stderr := bufs[1].String()
	if rawBytes[1] > int64(MaxOutputBytes) {
		stderr += truncationMarker
	}
	mu.Unlock()

	return &Result{
		ExitCode: status.exit,
		Stdout:   stdout,
		Stderr:   stderr,
	}, runErr
}
