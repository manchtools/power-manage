// Package exectest provides a fake exec.Runner for unit-testing capability
// packages with no host, no sudo, and no container: because every capability
// handle is built with an explicit Runner, a test passes a FakeRunner and
// asserts on the exact Commands the capability built.
package exectest

import (
	"context"
	"strings"
	"sync"

	"github.com/manchtools/power-manage/sdk/exec"
)

// FakeRunner is a drop-in exec.Runner.
var _ exec.Runner = (*FakeRunner)(nil)

type scripted struct {
	res exec.Result
	err error
}

// FakeRunner is an exec.Runner that records every Command it receives and
// returns scripted Results in FIFO order. An unscripted call returns a clean
// success (zero Result, nil error). Safe for concurrent use.
type FakeRunner struct {
	mu      sync.Mutex
	backend exec.PrivilegeBackend
	calls   []exec.Command
	ctxs    []context.Context
	queue   []scripted
}

// New returns a FakeRunner that reports the given privilege backend. The zero
// value defaults to exec.Direct (the common unit-test runner).
func New(backend exec.PrivilegeBackend) *FakeRunner {
	if backend == 0 {
		backend = exec.Direct
	}
	return &FakeRunner{backend: backend}
}

// Backend reports the configured privilege backend, so a capability under test
// can branch on Runner.Backend() (e.g. an fd-safe vs sudo path).
func (f *FakeRunner) Backend() exec.PrivilegeBackend { return f.backend }

// Push scripts the next Run/Stream outcome (FIFO).
func (f *FakeRunner) Push(r exec.Result, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queue = append(f.queue, scripted{res: r, err: err})
}

// Calls returns every Command received, in order.
func (f *FakeRunner) Calls() []exec.Command {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]exec.Command(nil), f.calls...)
}

// CallContexts returns the context received with each recorded Command, in
// order (1:1 with Calls). Lets a test assert the invariant that every
// escalated call ran under a deadline-bounded context.
func (f *FakeRunner) CallContexts() []context.Context {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]context.Context(nil), f.ctxs...)
}

// record appends the attempted Command and its context to the call log.
func (f *FakeRunner) record(ctx context.Context, c exec.Command) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
	f.ctxs = append(f.ctxs, ctx)
}

// pop returns the next scripted outcome (FIFO), or a clean success if none.
func (f *FakeRunner) pop() (exec.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queue) == 0 {
		return exec.Result{}, nil
	}
	s := f.queue[0]
	f.queue = f.queue[1:]
	return s.res, s.err
}

// Run records the Command and returns the next scripted Result. An
// already-cancelled context short-circuits with ctx.Err() WITHOUT consuming a
// scripted result — mirroring the real Runner, so a capability's ctx handling
// can be unit-tested faithfully.
func (f *FakeRunner) Run(ctx context.Context, c exec.Command) (exec.Result, error) {
	// Apply the same env gate the real Runner enforces, BEFORE recording: a
	// Command carrying a blocked/reserved/malformed env var is rejected and never
	// recorded or "run", so a capability that builds an adversarial environment
	// fails identically against the fake and a real Runner.
	if err := exec.ValidateCommandEnv(c.Env); err != nil {
		return exec.Result{}, err
	}
	f.record(ctx, c)
	if err := ctx.Err(); err != nil {
		return exec.Result{}, err
	}
	return f.pop()
}

// Stream records the Command, returns the next scripted Result, and replays the
// scripted stdout/stderr to onLine line-by-line so streaming capabilities can
// be exercised without a real process. A cancelled context short-circuits as in
// Run (no scripted result consumed, no replay).
func (f *FakeRunner) Stream(ctx context.Context, c exec.Command, onLine exec.OutputCallback) (exec.Result, error) {
	if err := exec.ValidateCommandEnv(c.Env); err != nil {
		return exec.Result{}, err
	}
	f.record(ctx, c)
	if err := ctx.Err(); err != nil {
		return exec.Result{}, err
	}
	res, err := f.pop()
	if onLine != nil {
		replay(res.Stdout, exec.StreamStdout, onLine)
		replay(res.Stderr, exec.StreamStderr, onLine)
	}
	return res, err
}

// replay delivers buf to onLine one line at a time. Every delivered line is
// newline-terminated — INCLUDING an unterminated final line — because that is
// exactly what the real Runner does (its streaming path appends "\n" to every
// callback line; pinned by TestRunner_UnterminatedFinalLineDelivered).
// Preserving a missing final newline here would make the fake LESS faithful.
func replay(buf string, stream exec.StreamType, onLine exec.OutputCallback) {
	if buf == "" {
		return
	}
	var seq int64
	for _, line := range strings.Split(strings.TrimSuffix(buf, "\n"), "\n") {
		onLine(stream, line+"\n", seq)
		seq++
	}
}
