package exectest_test

import (
	"context"
	"errors"
	"testing"

	"github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/exec/exectest"
)

// Stream with a nil callback still records the Command and returns the scripted
// Result (no replay attempted).
func TestFakeRunner_StreamNilCallback(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{ExitCode: 0, Stdout: "line\n"}, nil)

	res, err := f.Stream(context.Background(), exec.Command{Name: "journalctl"}, nil)
	if err != nil {
		t.Fatalf("Stream(nil callback) err = %v", err)
	}
	if res.Stdout != "line\n" {
		t.Errorf("Stdout = %q, want the scripted result", res.Stdout)
	}
	if len(f.Calls()) != 1 || f.Calls()[0].Name != "journalctl" {
		t.Errorf("Stream did not record the Command: %+v", f.Calls())
	}
}

// Stream mirrors Run on an already-cancelled context: it returns ctx.Err(),
// does NOT consume the scripted result, and replays nothing.
func TestFakeRunner_StreamRespectsCancelledContext(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "must-not-replay\n"}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	replayed := 0
	res, err := f.Stream(ctx, exec.Command{Name: "journalctl"},
		func(exec.StreamType, string, int64) { replayed++ })
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	if replayed != 0 {
		t.Errorf("replayed %d lines on a cancelled Stream, want 0", replayed)
	}
	if res.Stdout != "" {
		t.Errorf("res = %+v, want zero value (scripted result not consumed)", res)
	}
	// The scripted result is preserved for the next (non-cancelled) call.
	if next, _ := f.Run(context.Background(), exec.Command{Name: "journalctl"}); next.Stdout != "must-not-replay\n" {
		t.Errorf("scripted result was wrongly consumed by the cancelled Stream: %q", next.Stdout)
	}
}

// Replay newline-terminates EVERY delivered line — including an unterminated
// final line — because that is exactly what the real Runner does (pinned by
// TestRunner_UnterminatedFinalLineDelivered). Sequence numbers are per-stream
// monotonic from 0.
func TestFakeRunner_ReplayTerminatesFinalLineAndSequences(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "a\nb", Stderr: "e1\n"}, nil)

	type ev struct {
		s    exec.StreamType
		line string
		seq  int64
	}
	var got []ev
	_, err := f.Stream(context.Background(), exec.Command{Name: "x"},
		func(s exec.StreamType, line string, seq int64) {
			got = append(got, ev{s, line, seq})
		})
	if err != nil {
		t.Fatalf("Stream err = %v", err)
	}
	want := []ev{
		{exec.StreamStdout, "a\n", 0},
		{exec.StreamStdout, "b\n", 1},
		{exec.StreamStderr, "e1\n", 0},
	}
	if len(got) != len(want) {
		t.Fatalf("replayed %d events, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
