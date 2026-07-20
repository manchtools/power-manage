package exectest_test

import (
	"context"
	"errors"
	"testing"

	"github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/exec/exectest"
)

// FakeRunner is the keystone of the unit tier: a capability built with it can
// be tested with no host, no sudo, no container. It records every Command in
// order and returns scripted Results FIFO.

// Compile-time proof it is a drop-in exec.Runner.
var _ exec.Runner = (*exectest.FakeRunner)(nil)

func TestFakeRunner_RecordsCommandsInOrder(t *testing.T) {
	f := exectest.New(exec.Direct)
	ctx := context.Background()

	_, _ = f.Run(ctx, exec.Command{Name: "useradd", Args: []string{"-m", "deploy"}})
	_, _ = f.Run(ctx, exec.Command{Name: "usermod", Args: []string{"-L", "deploy"}})

	calls := f.Calls()
	if len(calls) != 2 {
		t.Fatalf("Calls() len = %d, want 2", len(calls))
	}
	if calls[0].Name != "useradd" || calls[1].Name != "usermod" {
		t.Errorf("recorded order = %q,%q, want useradd,usermod", calls[0].Name, calls[1].Name)
	}
}

func TestFakeRunner_ScriptsResultsFIFO(t *testing.T) {
	f := exectest.New(exec.Direct)
	want1 := exec.Result{ExitCode: 0, Stdout: "first"}
	errBoom := errors.New("boom")
	f.Push(want1, nil)
	f.Push(exec.Result{ExitCode: 7}, errBoom)

	got1, err1 := f.Run(context.Background(), exec.Command{Name: "a"})
	if err1 != nil || got1.Stdout != "first" {
		t.Errorf("first Run = (%+v, %v), want (%+v, nil)", got1, err1, want1)
	}
	got2, err2 := f.Run(context.Background(), exec.Command{Name: "b"})
	if !errors.Is(err2, errBoom) || got2.ExitCode != 7 {
		t.Errorf("second Run = (%+v, %v), want (ExitCode 7, boom)", got2, err2)
	}
}

func TestFakeRunner_DefaultsToSuccessWhenUnscripted(t *testing.T) {
	f := exectest.New(exec.Direct)
	res, err := f.Run(context.Background(), exec.Command{Name: "true"})
	if err != nil || res.ExitCode != 0 {
		t.Errorf("unscripted Run = (%+v, %v), want clean success", res, err)
	}
}

// AC-3 on the unit tier: the FakeRunner applies the IDENTICAL env gate the real
// Runner enforces (ValidateCommandEnv), so an adversarial Command.Env fails the
// same way against a fake as against a real Runner — and is never recorded.
func TestFakeRunner_RejectsBlockedEnvLikeRealRunner(t *testing.T) {
	cases := []struct {
		name string
		env  []string
		want error
	}{
		{name: "LD_PRELOAD", env: []string{"LD_PRELOAD=/tmp/evil.so"}, want: exec.ErrBlockedEnvVar},
		{name: "PATH override", env: []string{"PATH=/tmp/attacker"}, want: exec.ErrBlockedEnvVar},
		{name: "reserved locale", env: []string{"LC_ALL=tr_TR.UTF-8"}, want: exec.ErrReservedEnvVar},
		{name: "reserved LANGUAGE", env: []string{"LANGUAGE=ja"}, want: exec.ErrReservedEnvVar},
		{name: "reserved NO_COLOR", env: []string{"NO_COLOR="}, want: exec.ErrReservedEnvVar},
		{name: "malformed", env: []string{"NOT_KEY_VALUE"}, want: exec.ErrInvalidEnvVar},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := exectest.New(exec.Direct)
			_, err := f.Run(context.Background(), exec.Command{Name: "true", Env: tc.env})
			if !errors.Is(err, tc.want) {
				t.Fatalf("FakeRunner.Run env %v error = %v, want %v", tc.env, err, tc.want)
			}
			if calls := f.Calls(); len(calls) != 0 {
				t.Fatalf("FakeRunner recorded %d invalid command(s); validation should reject before recording/running: %+v", len(calls), calls)
			}
		})
	}
}

func TestFakeRunner_BackendReported(t *testing.T) {
	if got := exectest.New(exec.Sudo).Backend(); got != exec.Sudo {
		t.Errorf("Backend() = %d, want Sudo", got)
	}
	// Zero value defaults to Direct (the common unit-test runner).
	if got := exectest.New(0).Backend(); got != exec.Direct {
		t.Errorf("Backend() for zero value = %d, want Direct default", got)
	}
}

// A cancelled context makes FakeRunner behave like the real Runner: it returns
// ctx.Err(), does NOT consume a scripted result (the command did not run), but
// still records the attempt so a test can see what the capability tried.
func TestFakeRunner_RespectsCancelledContext(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{Stdout: "should-not-be-returned"}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, err := f.Run(ctx, exec.Command{Name: "useradd"})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Run with cancelled ctx err = %v, want context.Canceled", err)
	}
	if res.Stdout != "" {
		t.Errorf("cancelled Run returned scripted output %q; the scripted result must not be consumed", res.Stdout)
	}
	if len(f.Calls()) != 1 {
		t.Errorf("Calls() = %d, want the attempted command recorded", len(f.Calls()))
	}
	// The scripted result is preserved for the next (non-cancelled) call.
	if res2, _ := f.Run(context.Background(), exec.Command{Name: "useradd"}); res2.Stdout != "should-not-be-returned" {
		t.Errorf("scripted result was wrongly consumed by the cancelled call: got %q", res2.Stdout)
	}
}

// CallContexts returns the context received with each recorded Command (1:1
// with Calls), so a test can assert every escalated call ran under a
// deadline-bounded context.
func TestFakeRunner_CallContextsRecorded(t *testing.T) {
	f := exectest.New(exec.Direct)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, _ = f.Run(ctx, exec.Command{Name: "true"})
	ctxs := f.CallContexts()
	if len(ctxs) != 1 {
		t.Fatalf("CallContexts() len = %d, want 1", len(ctxs))
	}
	if ctxs[0] != ctx {
		t.Errorf("CallContexts()[0] is not the ctx passed to Run")
	}
}

// Stream records the Command too and replays scripted stdout to the callback so
// streaming capabilities can be unit-tested.
func TestFakeRunner_StreamRecordsAndReplays(t *testing.T) {
	f := exectest.New(exec.Direct)
	f.Push(exec.Result{ExitCode: 0, Stdout: "line1\nline2\n"}, nil)

	var lines []string
	_, err := f.Stream(context.Background(), exec.Command{Name: "journalctl"},
		func(s exec.StreamType, line string, seq int64) {
			lines = append(lines, line)
		})
	if err != nil {
		t.Fatalf("Stream err = %v", err)
	}
	if len(f.Calls()) != 1 || f.Calls()[0].Name != "journalctl" {
		t.Errorf("Stream did not record the Command: %+v", f.Calls())
	}
	if len(lines) == 0 {
		t.Error("Stream replayed no lines to the callback")
	}
}
