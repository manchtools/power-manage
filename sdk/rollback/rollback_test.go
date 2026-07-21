package rollback

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRun_RollsBackAppliedStepsInReverseOrder(t *testing.T) {
	boom := errors.New("step three failed")
	var calls []string
	steps := []Step{
		{Name: "one", Apply: func(context.Context) error { calls = append(calls, "apply-one"); return nil }, Rollback: func(context.Context) error { calls = append(calls, "undo-one"); return nil }},
		{Name: "two", Apply: func(context.Context) error { calls = append(calls, "apply-two"); return nil }, Rollback: func(context.Context) error { calls = append(calls, "undo-two"); return nil }},
		{Name: "three", Apply: func(context.Context) error { calls = append(calls, "apply-three"); return boom }, Rollback: func(context.Context) error { calls = append(calls, "undo-three"); return nil }},
	}
	if err := Run(context.Background(), steps...); !errors.Is(err, boom) {
		t.Fatalf("Run error = %v, want original failure", err)
	}
	want := []string{"apply-one", "apply-two", "apply-three", "undo-two", "undo-one"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
}

func TestRun_JoinsRollbackFailures(t *testing.T) {
	applyErr := errors.New("apply failed")
	undoErr := errors.New("undo failed")
	err := Run(context.Background(),
		Step{Name: "one", Apply: func(context.Context) error { return nil }, Rollback: func(context.Context) error { return undoErr }},
		Step{Name: "two", Apply: func(context.Context) error { return applyErr }, Rollback: func(context.Context) error { return nil }},
	)
	if !errors.Is(err, applyErr) || !errors.Is(err, undoErr) {
		t.Fatalf("Run error = %v, want both apply and rollback failures", err)
	}
	if !strings.Contains(err.Error(), "one") || !strings.Contains(err.Error(), "two") {
		t.Fatalf("Run error = %q, want both step names", err)
	}
}

func TestRun_RejectsIncompleteStepBeforeApplying(t *testing.T) {
	called := false
	err := Run(context.Background(),
		Step{Name: "one", Apply: func(context.Context) error { called = true; return nil }, Rollback: func(context.Context) error { return nil }},
		Step{Name: "two", Apply: func(context.Context) error { return nil }},
	)
	if err == nil {
		t.Fatal("Run accepted a step without rollback")
	}
	if called {
		t.Fatal("Run applied a step before validating the full sequence")
	}
}

func TestRun_RejectsNilContext(t *testing.T) {
	//lint:ignore SA1012 the exported boundary must reject a hostile nil context
	if err := Run(nil); err == nil {
		t.Fatal("Run accepted a nil context")
	}
}

func TestRun_GivesEachRollbackAFreshDeadline(t *testing.T) {
	originalTimeout := compensationTimeout
	compensationTimeout = 100 * time.Millisecond
	t.Cleanup(func() { compensationTimeout = originalTimeout })
	laterRan := false
	err := Run(context.Background(),
		Step{Name: "one", Apply: func(context.Context) error { return nil }, Rollback: func(ctx context.Context) error {
			laterRan = ctx.Err() == nil
			return nil
		}},
		Step{Name: "two", Apply: func(context.Context) error { return nil }, Rollback: func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		}},
		Step{Name: "three", Apply: func(context.Context) error { return errors.New("fail") }, Rollback: func(context.Context) error { return nil }},
	)
	if err == nil || !laterRan {
		t.Fatalf("Run error = %v, later rollback received no fresh deadline", err)
	}
}
