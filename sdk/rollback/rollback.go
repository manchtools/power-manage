// Package rollback applies compensatable system steps atomically from the
// caller's perspective: a later failure unwinds every completed step in reverse
// order and reports both the original and any compensation failures.
package rollback

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var compensationTimeout = 30 * time.Second

// Step is one system mutation and the compensation that restores its pre-state.
type Step struct {
	Name     string
	Apply    func(context.Context) error
	Rollback func(context.Context) error
}

// Run applies steps in order. A failed step is not rolled back because it did
// not report success; every earlier successful step is compensated in reverse.
func Run(ctx context.Context, steps ...Step) error {
	if ctx == nil {
		return errors.New("rollback: context is required")
	}
	for i, step := range steps {
		if step.Name == "" || step.Apply == nil || step.Rollback == nil {
			return fmt.Errorf("rollback: step %d requires name, apply, and rollback", i+1)
		}
	}
	for i, step := range steps {
		if err := step.Apply(ctx); err != nil {
			cause := fmt.Errorf("%s: %w", step.Name, err)
			if i == 0 {
				return cause
			}
			errs := []error{cause}
			for j := i - 1; j >= 0; j-- {
				rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), compensationTimeout)
				if undoErr := steps[j].Rollback(rollbackCtx); undoErr != nil {
					errs = append(errs, fmt.Errorf("rollback %s: %w", steps[j].Name, undoErr))
				}
				cancel()
			}
			return errors.Join(errs...)
		}
	}
	return nil
}
