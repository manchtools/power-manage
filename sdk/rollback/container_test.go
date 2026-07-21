//go:build container

package rollback_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/fsafe"
	"github.com/manchtools/power-manage/sdk/rollback"
)

func TestContainer_RollbackRestoresPreState(t *testing.T) {
	runner, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatal(err)
	}
	files, err := fsafe.New(runner)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.conf")
	created := filepath.Join(dir, "created.conf")
	if err := os.WriteFile(existing, []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cause := errors.New("third step failed")
	err = rollback.Run(context.Background(),
		rollback.Step{
			Name: "replace existing",
			Apply: func(ctx context.Context) error {
				return files.WriteFile(ctx, existing, []byte("after\n"), fsafe.WriteOptions{Mode: 0o600})
			},
			Rollback: func(ctx context.Context) error {
				return files.WriteFile(ctx, existing, []byte("before\n"), fsafe.WriteOptions{Mode: 0o600})
			},
		},
		rollback.Step{
			Name: "create new",
			Apply: func(ctx context.Context) error {
				return files.WriteFile(ctx, created, []byte("new\n"), fsafe.WriteOptions{Mode: 0o600})
			},
			Rollback: func(ctx context.Context) error { return files.Remove(ctx, created) },
		},
		rollback.Step{
			Name:     "fail",
			Apply:    func(context.Context) error { return cause },
			Rollback: func(context.Context) error { return nil },
		},
	)
	if !errors.Is(err, cause) {
		t.Fatalf("Run error = %v, want original failure", err)
	}
	got, err := os.ReadFile(existing)
	if err != nil || string(got) != "before\n" {
		t.Fatalf("existing pre-state = (%q, %v), want before", got, err)
	}
	if _, err := os.Stat(created); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("created path survived rollback: %v", err)
	}
}
