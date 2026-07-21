//go:build policycontainer

package fsafe

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
)

func TestContainer_PolicyValidators(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("policy validator container must run as root")
	}
	for _, tool := range []string{"sshd", "visudo"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("required real validator %s is absent: %v", tool, err)
		}
	}
	runner, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(runner)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("visudo accepts candidate before publish", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		path := "/etc/sudoers.d/pm-sdk-policy-container-test"
		t.Cleanup(func() { _ = os.Remove(path) })
		content := []byte("%sudo ALL=(ALL:ALL) /usr/bin/id\n")
		result, err := m.ApplyPolicyFile(ctx, PolicyFileRequest{
			Surface: PolicySurfaceAdminPolicy,
			Path:    path,
			Desired: PolicyFileState{Presence: PolicyFilePresent, Content: content},
		})
		if err != nil {
			t.Fatalf("ApplyPolicyFile: %v", err)
		}
		got, readErr := os.ReadFile(path)
		if !result.Changed || readErr != nil || !slices.Equal(got, content) {
			t.Fatalf("published sudoers = (%q, %v, changed=%v), want %q", got, readErr, result.Changed, content)
		}
	})

	t.Run("sshd rejects candidate without touching live file", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		path := "/etc/ssh/sshd_config.d/0098-pm-sdk-policy-container-test.conf"
		t.Cleanup(func() { _ = os.Remove(path) })
		before := []byte("Port 22\n")
		if err := os.WriteFile(path, before, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := m.ApplyPolicyFile(ctx, PolicyFileRequest{
			Surface: PolicySurfaceSSHD,
			Path:    path,
			Desired: PolicyFileState{Presence: PolicyFilePresent, Content: []byte("NotARealDirective yes\n")},
		})
		if err == nil {
			t.Fatal("real sshd accepted invalid candidate")
		}
		var commandErr *pmexec.CommandError
		if !errors.As(err, &commandErr) || commandErr.Name != "sshd" {
			t.Fatalf("reject error = %v, want sshd CommandError proving the validator rejected the candidate", err)
		}
		got, readErr := os.ReadFile(path)
		if readErr != nil || !slices.Equal(got, before) {
			t.Fatalf("live sshd file = (%q, %v), want prior %q", got, readErr, before)
		}
	})

	t.Run("reload failure restores sshd bytes", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		path := "/etc/ssh/sshd_config.d/99-pm-sdk-policy-container-test.conf"
		t.Cleanup(func() { _ = os.Remove(path) })
		before := []byte("Port 22\n")
		if err := os.WriteFile(path, before, 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := m.ApplyPolicyFile(ctx, PolicyFileRequest{
			Surface: PolicySurfaceSSH,
			Path:    path,
			Desired: PolicyFileState{Presence: PolicyFilePresent, Content: []byte("Port 2222\n")},
		})
		if err == nil {
			t.Fatal("systemctl reload unexpectedly succeeded in the non-systemd test container")
		}
		var commandErr *pmexec.CommandError
		if !errors.As(err, &commandErr) || commandErr.Name != "systemctl" {
			t.Fatalf("reload error = %v, want systemctl CommandError proving sshd validation passed", err)
		}
		got, readErr := os.ReadFile(path)
		if readErr != nil || !slices.Equal(got, before) {
			t.Fatalf("restored sshd file = (%q, %v), want prior %q", got, readErr, before)
		}
	})
}
