package enroll

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestRelay_SocketModeAndFivePerMinuteLimit(t *testing.T) {
	allowRelayTestParent(t)
	path := filepath.Join(t.TempDir(), "enroll.sock")
	enroller := &countingEnroller{}
	relay, err := NewRelay(enroller)
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- relay.Serve(ctx, path) }()
	waitForEnrollmentSocket(t, path)
	info, err := os.Lstat(path)
	if err != nil {
		cancel()
		t.Fatalf("lstat enrollment socket: %v", err)
	}
	if info.Mode().Type() != os.ModeSocket || info.Mode().Perm() != 0o666 {
		cancel()
		t.Fatalf("enrollment socket mode = %v; want socket 0666", info.Mode())
	}

	for attempt := 1; attempt <= 6; attempt++ {
		deviceID, err := Submit(ctx, path, "registration-token", "")
		if attempt <= 5 {
			if err != nil || deviceID != enrolledClientDeviceID {
				cancel()
				t.Fatalf("attempt %d = (%q, %v); want successful enrollment", attempt, deviceID, err)
			}
			continue
		}
		if !errors.Is(err, ErrLocalRateLimited) {
			cancel()
			t.Fatalf("sixth attempt error = %v; want local rate limit", err)
		}
	}
	if got := enroller.Calls(); got != 5 {
		cancel()
		t.Fatalf("enroller calls = %d; want five", got)
	}

	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("relay cancellation error = %v; want context canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not stop after cancellation")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("relay socket after shutdown = %v; want removed", err)
	}
}

func TestRelay_ReplacesOnlyStaleSocketEntries(t *testing.T) {
	allowRelayTestParent(t)
	t.Run("live socket", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "enroll.sock")
		address, err := net.ResolveUnixAddr("unix", path)
		if err != nil {
			t.Fatalf("resolve live socket: %v", err)
		}
		live, err := net.ListenUnix("unix", address)
		if err != nil {
			t.Fatalf("create live socket: %v", err)
		}
		defer func() { _ = live.Close() }()
		if err := removeStaleSocket(path); err == nil || !strings.Contains(err.Error(), "active") {
			t.Fatalf("live socket removal error = %v; want active-socket refusal", err)
		}
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("live socket path was removed: %v", err)
		}
	})

	t.Run("stale socket", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "enroll.sock")
		address, err := net.ResolveUnixAddr("unix", path)
		if err != nil {
			t.Fatalf("resolve stale socket: %v", err)
		}
		stale, err := net.ListenUnix("unix", address)
		if err != nil {
			t.Fatalf("create stale socket: %v", err)
		}
		stale.SetUnlinkOnClose(false)
		if err := stale.Close(); err != nil {
			t.Fatalf("close stale socket: %v", err)
		}
		relay, err := NewRelay(&countingEnroller{})
		if err != nil {
			t.Fatalf("NewRelay: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() { result <- relay.Serve(ctx, path) }()
		waitForEnrollmentSocket(t, path)
		cancel()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("relay cancellation error = %v; want context canceled", err)
		}
	})

	for _, entry := range []struct {
		name   string
		create func(*testing.T, string)
		want   string
	}{
		{name: "regular file", create: func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
				t.Fatalf("write regular socket fixture: %v", err)
			}
		}, want: "not a socket"},
		{name: "symlink", create: func(t *testing.T, path string) {
			if err := os.Symlink(filepath.Join(filepath.Dir(path), "target"), path); err != nil {
				t.Fatalf("create socket symlink fixture: %v", err)
			}
		}, want: "not a socket"},
	} {
		t.Run(entry.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "enroll.sock")
			entry.create(t, path)
			relay, err := NewRelay(&countingEnroller{})
			if err != nil {
				t.Fatalf("NewRelay: %v", err)
			}
			err = relay.Serve(context.Background(), path)
			if err == nil || !strings.Contains(err.Error(), entry.want) {
				t.Fatalf("Serve error = %v; want category %q", err, entry.want)
			}
		})
	}
}

func TestRelay_BoundsEachEnrollmentWithADeadline(t *testing.T) {
	allowRelayTestParent(t)
	path := filepath.Join(t.TempDir(), "enroll.sock")
	relay, err := NewRelay(deadlineEnroller{})
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- relay.Serve(ctx, path) }()
	waitForEnrollmentSocket(t, path)
	if _, err := Submit(context.Background(), path, "registration-token", ""); err != nil {
		cancel()
		t.Fatalf("deadline-bounded enrollment: %v", err)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("relay cancellation error = %v; want context canceled", err)
	}
}

func TestRelay_RefusesWritableSocketParent(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatalf("make socket parent writable: %v", err)
	}
	original := relayParentSafe
	relayParentSafe = func(path string) error {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat == nil {
			return errors.New("test parent ownership is unavailable")
		}
		rootStat := *stat
		rootStat.Uid = 0
		if err := validateRelayParentInfo(rootOwnedRelayParentInfo{FileInfo: info, stat: &rootStat}); err != nil {
			return fmt.Errorf("enroll: relay socket parent is unsafe: %s: %w", path, err)
		}
		return nil
	}
	t.Cleanup(func() { relayParentSafe = original })
	relay, err := NewRelay(&countingEnroller{})
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = relay.Serve(ctx, filepath.Join(directory, "enroll.sock"))
	if err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("writable-parent Serve error = %v; want unsafe-parent refusal", err)
	}
}

type rootOwnedRelayParentInfo struct {
	os.FileInfo
	stat *syscall.Stat_t
}

func (i rootOwnedRelayParentInfo) Sys() any { return i.stat }

func TestSubmit_RejectsTrailingLocalResponse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "enroll.sock")
	address, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		t.Fatalf("resolve response fixture socket: %v", err)
	}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		t.Fatalf("listen for response fixture: %v", err)
	}
	defer func() { _ = listener.Close() }()
	serverResult := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			serverResult <- err
			return
		}
		defer func() { _ = connection.Close() }()
		if _, err := io.ReadAll(connection); err != nil {
			serverResult <- err
			return
		}
		_, err = io.WriteString(connection, `{"device_id":"`+enrolledClientDeviceID+`"}{}`)
		serverResult <- err
	}()
	_, err = Submit(context.Background(), path, "registration-token", "")
	if !errors.Is(err, errLocalTrailingData) {
		t.Fatalf("Submit trailing-response error = %v; want trailing-data rejection", err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("serve trailing response fixture: %v", err)
	}
}

type countingEnroller struct {
	mu    sync.Mutex
	calls int
}

type deadlineEnroller struct{}

func (deadlineEnroller) Enroll(ctx context.Context, _, _ string) (string, error) {
	if _, ok := ctx.Deadline(); !ok {
		return "", errors.New("enrollment context has no deadline")
	}
	return enrolledClientDeviceID, nil
}

func (e *countingEnroller) Enroll(context.Context, string, string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	return enrolledClientDeviceID, nil
}

func (e *countingEnroller) Calls() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

func waitForEnrollmentSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		info, err := os.Lstat(path)
		if err == nil && info.Mode().Type() == os.ModeSocket {
			return
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("wait for enrollment socket: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for enrollment socket")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func allowRelayTestParent(t *testing.T) {
	t.Helper()
	original := relayParentSafe
	relayParentSafe = func(string) error { return nil }
	t.Cleanup(func() { relayParentSafe = original })
}
