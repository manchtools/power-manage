package validate

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestLUKSDevicePath_Accepts(t *testing.T) {
	for _, in := range []string{
		"/dev/sda2", "/dev/nvme0n1p3", "/dev/mapper/cryptroot",
		"/dev/disk/by-uuid/1234-abcd", "/dev/disk/by-partlabel/root",
	} {
		assertAccept(t, LUKSDevicePath, in)
	}
}

func TestLUKSDevicePath_Rejects(t *testing.T) {
	for _, in := range []string{
		"", "sda2", "-rf", "/etc/shadow", "/dev/../etc/shadow",
		"/dev/sd a", "/dev/sda\n", "/dev/sda;reboot", "/dev/mapper/../../etc",
	} {
		assertReject(t, LUKSDevicePath, in)
	}
}

func TestFlatpakAppID_Accepts(t *testing.T) {
	for _, in := range []string{
		"org.videolan.VLC",
		"com.github.tchx84.Flatseal",
		"io.github.some-user.App", // hyphens are legitimate in flatpak IDs
		"org.freedesktop.Platform.GL.default",
		"_leading.Underscore",
	} {
		assertAccept(t, FlatpakAppID, in)
	}
}

func TestFlatpakAppID_Rejects(t *testing.T) {
	for _, in := range []string{
		"",
		"VLC",                           // single element — not reverse-DNS
		"org.videolan.VLC/x86_64",       // slash → path-join escape
		"../org.x",                      // traversal
		"org..x",                        // empty element
		"1org.videolan.VLC",             // element starts with a digit
		"org.videolan.VLC\n",            // control char
		"org.9videolan.VLC",             // middle element starts with a digit
		"org.videolan.",                 // trailing empty element
		strings.Repeat("a.", 128) + "b", // 257 chars, > 255 cap
	} {
		assertReject(t, FlatpakAppID, in)
	}
}

// LoginShell membership is checked against /etc/shells through the
// readLoginShells seam; the tests stub it so the check is host-independent.
func withLoginShells(t *testing.T, shells []string, err error) {
	t.Helper()
	restore := readLoginShells
	readLoginShells = func() ([]string, error) { return shells, err }
	t.Cleanup(func() { readLoginShells = restore })
}

func TestLoginShell_AcceptsListedShell(t *testing.T) {
	withLoginShells(t, []string{"/bin/bash", "/bin/sh", "/usr/bin/zsh"}, nil)
	assertAccept(t, LoginShell, "/bin/bash")
	assertAccept(t, LoginShell, "/usr/bin/zsh")
}

func TestLoginShell_RejectsUnlistedShell(t *testing.T) {
	withLoginShells(t, []string{"/bin/sh"}, nil)
	// A perfectly-shaped absolute path that is simply not an approved shell.
	assertReject(t, LoginShell, "/bin/bash")
}

func TestLoginShell_RejectsRelativeOrControl(t *testing.T) {
	withLoginShells(t, []string{"/bin/bash"}, nil)
	assertReject(t, LoginShell, "bash")       // relative
	assertReject(t, LoginShell, "/bin/sh\nx") // control char
}

// Fail closed: an unreadable /etc/shells must REJECT every shell, never
// accept — a missing allow-list can't be read as "anything goes".
func TestLoginShell_FailsClosedWhenShellsUnreadable(t *testing.T) {
	withLoginShells(t, nil, fmt.Errorf("permission denied"))
	err := LoginShell("/bin/bash")
	if err == nil {
		t.Fatal("accepted a shell when /etc/shells was unreadable, want fail-closed rejection")
	}
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("fail-closed rejection was %v, want ErrInvalid-wrapped", err)
	}
}
