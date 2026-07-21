//go:build linux

package fsafe

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/exec/exectest"
)

func newPolicyManager(t *testing.T) (*exectest.FakeRunner, Manager) {
	t.Helper()
	fr := exectest.New(pmexec.Direct)
	m, err := New(fr)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	originalParentDirSafe := parentDirSafe
	parentDirSafe = func(string) error { return nil }
	originalPolicyRootFor := policyRootFor
	root := t.TempDir()
	policyRootFor = func(policyPathClass) string { return root }
	t.Cleanup(func() {
		parentDirSafe = originalParentDirSafe
		policyRootFor = originalPolicyRootFor
	})
	return fr, m
}

func policyTarget(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(policyRootFor(policyPathSudoers), name)
}

func presentPolicy(surface PolicySurface, path string, content string) PolicyFileRequest {
	return PolicyFileRequest{
		Surface: surface,
		Path:    path,
		Desired: PolicyFileState{Presence: PolicyFilePresent, Content: []byte(content)},
	}
}

func TestApplyPolicyFile_HashEqualNoOp(t *testing.T) {
	fr, m := newPolicyManager(t)
	path := policyTarget(t, "admin")
	if err := os.WriteFile(path, []byte("same\n"), 0o440); err != nil {
		t.Fatal(err)
	}

	got, err := m.ApplyPolicyFile(context.Background(), presentPolicy(PolicySurfaceAdminPolicy, path, "same\n"))
	if err != nil {
		t.Fatalf("ApplyPolicyFile: %v", err)
	}
	if got.Changed {
		t.Fatal("hash-equal content reported changed=true")
	}
	if len(fr.Calls()) != 0 {
		t.Fatalf("no-op ran commands: %+v", fr.Calls())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("no-op left candidate files: %+v", entries)
	}
}

func TestApplyPolicyFile_ValidatorFailureNeverReachesLivePath(t *testing.T) {
	fr, m := newPolicyManager(t)
	path := policyTarget(t, "ssh.conf")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fr.Push(pmexec.Result{ExitCode: 1, Stderr: "bad ssh config"}, nil)

	_, err := m.ApplyPolicyFile(context.Background(), presentPolicy(PolicySurfaceSSH, path, "bad\n"))
	if err == nil || !strings.Contains(err.Error(), "bad ssh config") {
		t.Fatalf("validator error = %v, want bad ssh config detail", err)
	}
	if got, readErr := os.ReadFile(path); readErr != nil || string(got) != "old\n" {
		t.Fatalf("live content after validator failure = (%q, %v), want old", got, readErr)
	}
	calls := fr.Calls()
	if len(calls) != 1 {
		t.Fatalf("validator failure calls = %+v, want only sshd", calls)
	}
	candidate := calls[0].Args[len(calls[0].Args)-1]
	if calls[0].Name != "sshd" || !slices.Equal(calls[0].Args[:2], []string{"-t", "-f"}) {
		t.Fatalf("validator = %s %q, want sshd [-t -f <candidate>]", calls[0].Name, calls[0].Args)
	}
	if candidate == path || filepath.Dir(candidate) != filepath.Dir(path) {
		t.Fatalf("validator candidate = %q, want random sibling of %q", candidate, path)
	}
	if _, statErr := os.Stat(candidate); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("failed candidate survived cleanup: %v", statErr)
	}
}

func TestApplyPolicyFile_ReloadFailureRestoresPreviousBytes(t *testing.T) {
	fr, m := newPolicyManager(t)
	path := policyTarget(t, "0050-sshd.conf")
	before := []byte("Port 22\n")
	if err := os.WriteFile(path, before, 0o644); err != nil {
		t.Fatal(err)
	}
	fr.Push(pmexec.Result{}, nil) // candidate validator
	fr.Push(pmexec.Result{ExitCode: 1, Stderr: "reload failed"}, nil)

	_, err := m.ApplyPolicyFile(context.Background(), presentPolicy(PolicySurfaceSSHD, path, "Port 2222\n"))
	if err == nil || !strings.Contains(err.Error(), "reload failed") {
		t.Fatalf("reload error = %v, want reload failed detail", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || !slices.Equal(got, before) {
		t.Fatalf("restored bytes = (%q, %v), want %q", got, readErr, before)
	}
	calls := fr.Calls()
	if len(calls) != 2 {
		t.Fatalf("calls = %+v, want validator then reload", calls)
	}
	if calls[0].Name != "sshd" || calls[1].Name != "systemctl" || !slices.Equal(calls[1].Args, []string{"reload", "sshd"}) {
		t.Fatalf("sequence = %+v, want sshd validate then systemctl reload sshd", calls)
	}
}

func TestApplyPolicyFile_SwapEffectThenErrorRestoresPreviousBytes(t *testing.T) {
	_, m := newPolicyManager(t)
	path := policyTarget(t, "admin")
	before := []byte("old\n")
	if err := os.WriteFile(path, before, 0o440); err != nil {
		t.Fatal(err)
	}
	cause := errors.New("swap result lost")
	originalPolicySwapRename := policySwapRename
	policySwapRename = func(oldPath, newPath string, removeExisting bool) error {
		if err := safeRename(oldPath, newPath, removeExisting); err != nil {
			return err
		}
		return cause
	}
	t.Cleanup(func() { policySwapRename = originalPolicySwapRename })

	_, err := m.ApplyPolicyFile(context.Background(), presentPolicy(PolicySurfaceAdminPolicy, path, "new\n"))
	if !errors.Is(err, cause) {
		t.Fatalf("err = %v, want effect-then-error cause", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || !slices.Equal(got, before) {
		t.Fatalf("restored bytes = (%q, %v), want %q", got, readErr, before)
	}
}

func TestApplyPolicyFile_RevertReplaysPriorThroughValidator(t *testing.T) {
	fr, m := newPolicyManager(t)
	path := policyTarget(t, "admin")
	if err := os.WriteFile(path, []byte("old\n"), 0o440); err != nil {
		t.Fatal(err)
	}

	applied, err := m.ApplyPolicyFile(context.Background(), presentPolicy(PolicySurfaceAdminPolicy, path, "new\n"))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !applied.Changed || applied.Previous.Presence != PolicyFilePresent || string(applied.Previous.Content) != "old\n" {
		t.Fatalf("apply result = %+v, want changed with old snapshot", applied)
	}

	reverted, err := m.ApplyPolicyFile(context.Background(), PolicyFileRequest{
		Surface: PolicySurfaceAdminPolicy,
		Path:    path,
		Desired: applied.Previous,
	})
	if err != nil {
		t.Fatalf("revert: %v", err)
	}
	if !reverted.Changed {
		t.Fatal("revert reported changed=false")
	}
	if got, readErr := os.ReadFile(path); readErr != nil || string(got) != "old\n" {
		t.Fatalf("reverted content = (%q, %v), want old", got, readErr)
	}
	calls := fr.Calls()
	if len(calls) != 2 {
		t.Fatalf("validator calls = %+v, want one for apply and one for revert", calls)
	}
	for i, call := range calls {
		if call.Name != "visudo" || len(call.Args) != 3 || call.Args[0] != "-c" || call.Args[1] != "-f" || call.Args[2] == path {
			t.Errorf("validator call %d = %s %q, want visudo -c -f <candidate>", i, call.Name, call.Args)
		}
	}
}

func TestApplyPolicyFile_RevertToAbsentUsesValidator(t *testing.T) {
	fr, m := newPolicyManager(t)
	path := policyTarget(t, "admin")

	applied, err := m.ApplyPolicyFile(context.Background(), presentPolicy(PolicySurfaceAdminPolicy, path, "rule\n"))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if applied.Previous.Presence != PolicyFileAbsent {
		t.Fatalf("previous presence = %v, want absent", applied.Previous.Presence)
	}
	if _, err := m.ApplyPolicyFile(context.Background(), PolicyFileRequest{
		Surface: PolicySurfaceAdminPolicy,
		Path:    path,
		Desired: applied.Previous,
	}); err != nil {
		t.Fatalf("revert absent: %v", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("target survived absent revert: %v", statErr)
	}
	if calls := fr.Calls(); len(calls) != 2 || calls[0].Name != "visudo" || calls[1].Name != "visudo" {
		t.Fatalf("apply/revert validators = %+v, want visudo twice", calls)
	}
}

func TestApplyPolicyFile_ManagedBlockReplacesMarkedRegion(t *testing.T) {
	_, m := newPolicyManager(t)
	path := policyTarget(t, "admin")
	before := "header\n# BEGIN PM\nold\n# END PM\ntail\n"
	if err := os.WriteFile(path, []byte(before), 0o440); err != nil {
		t.Fatal(err)
	}

	result, err := m.ApplyPolicyFile(context.Background(), PolicyFileRequest{
		Surface: PolicySurfaceAdminPolicy,
		Path:    path,
		Desired: PolicyFileState{
			Presence: PolicyFilePresent,
			Content:  []byte("new\nvalue\n"),
			Block:    &PolicyManagedBlock{Begin: "# BEGIN PM", End: "# END PM"},
		},
	})
	if err != nil {
		t.Fatalf("ApplyPolicyFile: %v", err)
	}
	if !result.Changed || string(result.Previous.Content) != before {
		t.Fatalf("result = %+v, want changed with exact previous bytes", result)
	}
	want := "header\n# BEGIN PM\nnew\nvalue\n# END PM\ntail\n"
	if got, readErr := os.ReadFile(path); readErr != nil || string(got) != want {
		t.Fatalf("managed file = (%q, %v), want %q", got, readErr, want)
	}
}

func TestApplyPolicyFile_MalformedManagedBlockRefusedBeforeMutation(t *testing.T) {
	tests := map[string]string{
		"missing end":     "header\n# BEGIN PM\nold\n",
		"duplicate begin": "# BEGIN PM\nold\n# BEGIN PM\nmore\n# END PM\n",
	}
	for name, before := range tests {
		t.Run(name, func(t *testing.T) {
			fr, m := newPolicyManager(t)
			path := policyTarget(t, "admin")
			if err := os.WriteFile(path, []byte(before), 0o440); err != nil {
				t.Fatal(err)
			}
			_, err := m.ApplyPolicyFile(context.Background(), PolicyFileRequest{
				Surface: PolicySurfaceAdminPolicy,
				Path:    path,
				Desired: PolicyFileState{
					Presence: PolicyFilePresent,
					Content:  []byte("new\n"),
					Block:    &PolicyManagedBlock{Begin: "# BEGIN PM", End: "# END PM"},
				},
			})
			if !errors.Is(err, ErrInvalidPolicyFile) {
				t.Fatalf("err = %v, want ErrInvalidPolicyFile", err)
			}
			if got, readErr := os.ReadFile(path); readErr != nil || string(got) != before {
				t.Fatalf("live content changed = (%q, %v), want %q", got, readErr, before)
			}
			if len(fr.Calls()) != 0 {
				t.Fatalf("malformed block ran commands: %+v", fr.Calls())
			}
		})
	}
}

func TestApplyPolicyFile_ManagedContentCannotInjectMarkers(t *testing.T) {
	fr, m := newPolicyManager(t)
	path := policyTarget(t, "admin")
	if err := os.WriteFile(path, []byte("base\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	_, err := m.ApplyPolicyFile(context.Background(), PolicyFileRequest{
		Surface: PolicySurfaceAdminPolicy,
		Path:    path,
		Desired: PolicyFileState{
			Presence: PolicyFilePresent,
			Content:  []byte("value\n# BEGIN PM\nother\n"),
			Block:    &PolicyManagedBlock{Begin: "# BEGIN PM", End: "# END PM"},
		},
	})
	if !errors.Is(err, ErrInvalidPolicyFile) {
		t.Fatalf("err = %v, want ErrInvalidPolicyFile", err)
	}
	if got, readErr := os.ReadFile(path); readErr != nil || string(got) != "base\n" {
		t.Fatalf("live content changed = (%q, %v), want base", got, readErr)
	}
	if len(fr.Calls()) != 0 {
		t.Fatalf("marker injection ran commands: %+v", fr.Calls())
	}
}

func TestApplyPolicyFile_ManagedMarkersMustBeComments(t *testing.T) {
	tests := []struct {
		name    string
		surface PolicySurface
		begin   string
		end     string
	}{
		{name: "sshd directive", surface: PolicySurfaceSSHD, begin: "PermitRootLogin yes", end: "# END PM"},
		{name: "sudoers rule", surface: PolicySurfaceAdminPolicy, begin: "%wheel ALL=(ALL) NOPASSWD: ALL", end: "# END PM"},
		{name: "sudoers include", surface: PolicySurfaceAdminPolicy, begin: "#include /etc/sudoers.d/extra", end: "# END PM"},
		{name: "sudoers includedir", surface: PolicySurfaceAdminPolicy, begin: "#includedir /etc/sudoers.d", end: "# END PM"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fr, m := newPolicyManager(t)
			name := "policy"
			if tt.surface == PolicySurfaceSSHD {
				name = "0050-policy.conf"
			}
			path := policyTarget(t, name)
			_, err := m.ApplyPolicyFile(context.Background(), PolicyFileRequest{
				Surface: tt.surface,
				Path:    path,
				Desired: PolicyFileState{
					Presence: PolicyFilePresent,
					Content:  []byte("value\n"),
					Block:    &PolicyManagedBlock{Begin: tt.begin, End: tt.end},
				},
			})
			if !errors.Is(err, ErrInvalidPolicyFile) {
				t.Fatalf("err = %v, want ErrInvalidPolicyFile", err)
			}
			if len(fr.Calls()) != 0 {
				t.Fatalf("active marker ran commands: %+v", fr.Calls())
			}
		})
	}
}

func TestApplyPolicyFile_PathClassAndSymlinkLeafRefused(t *testing.T) {
	t.Run("wrong directory", func(t *testing.T) {
		fr, m := newPolicyManager(t)
		wrong := filepath.Join(t.TempDir(), "admin")
		_, err := m.ApplyPolicyFile(context.Background(), presentPolicy(PolicySurfaceAdminPolicy, wrong, "rule\n"))
		if !errors.Is(err, ErrInvalidPolicyFile) {
			t.Fatalf("err = %v, want ErrInvalidPolicyFile", err)
		}
		if len(fr.Calls()) != 0 {
			t.Fatalf("wrong path class ran commands: %+v", fr.Calls())
		}
	})

	t.Run("final symlink", func(t *testing.T) {
		fr, m := newPolicyManager(t)
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte("victim\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		path := policyTarget(t, "admin")
		if err := os.Symlink(victim, path); err != nil {
			t.Fatal(err)
		}
		_, err := m.ApplyPolicyFile(context.Background(), presentPolicy(PolicySurfaceAdminPolicy, path, "rule\n"))
		if !errors.Is(err, ErrInvalidPolicyFile) {
			t.Fatalf("err = %v, want ErrInvalidPolicyFile", err)
		}
		if got, readErr := os.ReadFile(victim); readErr != nil || string(got) != "victim\n" {
			t.Fatalf("symlink victim changed = (%q, %v)", got, readErr)
		}
		if len(fr.Calls()) != 0 {
			t.Fatalf("symlink leaf ran commands: %+v", fr.Calls())
		}
	})
}

func TestApplyPolicyFile_IneffectiveDropInFilenameRefused(t *testing.T) {
	tests := []struct {
		name    string
		surface PolicySurface
		file    string
	}{
		{name: "ssh missing conf", surface: PolicySurfaceSSH, file: "pm-ssh-policy"},
		{name: "sudoers dot ignored", surface: PolicySurfaceAdminPolicy, file: "pm-policy.conf"},
		{name: "sudoers backup ignored", surface: PolicySurfaceAdminPolicy, file: "pm-policy~"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fr, m := newPolicyManager(t)
			path := policyTarget(t, tt.file)
			_, err := m.ApplyPolicyFile(context.Background(), presentPolicy(tt.surface, path, "value\n"))
			if !errors.Is(err, ErrInvalidPolicyFile) {
				t.Fatalf("err = %v, want ErrInvalidPolicyFile", err)
			}
			if len(fr.Calls()) != 0 {
				t.Fatalf("ineffective filename ran commands: %+v", fr.Calls())
			}
		})
	}
}

func TestApplyPolicyFile_SSHDAllowsSafeConfFilenames(t *testing.T) {
	for _, name := range []string{"pm-policy.conf", "50-pm-policy.conf", "10000-pm-policy.conf"} {
		t.Run(name, func(t *testing.T) {
			fr, m := newPolicyManager(t)
			path := policyTarget(t, name)

			result, err := m.ApplyPolicyFile(context.Background(), presentPolicy(PolicySurfaceSSHD, path, "Port 2222\n"))
			if err != nil {
				t.Fatalf("ApplyPolicyFile: %v", err)
			}
			if !result.Changed {
				t.Fatal("ApplyPolicyFile reported changed=false")
			}
			calls := fr.Calls()
			if len(calls) != 2 || calls[0].Name != "sshd" || calls[1].Name != "systemctl" {
				t.Fatalf("calls = %+v, want sshd validation followed by systemctl reload", calls)
			}
		})
	}
}

func TestApplyPolicyFile_InvalidRequestRefusedBeforeMutation(t *testing.T) {
	tests := []PolicyFileRequest{
		{},
		{Surface: PolicySurfaceAdminPolicy, Path: "/tmp/x", Desired: PolicyFileState{}},
		{Surface: PolicySurfaceAdminPolicy, Path: "/tmp/x", Desired: PolicyFileState{Presence: PolicyFileAbsent, Content: []byte("hidden")}},
		{Surface: PolicySurfaceAdminPolicy, Path: "/tmp/x", Desired: PolicyFileState{Presence: PolicyFilePresent, Block: &PolicyManagedBlock{Begin: "# BEGIN\nINJECT", End: "# END"}}},
	}
	for i, req := range tests {
		fr, m := newPolicyManager(t)
		if _, err := m.ApplyPolicyFile(context.Background(), req); !errors.Is(err, ErrInvalidPolicyFile) {
			t.Errorf("case %d error = %v, want ErrInvalidPolicyFile for %+v", i, err, req)
		}
		if len(fr.Calls()) != 0 {
			t.Errorf("case %d ran commands: %+v", i, fr.Calls())
		}
	}
}

func TestPolicySurfaceTable_ExactRows(t *testing.T) {
	if len(policySurfaceTable) != 3 {
		t.Fatalf("surface rows = %d, want exactly 3", len(policySurfaceTable))
	}
	want := []policySurfaceSpec{
		{policyPathSSHDPerAction, policyValidatorSSHD, policyReloadSSHD},
		{policyPathSSHDGlobal, policyValidatorSSHD, policyReloadSSHD},
		{policyPathSudoers, policyValidatorVisudo, policyReloadNone},
	}
	if !slices.Equal(policySurfaceTable[:], want) {
		t.Fatalf("surface table = %+v, want %+v", policySurfaceTable, want)
	}
	for i, row := range policySurfaceTable {
		if row.path == 0 || row.validator == 0 || row.reload == 0 {
			t.Errorf("row %d has a missing required column: %+v", i, row)
		}
	}
}

func TestApplyPolicyFile_ManagedBlockDoesNotStrandOldContent(t *testing.T) {
	_, m := newPolicyManager(t)
	path := policyTarget(t, "admin")
	if err := os.WriteFile(path, []byte("base\n"), 0o440); err != nil {
		t.Fatal(err)
	}
	req := PolicyFileRequest{
		Surface: PolicySurfaceAdminPolicy,
		Path:    path,
		Desired: PolicyFileState{
			Presence: PolicyFilePresent,
			Block:    &PolicyManagedBlock{Begin: "# BEGIN PM", End: "# END PM"},
		},
	}
	req.Desired.Content = []byte("first\n")
	if _, err := m.ApplyPolicyFile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	req.Desired.Content = []byte("second\n")
	if _, err := m.ApplyPolicyFile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "first") || strings.Count(string(got), "# BEGIN PM") != 1 {
		t.Fatalf("old managed content stranded: %q", got)
	}
}

func TestApplyPolicyFile_EscalatedCandidateAndSwapArgv(t *testing.T) {
	fr, m := newEscalatedManager(t)
	originalPolicyRootFor := policyRootFor
	policyRootFor = func(policyPathClass) string { return "/etc" }
	t.Cleanup(func() { policyRootFor = originalPolicyRootFor })
	target := "/etc/pm-admin-policy"
	candidate := "/etc/.pm-policy-A1b2C3d4E5"
	fr.Push(pmexec.Result{Stdout: "old\n"}, nil)          // cat live
	fr.Push(pmexec.Result{Stdout: candidate + "\n"}, nil) // candidate shell
	fr.Push(pmexec.Result{}, nil)                         // visudo
	fr.Push(pmexec.Result{}, nil)                         // mv

	result, err := m.ApplyPolicyFile(context.Background(), presentPolicy(PolicySurfaceAdminPolicy, target, "new\n"))
	if err != nil {
		t.Fatalf("ApplyPolicyFile: %v", err)
	}
	if !result.Changed || string(result.Previous.Content) != "old\n" {
		t.Fatalf("result = %+v, want changed with old snapshot", result)
	}
	calls := mustCalls(t, fr, 4)
	if calls[1].Name != "sh" || len(calls[1].Args) != 5 || calls[1].Args[0] != "-c" || calls[1].Args[1] != policyCandidateScript || calls[1].Args[3] != target || calls[1].Args[4] != "0440" {
		t.Fatalf("candidate writer = %s %q, want exact shell + positional target/mode", calls[1].Name, calls[1].Args)
	}
	data, err := io.ReadAll(calls[1].Stdin)
	if err != nil || string(data) != "new\n" {
		t.Fatalf("candidate stdin = (%q, %v), want new content", data, err)
	}
	for _, arg := range calls[1].Args {
		if strings.Contains(arg, "new") {
			t.Fatalf("content leaked into candidate argv: %q", calls[1].Args)
		}
	}
	if calls[2].Name != "visudo" || !slices.Equal(calls[2].Args, []string{"-c", "-f", candidate}) {
		t.Fatalf("validator = %s %q, want visudo candidate", calls[2].Name, calls[2].Args)
	}
	if calls[3].Name != "mv" || !slices.Equal(calls[3].Args, []string{"-T", "--", candidate, target}) {
		t.Fatalf("swap = %s %q, want mv -T -- candidate target", calls[3].Name, calls[3].Args)
	}
}

func TestApplyPolicyFile_EscalatedCandidatePathValidatedBeforeUse(t *testing.T) {
	fr, m := newEscalatedManager(t)
	originalPolicyRootFor := policyRootFor
	policyRootFor = func(policyPathClass) string { return "/etc" }
	t.Cleanup(func() { policyRootFor = originalPolicyRootFor })
	fr.Push(pmexec.Result{Stdout: "old\n"}, nil)
	fr.Push(pmexec.Result{Stdout: "/tmp/attacker-candidate\n"}, nil)

	_, err := m.ApplyPolicyFile(context.Background(), presentPolicy(PolicySurfaceAdminPolicy, "/etc/pm-admin-policy", "new\n"))
	if !errors.Is(err, ErrInvalidPolicyFile) {
		t.Fatalf("err = %v, want ErrInvalidPolicyFile", err)
	}
	if calls := mustCalls(t, fr, 2); calls[0].Name != "cat" || calls[1].Name != "sh" {
		t.Fatalf("calls = %+v, want read then candidate writer only", calls)
	}
}
