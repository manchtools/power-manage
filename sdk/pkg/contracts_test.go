package pkg

import (
	"context"
	"errors"
	"reflect"
	"testing"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/exec/exectest"
)

func newTestManager(t *testing.T, backend Backend) (Manager, *exectest.FakeRunner) {
	t.Helper()
	r := exectest.New(pmexec.Direct)
	m, err := New(backend, r)
	if err != nil {
		t.Fatalf("New(%s): %v", backend, err)
	}
	return m, r
}

func TestQueries_BackendUnavailable(t *testing.T) {
	for _, backend := range []Backend{Apt, Dnf, Pacman, Zypper, Flatpak} {
		t.Run(backend.String(), func(t *testing.T) {
			m, r := newTestManager(t, backend)
			r.Push(pmexec.Result{}, pmexec.ErrBackendUnavailable)
			if _, err := m.List(context.Background()); !errors.Is(err, pmexec.ErrBackendUnavailable) {
				t.Fatalf("List error = %v, want ErrBackendUnavailable", err)
			}
		})
	}
}

func TestQueries_AbsentVsFailure(t *testing.T) {
	for _, backend := range []Backend{Apt, Dnf, Pacman, Zypper, Flatpak} {
		t.Run(backend.String()+"/absent", func(t *testing.T) {
			m, r := newTestManager(t, backend)
			r.Push(pmexec.Result{ExitCode: 1}, nil)
			version, err := m.InstalledVersion(context.Background(), "definitely-absent")
			if err != nil || version != "" {
				t.Fatalf("InstalledVersion absent = (%q, %v), want (empty, nil)", version, err)
			}
		})
		t.Run(backend.String()+"/query-failed", func(t *testing.T) {
			m, r := newTestManager(t, backend)
			r.Push(pmexec.Result{ExitCode: 2, Stderr: "database unreadable"}, nil)
			if _, err := m.InstalledVersion(context.Background(), "bash"); err == nil {
				t.Fatal("InstalledVersion query failure returned nil error")
			}
		})
	}
}

func TestQueries_NeverNilSuccess(t *testing.T) {
	tests := []struct {
		name string
		run  func(Manager) (any, error)
	}{
		{"List", func(m Manager) (any, error) { return m.List(context.Background()) }},
		{"Search", func(m Manager) (any, error) { return m.Search(context.Background(), "bash") }},
		{"ListUpgradable", func(m Manager) (any, error) { return m.ListUpgradable(context.Background()) }},
		{"ListPinned", func(m Manager) (any, error) { return m.ListPinned(context.Background()) }},
	}
	for _, backend := range []Backend{Apt, Dnf, Pacman, Zypper, Flatpak} {
		for _, tc := range tests {
			t.Run(backend.String()+"/"+tc.name, func(t *testing.T) {
				m, _ := newTestManager(t, backend)
				got, err := tc.run(m)
				if err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
				if got == nil || reflect.ValueOf(got).IsNil() {
					t.Fatalf("%s returned (nil, nil)", tc.name)
				}
			})
		}
	}
}

func TestParsers_RejectMalformedNumbers(t *testing.T) {
	if _, err := parseSizeWithUnits("not-a-size", []sizeUnit{{suffix: " B", mult: 1}}); err == nil {
		t.Fatal("parseSizeWithUnits accepted malformed digits as zero")
	}
	if _, err := parseSizeWithUnits("9223372036854775808", nil); err == nil {
		t.Fatal("parseSizeWithUnits accepted an int64-overflowing boundary")
	}
}

func TestList_SkipsOneMalformedEntry(t *testing.T) {
	out := "alpha\t1.2.3-1\tamd64\tinstall ok installed\t12\n" +
		"broken\t1.0\tamd64\tinstall ok installed\tnot-a-number\n" +
		"overflow\t1.0\tamd64\tinstall ok installed\t9223372036854775807\n" +
		"omega\t2.0\tall\tinstall ok installed\t3\n"
	got := parseAptList(out, nil)
	if len(got) != 2 || got[0].Name != "alpha" || got[1].Name != "omega" {
		t.Fatalf("parseAptList = %+v, want valid siblings preserved and malformed row skipped", got)
	}
}

func TestList_PreservesDottedVersions(t *testing.T) {
	out := "python3.11-libs\t3.11.9-1.fc40\tx86_64\t18432\tupdates\n"
	got := parseDnfList(out, nil)
	if len(got) != 1 {
		t.Fatalf("parseDnfList count = %d, want 1", len(got))
	}
	if got[0].Name != "python3.11-libs" || got[0].Version != "3.11.9-1.fc40" {
		t.Fatalf("parseDnfList = %+v, dotted name/version was truncated", got[0])
	}
}

func TestDnf_DottedNameAndARMArchitecture(t *testing.T) {
	m, r := newTestManager(t, Dnf)
	r.Push(pmexec.Result{ExitCode: 100, Stdout: "python3.11-libs.aarch64 3.11.9-1.fc40 updates\n"}, nil)
	r.Push(pmexec.Result{Stdout: "3.11.8-1.fc40\n"}, nil)
	updates, err := m.ListUpgradable(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 1 || updates[0].Name != "python3.11-libs" || updates[0].Architecture != "aarch64" {
		t.Fatalf("ListUpgradable = %+v, want dotted name and ARM architecture preserved", updates)
	}
}
