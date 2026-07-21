//go:build container

package pkg

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
)

func containerBackend(t *testing.T) Backend {
	t.Helper()
	switch os.Getenv("PM_PKG_BACKEND") {
	case "apt":
		return Apt
	case "dnf":
		return Dnf
	case "pacman":
		return Pacman
	case "zypper":
		return Zypper
	case "flatpak":
		return Flatpak
	default:
		t.Fatalf("PM_PKG_BACKEND names no supported backend: %q", os.Getenv("PM_PKG_BACKEND"))
		return 0
	}
}

func TestContainer_PackageManagerRoundTrip(t *testing.T) {
	if locale := os.Getenv("LC_ALL"); os.Getenv("PM_REQUIRE_NON_ENGLISH") == "1" && (locale == "" || strings.HasPrefix(locale, "C")) {
		t.Fatalf("non-English lane has LC_ALL=%q", locale)
	}
	runner, err := pmexec.NewRunner(pmexec.Direct)
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(containerBackend(t), runner)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	version, err := m.Version(ctx)
	if err != nil || version == "" {
		t.Fatalf("Version = (%q, %v), want a real tool version", version, err)
	}
	packages, err := m.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if packages == nil {
		t.Fatal("List returned nil without error")
	}
	if m.Backend() == Flatpak {
		return // a fresh flatpak installation legitimately contains no applications
	}

	known := os.Getenv("PM_KNOWN_PACKAGE")
	if known == "" {
		t.Fatal("PM_KNOWN_PACKAGE is required for native package-manager lanes")
	}
	var listed *Package
	for i := range packages {
		if packages[i].Name == known {
			listed = &packages[i]
			break
		}
	}
	if listed == nil {
		t.Fatalf("List did not contain installed package %q", known)
	}
	installedVersion, err := m.InstalledVersion(ctx, known)
	if err != nil {
		t.Fatalf("InstalledVersion(%q): %v", known, err)
	}
	if installedVersion != listed.Version {
		t.Fatalf("round trip version = %q, List version = %q", installedVersion, listed.Version)
	}
	if !strings.Contains(installedVersion, ".") {
		t.Fatalf("fixture version %q has no dotted component", installedVersion)
	}
	shown, err := m.Show(ctx, known)
	if err != nil || shown == nil || shown.Name != known {
		t.Fatalf("Show(%q) = (%+v, %v), want a real parsed package", known, shown, err)
	}
	installed, err := m.IsInstalled(ctx, "pm-package-that-does-not-exist")
	if err != nil || installed {
		t.Fatalf("absent IsInstalled = (%v, %v), want (false, nil)", installed, err)
	}
}
