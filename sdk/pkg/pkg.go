// Package pkg provides a uniform package-manager abstraction for Linux.
//
// A Manager is built for an explicit Backend over an injected exec.Runner —
// the SDK keeps no global escalation state and every Manager is unit-testable
// with exectest.FakeRunner (no host, no sudo, no container):
//
//	r, _ := exec.NewRunner(exec.Sudo)
//	m, err := pkg.New(pkg.Apt, r)
//	if err != nil { ... }
//	if _, err := m.Install(ctx, pkg.InstallOptions{}, "vim", "git"); err != nil { ... }
//
// Reads (Search/List/Show/IsInstalled/…) run unprivileged; mutations
// (Install/InstallLocal/Remove/Update/Upgrade/Pin/Unpin/Autoremove) run
// through the Runner's privilege backend. Every package-name, version, and
// local-file-path argument is validated before it can reach argv — there is no
// opt-out.
package pkg

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/validate"
)

// ErrUnknownBackend is returned by New for a Backend the SDK does not implement
// (including the zero value). Fail-closed: no silent default.
var (
	ErrUnknownBackend  = errors.New("pkg: unknown package-manager backend")
	ErrMalformedOutput = errors.New("pkg: malformed package-manager output")
)

// ErrSecurityOnlyUnsupported is returned by UpgradeAll when UpgradeOptions.
// SecurityOnly is set on a backend that has no security-only upgrade path:
// pacman (a rolling release with no security/non-security distinction) and
// flatpak (no security channel). Fail-closed: the SDK never silently performs a
// full upgrade when only security updates were requested.
var ErrSecurityOnlyUnsupported = errors.New("pkg: security-only upgrade not supported by this backend")

// UpgradeOptions configures UpgradeAll.
type UpgradeOptions struct {
	// SecurityOnly restricts the upgrade to security updates. Supported on apt
	// (unattended-upgrade),
	// dnf (--security) and zypper (patch --category security). pacman and flatpak
	// return ErrSecurityOnlyUnsupported.
	SecurityOnly bool
}

// Backend identifies a supported package manager. The zero value is invalid
// (New rejects it); valid values start at 1.
type Backend int

const (
	// Apt is the Debian/Ubuntu package manager (apt / dpkg).
	Apt Backend = iota + 1
	// Dnf is the Fedora/RHEL package manager (dnf / rpm).
	Dnf
	// Pacman is the Arch Linux package manager.
	Pacman
	// Zypper is the openSUSE/SLES package manager (zypper / rpm).
	Zypper
	// Flatpak is the cross-distro application bundle manager.
	Flatpak
)

// String returns the canonical lowercase backend name.
func (b Backend) String() string {
	switch b {
	case Apt:
		return "apt"
	case Dnf:
		return "dnf"
	case Pacman:
		return "pacman"
	case Zypper:
		return "zypper"
	case Flatpak:
		return "flatpak"
	default:
		return fmt.Sprintf("Backend(%d)", int(b))
	}
}

// Manager is the uniform package-manager surface. Every method takes a context
// so the caller controls timeout/cancellation. Query methods return typed
// results; mutating methods return the command's output (an exec.Result carrying
// exit code, stdout and stderr) so callers can surface what the package manager
// actually did, plus an error — a non-zero exit becomes an *exec.CommandError
// carrying the exit code and stderr while the Result still carries the full
// stdout/stderr. The Result is populated on both the success and non-zero-exit
// paths; it is the zero Result only when the command could not be run at all
// (the error is then a plain runner error) or when the call is a validated
// no-op (e.g. an empty package list).
type Manager interface {
	// Backend reports which package-manager backend this Manager drives.
	Backend() Backend

	// --- queries (unprivileged) ---

	// Version returns the package-manager tool version string.
	Version(ctx context.Context) (string, error)
	// Search returns packages whose name/summary matches query.
	Search(ctx context.Context, query string) ([]SearchResult, error)
	// List returns the installed packages.
	List(ctx context.Context) ([]Package, error)
	// ListUpgradable returns packages with an available upgrade.
	ListUpgradable(ctx context.Context) ([]PackageUpdate, error)
	// Show returns detailed information about a single package.
	Show(ctx context.Context, name string) (*Package, error)
	// ListVersions returns the versions available for a package.
	ListVersions(ctx context.Context, name string) (*VersionInfo, error)
	// IsInstalled reports whether name is currently installed.
	IsInstalled(ctx context.Context, name string) (bool, error)
	// LocalPackageInfo reads a package's canonical name (and, where the backend
	// reports them, version and architecture) from a LOCAL package file already on
	// disk — a .deb, .rpm or pacman package — WITHOUT installing it. path must be
	// an absolute filesystem path (validate.LocalPackagePath). The name a crafted
	// file embeds is untrusted, so it is validated against the backend's
	// package-name grammar before being returned; a flag-shaped or
	// metacharacter-bearing name is rejected. The flatpak backend has no clean
	// local name-introspection command and returns a not-supported error.
	LocalPackageInfo(ctx context.Context, path string) (*LocalPackage, error)
	// InstalledVersion returns the installed version of name, or "" if absent.
	InstalledVersion(ctx context.Context, name string) (string, error)
	// InstalledCount returns the number of installed packages.
	InstalledCount(ctx context.Context) (int, error)
	// HasUpdates reports whether any update is available. When securityOnly is
	// true only security updates are considered (where the backend supports it).
	HasUpdates(ctx context.Context, securityOnly bool) (bool, error)
	// IsPinned reports whether name is held back from upgrades.
	IsPinned(ctx context.Context, name string) (bool, error)
	// ListPinned returns the packages held back from upgrades.
	ListPinned(ctx context.Context) ([]Package, error)

	// --- mutations (privileged) ---

	// Install installs the named packages. opts.Version pins a single package
	// (exactly one name required when set); opts.AllowDowngrade permits a lower
	// version than installed.
	Install(ctx context.Context, opts InstallOptions, packages ...string) (pmexec.Result, error)
	// InstallLocal installs a package from a local file already on disk — a
	// downloaded .deb, .rpm, pacman package, or flatpak bundle — rather than by
	// name from a configured repository, resolving dependencies from the
	// configured repositories where the backend supports it (apt/dnf/zypper/
	// pacman). path must be an ABSOLUTE filesystem path to the package file;
	// fetching and verifying the artifact (https transport, checksum) is the
	// caller's responsibility. opts.AllowDowngrade permits a lower version than
	// the one currently installed; opts.AllowUnsigned skips the backend's GPG
	// check (dnf --nogpgcheck / zypper --allow-unsigned-rpm) for a file whose
	// authenticity is established out of band — secure-default-off.
	InstallLocal(ctx context.Context, path string, opts InstallLocalOptions) (pmexec.Result, error)
	// Remove removes the named packages. opts.Purge also deletes configuration
	// where the backend distinguishes it (apt/pacman/flatpak); elsewhere Purge
	// is equivalent to a plain remove.
	Remove(ctx context.Context, opts RemoveOptions, packages ...string) (pmexec.Result, error)
	// Update refreshes the package metadata/database.
	Update(ctx context.Context) (pmexec.Result, error)
	// Upgrade upgrades the named packages. With NO names it is a no-op (not a
	// full upgrade) — an accidentally-empty list must never upgrade the whole
	// system. Use UpgradeAll for that.
	Upgrade(ctx context.Context, packages ...string) (pmexec.Result, error)
	// UpgradeAll performs a full system upgrade (apt dist-upgrade / dnf upgrade /
	// pacman -Syu / zypper dist-upgrade / flatpak update). With
	// opts.SecurityOnly it upgrades only security updates where the backend
	// supports it (apt/dnf/zypper); pacman and flatpak return
	// ErrSecurityOnlyUnsupported.
	UpgradeAll(ctx context.Context, opts UpgradeOptions) (pmexec.Result, error)
	// Pin holds the named packages back from upgrades.
	Pin(ctx context.Context, packages ...string) (pmexec.Result, error)
	// Unpin releases the named packages so they upgrade again.
	Unpin(ctx context.Context, packages ...string) (pmexec.Result, error)
	// Autoremove removes packages installed only as now-unneeded dependencies.
	// It is a no-op (zero Result, nil error) on backends with no native equivalent.
	Autoremove(ctx context.Context) (pmexec.Result, error)
}

// FlatpakManager is the Manager returned by New(Flatpak, …); it adds remote
// (repository) management, which has no analogue on the native managers.
// Callers reach it with a type assertion:
//
//	if fm, ok := m.(pkg.FlatpakManager); ok { fm.AddRemote(ctx, "flathub", url) }
type FlatpakManager interface {
	Manager
	// AddRemote registers a flatpak remote. name must be a valid remote alias
	// and url an https repository URL.
	AddRemote(ctx context.Context, name, url string) error
	// RemoveRemote deletes a flatpak remote.
	RemoveRemote(ctx context.Context, name string) error
	// ListRemotes returns the configured flatpak remote names.
	ListRemotes(ctx context.Context) ([]string, error)
}

// Option customizes a Manager at construction.
type Option func(*config)

type config struct {
	// system selects flatpak --system (escalated) over --user (unprivileged).
	// Ignored by the native managers, which always operate system-wide.
	system bool
}

// WithUserScope makes a flatpak Manager operate on the per-user installation
// (--user, unprivileged) instead of the system installation. It has no effect
// on the native package managers.
func WithUserScope() Option {
	return func(c *config) { c.system = false }
}

// New builds a Manager for backend b driven by runner. A nil runner or an
// unknown backend is rejected (fail-closed). New is pure and never probes or
// chooses a backend; the agent injects the result of its one boot-time probe.
func New(b Backend, runner pmexec.Runner, opts ...Option) (Manager, error) {
	if runner == nil || isNilRunner(runner) {
		return nil, fmt.Errorf("pkg: %w", pmexec.ErrRunnerRequired)
	}
	cfg := config{system: true}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	switch b {
	case Apt:
		return &apt{r: runner}, nil
	case Dnf:
		return &dnf{r: runner}, nil
	case Pacman:
		return &pacman{r: runner}, nil
	case Zypper:
		return &zypper{r: runner}, nil
	case Flatpak:
		return &flatpak{r: runner, system: cfg.system}, nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownBackend, int(b))
	}
}

func isNilRunner(runner pmexec.Runner) bool {
	v := reflect.ValueOf(runner)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func validatePackageNames(names []string) error {
	for _, name := range names {
		if err := validate.PackageName(name); err != nil {
			return err
		}
	}
	return nil
}
