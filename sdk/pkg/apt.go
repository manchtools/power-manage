package pkg

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/validate"
)

// apt drives the Debian/Ubuntu package manager (apt / dpkg / apt-mark)
// over an injected Runner.
type apt struct {
	r pmexec.Runner
}

var _ Manager = (*apt)(nil)

// aptWriteEnv prevents debconf from attempting an interactive frontend when
// there is no terminal. The C locale is forced by the Runner on every command.
var aptWriteEnv = []string{"DEBIAN_FRONTEND=noninteractive"}

// dpkgConfOptions keep dpkg non-interactive when a postinst would otherwise
// prompt about a changed conffile (kernel/grub upgrades):
//   - --force-confdef: take the default action for new conffiles
//   - --force-confold: keep the currently-installed version if user-modified
var dpkgConfOptions = []string{
	"-o", "Dpkg::Options::=--force-confdef",
	"-o", "Dpkg::Options::=--force-confold",
}

func (a *apt) Backend() Backend { return Apt }

// write runs a privileged apt-family command and maps a non-zero exit to an
// *exec.CommandError. The command's Result (stdout, stderr, exit code) is
// returned on both the success and non-zero-exit paths; only an unrunnable
// command yields the zero Result.
func (a *apt) write(ctx context.Context, cmd string, args ...string) (pmexec.Result, error) {
	res, err := runPriv(ctx, a.r, true, aptWriteEnv, cmd, args...)
	if err != nil {
		return pmexec.Result{}, err
	}
	return res, asCommandError(cmd, res)
}

// Version returns the apt version string.
func (a *apt) Version(ctx context.Context) (string, error) {
	out, err := readOut(ctx, a.r, "apt", "--version")
	if err != nil {
		return "", err
	}
	parts := strings.Fields(out)
	if len(parts) >= 2 {
		return parts[1], nil
	}
	return "", fmt.Errorf("%w: apt returned no version", ErrMalformedOutput)
}

// Install installs packages, using --fix-broken to resolve dependency issues.
func (a *apt) Install(ctx context.Context, opts InstallOptions, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if err := validate.PackageVersion(opts.Version); err != nil {
		return pmexec.Result{}, err
	}
	if opts.Version != "" && len(packages) != 1 {
		return pmexec.Result{}, fmt.Errorf("pkg: InstallOptions.Version requires exactly one package, got %d", len(packages))
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	args := append([]string{"install", "-y", "--fix-broken"}, dpkgConfOptions...)
	if opts.AllowDowngrade {
		args = append(args, "--allow-downgrades")
	}
	if opts.Version != "" {
		args = append(args, fmt.Sprintf("%s=%s", packages[0], opts.Version))
	} else {
		args = append(args, packages...)
	}
	return a.write(ctx, "apt", args...)
}

// InstallLocal installs a local .deb file through apt install, which —
// unlike a bare `dpkg -i` — resolves the package's dependencies from the
// configured repositories. validate.LocalPackagePath requires an absolute path,
// so the operand can never be flag-shaped; the conffile-default options keep a
// postinst that touches a conffile non-interactive. opts.AllowUnsigned is a
// no-op here — a local .deb carries no per-file signature to skip.
func (a *apt) InstallLocal(ctx context.Context, path string, opts InstallLocalOptions) (pmexec.Result, error) {
	if err := validate.LocalPackagePath(path); err != nil {
		return pmexec.Result{}, err
	}
	flags := []string{"install", "-y"}
	flags = append(flags, dpkgConfOptions...)
	if opts.AllowDowngrade {
		flags = append(flags, "--allow-downgrades")
	}
	return a.write(ctx, "apt", append(flags, path)...)
}

// Remove removes packages; opts.Purge deletes configuration files too.
func (a *apt) Remove(ctx context.Context, opts RemoveOptions, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	verb := "remove"
	if opts.Purge {
		verb = "purge"
	}
	args := append([]string{verb, "-y"}, packages...)
	return a.write(ctx, "apt", args...)
}

// Update refreshes the package index.
func (a *apt) Update(ctx context.Context) (pmexec.Result, error) {
	return a.write(ctx, "apt", "update")
}

// Upgrade upgrades the named packages; with no names it runs a full
// dist-upgrade (which can add/remove packages to satisfy held-back deps).
func (a *apt) Upgrade(ctx context.Context, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil // empty is a no-op; UpgradeAll does a full upgrade
	}
	args := append([]string{"install", "-y", "--only-upgrade"}, dpkgConfOptions...)
	args = append(args, packages...)
	return a.write(ctx, "apt", args...)
}

// UpgradeAll performs a full distribution upgrade (apt dist-upgrade), or — with
// opts.SecurityOnly — applies only security updates via unattended-upgrade.
func (a *apt) UpgradeAll(ctx context.Context, opts UpgradeOptions) (pmexec.Result, error) {
	if opts.SecurityOnly {
		return a.securityUpgrade(ctx)
	}
	args := append([]string{"dist-upgrade", "-y"}, dpkgConfOptions...)
	return a.write(ctx, "apt", args...)
}

// securityUpgrade applies only security updates via unattended-upgrade — Debian/
// Ubuntu's canonical security-upgrade tool. It matches the exact security
// origins from its Allowed-Origins config (rather than a fragile origin-name
// heuristic) and handles holds, kernel transitions and conffile prompts. It
// requires the unattended-upgrades package; if absent it fails closed with an
// actionable error rather than silently performing a full upgrade.
func (a *apt) securityUpgrade(ctx context.Context) (pmexec.Result, error) {
	res, err := a.write(ctx, "unattended-upgrade", "-v")
	if errors.Is(err, pmexec.ErrBackendUnavailable) {
		return res, fmt.Errorf("%w: install unattended-upgrades for apt security-only upgrades", err)
	}
	return res, err
}

// Pin holds packages (apt-mark hold).
func (a *apt) Pin(ctx context.Context, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	return a.write(ctx, "apt-mark", append([]string{"hold"}, packages...)...)
}

// Unpin releases held packages (apt-mark unhold).
func (a *apt) Unpin(ctx context.Context, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	return a.write(ctx, "apt-mark", append([]string{"unhold"}, packages...)...)
}

// Autoremove removes packages installed only as now-unneeded dependencies.
func (a *apt) Autoremove(ctx context.Context) (pmexec.Result, error) {
	return a.write(ctx, "apt", "autoremove", "-y")
}

// Search searches package names. It always uses `apt-cache search`, which emits
// the stable single-line "name - description" format the parser expects; `apt
// search` produces a multi-line, presentation-oriented format that would not
// parse, and `--names-only` would drop the description (and the separator).
func (a *apt) Search(ctx context.Context, query string) ([]SearchResult, error) {
	if err := validate.SearchQuery(query); err != nil {
		return nil, err
	}
	out, err := readOut(ctx, a.r, "apt-cache", "search", query)
	if err != nil {
		return nil, err
	}

	results := make([]SearchResult, 0)
	scanner := newLineScanner(out)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), " - ", 2)
		if len(parts) < 2 {
			continue
		}
		results = append(results, SearchResult{
			Name:        strings.TrimSpace(parts[0]),
			Description: strings.TrimSpace(parts[1]),
		})
	}
	return results, nil
}

// List lists installed packages.
func (a *apt) List(ctx context.Context) ([]Package, error) {
	out, err := readOut(ctx, a.r, "dpkg-query", "-W",
		"-f=${Package}\t${Version}\t${Architecture}\t${Status}\t${Installed-Size}\t${Description}\n")
	if err != nil {
		return nil, err
	}

	pinned, err := a.getPinnedSet(ctx)
	if err != nil {
		return nil, err
	}

	return parseAptList(out, pinned), nil
}

func parseAptList(out string, pinned map[string]bool) []Package {
	packages := make([]Package, 0)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			continue
		}
		if !strings.Contains(fields[3], "installed") {
			continue
		}
		size, err := strconv.ParseInt(fields[4], 10, 64)
		if err != nil || size < 0 || size > math.MaxInt64/1024 {
			continue
		}
		desc := ""
		if len(fields) > 5 {
			desc = fields[5]
		}
		packages = append(packages, Package{
			Name:         fields[0],
			Version:      fields[1],
			Architecture: fields[2],
			Status:       "installed",
			Size:         size * 1024,
			Description:  desc,
			Pinned:       pinned[fields[0]],
		})
	}
	return packages
}

// ListUpgradable lists packages with an available upgrade.
func (a *apt) ListUpgradable(ctx context.Context) ([]PackageUpdate, error) {
	out, err := readOut(ctx, a.r, "apt", "list", "--upgradable")
	if err != nil {
		return nil, err
	}

	updates := make([]PackageUpdate, 0)
	scanner := newLineScanner(out)
	scanner.Scan() // skip header
	for scanner.Scan() {
		update, ok := parseAptUpgradable(scanner.Text())
		if !ok {
			continue
		}
		updates = append(updates, update)
	}
	return updates, nil
}

func parseAptUpgradable(line string) (PackageUpdate, bool) {
	fields := strings.Fields(line)
	if len(fields) < 6 || fields[3] != "[upgradable" || fields[4] != "from:" {
		return PackageUpdate{}, false
	}
	name, repository, ok := strings.Cut(fields[0], "/")
	if !ok || name == "" || repository == "" {
		return PackageUpdate{}, false
	}
	current := strings.TrimSuffix(strings.Join(fields[5:], " "), "]")
	if current == "" || current == strings.Join(fields[5:], " ") {
		return PackageUpdate{}, false
	}
	return PackageUpdate{
		Name:           name,
		Repository:     repository,
		NewVersion:     fields[1],
		Architecture:   fields[2],
		CurrentVersion: current,
	}, true
}

// Show returns detailed information about a package.
func (a *apt) Show(ctx context.Context, name string) (*Package, error) {
	if err := validate.PackageName(name); err != nil {
		return nil, err
	}
	out, err := readOut(ctx, a.r, "apt-cache", "show", name)
	if err != nil {
		return nil, err
	}

	pkg := &Package{Name: name}
	scanner := newLineScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		switch {
		case strings.HasPrefix(line, "Version:"):
			pkg.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		case strings.HasPrefix(line, "Architecture:"):
			pkg.Architecture = strings.TrimSpace(strings.TrimPrefix(line, "Architecture:"))
		case strings.HasPrefix(line, "Description:"):
			pkg.Description = strings.TrimSpace(strings.TrimPrefix(line, "Description:"))
		case strings.HasPrefix(line, "Installed-Size:"):
			size, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "Installed-Size:")), 10, 64)
			if err != nil || size < 0 || size > math.MaxInt64/1024 {
				return nil, fmt.Errorf("%w: invalid apt installed size", ErrMalformedOutput)
			}
			pkg.Size = size * 1024
		}
	}

	installed, err := a.IsInstalled(ctx, name)
	if err != nil {
		return nil, err
	}
	if installed {
		pkg.Status = "installed"
	} else {
		pkg.Status = "available"
	}
	pinned, err := a.IsPinned(ctx, name)
	if err != nil {
		return nil, err
	}
	pkg.Pinned = pinned
	return pkg, nil
}

// ListVersions lists the versions available for a package.
func (a *apt) ListVersions(ctx context.Context, name string) (*VersionInfo, error) {
	if err := validate.PackageName(name); err != nil {
		return nil, err
	}
	out, err := readOut(ctx, a.r, "apt-cache", "madison", name)
	if err != nil {
		return nil, err
	}

	info := &VersionInfo{Name: name}
	installed, err := a.InstalledVersion(ctx, name)
	if err != nil {
		return nil, err
	}
	info.Installed = installed

	seen := make(map[string]bool)
	scanner := newLineScanner(out)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "|") // package | version | repository
		if len(fields) < 3 {
			continue
		}
		version := strings.TrimSpace(fields[1])
		if seen[version] {
			continue
		}
		seen[version] = true
		info.Versions = append(info.Versions, AvailableVersion{
			Version:    version,
			Repository: strings.TrimSpace(fields[2]),
		})
	}
	return info, nil
}

// LocalPackageInfo reads the canonical Package/Version/Architecture out of a
// local .deb via `dpkg-deb -f` (an unprivileged read). The Package field a
// crafted .deb embeds is untrusted, so it is re-validated with
// validate.PackageName — the same grammar Remove/IsInstalled would feed it
// to — before being returned; a flag-shaped or metacharacter-bearing name is
// rejected here rather than surfacing as a package-manager flag downstream.
func (a *apt) LocalPackageInfo(ctx context.Context, path string) (*LocalPackage, error) {
	if err := validate.LocalPackagePath(path); err != nil {
		return nil, err
	}
	// dpkg-deb -f with MULTIPLE fields prints a labeled "Field: value" stanza (a
	// SINGLE field would print the bare value). Parse by field name so the
	// "Package:" label never leaks into the package name (which would then fail
	// validate.PackageName).
	out, err := readOut(ctx, a.r, "dpkg-deb", "-f", path, "Package", "Version", "Architecture")
	if err != nil {
		return nil, err
	}
	fields := parseControlFields(out)
	name := fields["Package"]
	if name == "" {
		return nil, fmt.Errorf("pkg: dpkg-deb reported no Package field for %q", path)
	}
	if err := validate.PackageName(name); err != nil {
		return nil, fmt.Errorf("pkg: local .deb reports an unsafe package name: %w", err)
	}
	return &LocalPackage{Name: name, Version: fields["Version"], Arch: fields["Architecture"]}, nil
}

// parseControlFields parses dpkg-deb -f's labeled "Field: value" stanza into a
// field map. The value is taken after the FIRST ":" so an epoch'd version
// ("1:2.0") survives intact, and the field LABEL never becomes part of a value.
func parseControlFields(out string) map[string]string {
	fields := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}
	return fields
}

// IsInstalled reports whether a package is installed (dpkg -s exits 0).
func (a *apt) IsInstalled(ctx context.Context, name string) (bool, error) {
	if err := validate.PackageName(name); err != nil {
		return false, err
	}
	res, err := runRead(ctx, a.r, "dpkg", "-s", name)
	if err != nil {
		return false, err
	}
	if res.ExitCode == 0 {
		return true, nil
	}
	if res.ExitCode == 1 {
		return false, nil
	}
	return false, asCommandError("dpkg", res)
}

// InstalledVersion returns the installed version of a package, or "" if absent
// (dpkg-query exits non-zero for an unknown package — a benign miss, not an error).
func (a *apt) InstalledVersion(ctx context.Context, name string) (string, error) {
	if err := validate.PackageName(name); err != nil {
		return "", err
	}
	out, ok, err := probe(ctx, a.r, "dpkg-query", 1, "-W", "-f=${Version}", name)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	version := strings.TrimSpace(out)
	if version == "" {
		return "", fmt.Errorf("%w: dpkg-query returned an empty version", ErrMalformedOutput)
	}
	return version, nil
}

// InstalledCount returns the number of installed packages.
func (a *apt) InstalledCount(ctx context.Context) (int, error) {
	out, err := readOut(ctx, a.r, "dpkg-query", "-f", ".\n", "-W")
	if err != nil {
		return 0, err
	}
	return countNonEmptyLines(out), nil
}

// HasUpdates reports whether any package can be upgraded. apt has no reliable
// security-only filter, so securityOnly is accepted but not honored here.
func (a *apt) HasUpdates(ctx context.Context, securityOnly bool) (bool, error) {
	_ = securityOnly
	out, err := readOut(ctx, a.r, "apt", "-s", "upgrade")
	if err != nil {
		return false, err
	}
	scanner := newLineScanner(out)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "Inst ") {
			return true, nil
		}
	}
	return false, nil
}

// IsPinned reports whether a package is held (apt-mark showhold <name>).
func (a *apt) IsPinned(ctx context.Context, name string) (bool, error) {
	if err := validate.PackageName(name); err != nil {
		return false, err
	}
	out, err := readOut(ctx, a.r, "apt-mark", "showhold", name)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) == name, nil
}

// ListPinned lists held packages.
func (a *apt) ListPinned(ctx context.Context) ([]Package, error) {
	out, err := readOut(ctx, a.r, "apt-mark", "showhold")
	if err != nil {
		return nil, err
	}

	packages := make([]Package, 0)
	scanner := newLineScanner(out)
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if name == "" {
			continue
		}
		version, err := a.InstalledVersion(ctx, name)
		if err != nil {
			return nil, err
		}
		packages = append(packages, Package{
			Name:    name,
			Version: version,
			Status:  "installed",
			Pinned:  true,
		})
	}
	return packages, nil
}

func (a *apt) getPinnedSet(ctx context.Context) (map[string]bool, error) {
	out, err := readOut(ctx, a.r, "apt-mark", "showhold")
	if err != nil {
		return nil, err
	}
	pinned := make(map[string]bool)
	scanner := newLineScanner(out)
	for scanner.Scan() {
		if name := strings.TrimSpace(scanner.Text()); name != "" {
			pinned[name] = true
		}
	}
	return pinned, nil
}
