package pkg

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/redos"
	"github.com/manchtools/power-manage/sdk/validate"
)

// dnf drives the Fedora/RHEL package manager (dnf / rpm) over an injected Runner.
type dnf struct {
	r pmexec.Runner
}

var _ Manager = (*dnf)(nil)

// nevraVersionRe matches the first dash-then-digit in an NEVRA string, marking
// the boundary between the package name and its version.
var nevraVersionRe = redos.MustVet(`-\d`)

// parseNEVRAName extracts the package name from an NEVRA string
// (Name-[Epoch:]Version-Release[.Arch]).
func parseNEVRAName(nevra string) string {
	loc := nevraVersionRe.FindStringIndex(nevra)
	if loc == nil {
		return nevra
	}
	return nevra[:loc[0]]
}

func (d *dnf) Backend() Backend { return Dnf }

// write runs a privileged dnf command and maps a non-zero exit to an error,
// returning the command Result (stdout/stderr/exit) on both the success and
// non-zero-exit paths.
func (d *dnf) write(ctx context.Context, args ...string) (pmexec.Result, error) {
	res, err := runPriv(ctx, d.r, true, nil, "dnf", args...)
	if err != nil {
		return pmexec.Result{}, err
	}
	return res, asCommandError("dnf", res)
}

// Version returns the dnf version string.
func (d *dnf) Version(ctx context.Context) (string, error) {
	out, err := readOut(ctx, d.r, "dnf", "--version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(strings.SplitN(out, "\n", 2)[0]), nil
}

// Install installs packages. opts.Version pins a single package (dnf name-version
// form); opts.AllowDowngrade adds --allowerasing and, on failure, retries an
// explicit `dnf downgrade`.
func (d *dnf) Install(ctx context.Context, opts InstallOptions, packages ...string) (pmexec.Result, error) {
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
	args := []string{"install", "-y"}
	if opts.AllowDowngrade {
		args = append(args, "--allowerasing")
	}
	var pkgSpec string
	if opts.Version != "" {
		pkgSpec = fmt.Sprintf("%s-%s", packages[0], opts.Version)
		args = append(args, pkgSpec)
	} else {
		args = append(args, packages...)
	}

	res, err := d.write(ctx, args...)
	// Only retry as an explicit downgrade when dnf itself rejected the install
	// (a non-zero exit). An exec/escalation/context failure must not trigger a
	// second escalated command.
	var ce *pmexec.CommandError
	if errors.As(err, &ce) && opts.AllowDowngrade && opts.Version != "" {
		return d.write(ctx, "downgrade", "-y", pkgSpec)
	}
	return res, err
}

// InstallLocal installs a local .rpm file through dnf, resolving its
// dependencies from the configured repositories (unlike a bare `rpm -i`). When
// the file is OLDER than the installed version dnf refuses to "install" it; with
// opts.AllowDowngrade that rejection is retried as an explicit `dnf downgrade`.
// opts.AllowUnsigned adds --nogpgcheck so an out-of-band-verified unsigned rpm is
// accepted (it is carried into the downgrade retry too). dnf5 rejects a "--"
// end-of-options separator, so it is NOT used; the path is kept safe by
// validate.LocalPackagePath, which requires an absolute path that can never be
// flag-shaped.
func (d *dnf) InstallLocal(ctx context.Context, path string, opts InstallLocalOptions) (pmexec.Result, error) {
	if err := validate.LocalPackagePath(path); err != nil {
		return pmexec.Result{}, err
	}
	flags := []string{"install", "-y"}
	if opts.AllowUnsigned {
		flags = append(flags, "--nogpgcheck")
	}
	if opts.AllowDowngrade {
		flags = append(flags, "--allowerasing")
	}
	res, err := d.write(ctx, append(flags, path)...)
	// Retry as an explicit downgrade ONLY when dnf itself rejected the install
	// (a non-zero exit); an exec/escalation/context failure must not trigger a
	// second escalated command. The downgrade carries the same GPG policy.
	var ce *pmexec.CommandError
	if errors.As(err, &ce) && opts.AllowDowngrade {
		dargs := []string{"downgrade", "-y"}
		if opts.AllowUnsigned {
			dargs = append(dargs, "--nogpgcheck")
		}
		return d.write(ctx, append(dargs, path)...)
	}
	return res, err
}

// Remove removes packages. dnf has no purge concept, so opts.Purge is a no-op.
func (d *dnf) Remove(ctx context.Context, _ RemoveOptions, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	return d.write(ctx, append([]string{"remove", "-y"}, packages...)...)
}

// Update refreshes metadata via `dnf check-update` (exit 100 = updates available
// is a success, not an error).
func (d *dnf) Update(ctx context.Context) (pmexec.Result, error) {
	res, err := runPriv(ctx, d.r, true, nil, "dnf", "check-update")
	if err != nil {
		return pmexec.Result{}, err
	}
	if res.ExitCode == 0 || res.ExitCode == 100 {
		return res, nil
	}
	return res, asCommandError("dnf", res)
}

// Upgrade upgrades the named packages, or all packages with no names.
func (d *dnf) Upgrade(ctx context.Context, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil // empty is a no-op; UpgradeAll does a full upgrade
	}
	return d.write(ctx, append([]string{"upgrade", "-y"}, packages...)...)
}

// UpgradeAll performs a full system upgrade (dnf upgrade).
func (d *dnf) UpgradeAll(ctx context.Context, opts UpgradeOptions) (pmexec.Result, error) {
	args := []string{"upgrade", "-y"}
	if opts.SecurityOnly {
		args = append(args, "--security")
	}
	return d.write(ctx, args...)
}

// ensureVersionLock verifies that the optional versionlock plugin is available.
func (d *dnf) ensureVersionLock(ctx context.Context) error {
	_, ok, err := probe(ctx, d.r, "dnf", 1, "versionlock", "--help")
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	return fmt.Errorf("%w: install the dnf versionlock plugin", pmexec.ErrBackendUnavailable)
}

// Pin holds packages back with dnf versionlock.
func (d *dnf) Pin(ctx context.Context, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	if err := d.ensureVersionLock(ctx); err != nil {
		return pmexec.Result{}, err
	}
	return d.write(ctx, append([]string{"versionlock", "add"}, packages...)...)
}

// Unpin releases held packages (dnf versionlock delete).
func (d *dnf) Unpin(ctx context.Context, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	if err := d.ensureVersionLock(ctx); err != nil {
		return pmexec.Result{}, err
	}
	return d.write(ctx, append([]string{"versionlock", "delete"}, packages...)...)
}

// Autoremove removes packages installed only as now-unneeded dependencies.
func (d *dnf) Autoremove(ctx context.Context) (pmexec.Result, error) {
	return d.write(ctx, "autoremove", "-y")
}

// Search searches package names/summaries (exit 1 = no matches).
func (d *dnf) Search(ctx context.Context, query string) ([]SearchResult, error) {
	if err := validate.SearchQuery(query); err != nil {
		return nil, err
	}
	res, err := runRead(ctx, d.r, "dnf", "search", "-q", query)
	if err != nil {
		return nil, err
	}
	if res.ExitCode == 1 {
		return []SearchResult{}, nil
	}
	if res.ExitCode != 0 {
		return nil, asCommandError("dnf", res)
	}

	results := make([]SearchResult, 0)
	scanner := newLineScanner(res.Stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "=") || line == "" {
			continue
		}
		parts := strings.SplitN(line, " : ", 2)
		if len(parts) < 2 {
			continue
		}
		name, _ := splitDnfNameArch(parts[0])
		results = append(results, SearchResult{
			Name:        name,
			Description: strings.TrimSpace(parts[1]),
		})
	}
	return results, nil
}

// List lists installed packages.
func (d *dnf) List(ctx context.Context) ([]Package, error) {
	out, err := readOut(ctx, d.r, "rpm", "-qa", "--queryformat",
		"%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SIZE}\t%{SUMMARY}\n")
	if err != nil {
		return nil, err
	}

	pinned, err := d.getPinnedSet(ctx)
	if err != nil {
		return nil, err
	}

	return parseDnfList(out, pinned), nil
}

func parseDnfList(out string, pinned map[string]bool) []Package {
	packages := make([]Package, 0)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			continue
		}
		size, err := strconv.ParseInt(fields[3], 10, 64)
		if err != nil || size < 0 {
			continue
		}
		desc := ""
		if len(fields) > 4 {
			desc = fields[4]
		}
		packages = append(packages, Package{
			Name:         fields[0],
			Version:      fields[1],
			Architecture: fields[2],
			Status:       "installed",
			Size:         size,
			Description:  desc,
			Pinned:       pinned[fields[0]],
		})
	}
	return packages
}

// ListUpgradable lists packages with an available upgrade (check-update exit 100).
func (d *dnf) ListUpgradable(ctx context.Context) ([]PackageUpdate, error) {
	res, err := runRead(ctx, d.r, "dnf", "check-update", "-q")
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 && res.ExitCode != 100 {
		return nil, asCommandError("dnf", res)
	}

	updates := make([]PackageUpdate, 0)
	scanner := newLineScanner(res.Stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		name, arch := splitDnfNameArch(fields[0])
		current, err := d.InstalledVersion(ctx, name)
		if err != nil {
			return nil, err
		}
		updates = append(updates, PackageUpdate{
			Name:           name,
			Architecture:   arch,
			NewVersion:     fields[1],
			Repository:     fields[2],
			CurrentVersion: current,
		})
	}
	return updates, nil
}

func splitDnfNameArch(value string) (name, arch string) {
	last := strings.LastIndexByte(value, '.')
	if last <= 0 || last == len(value)-1 {
		return value, ""
	}
	return value[:last], value[last+1:]
}

// Show returns detailed information about a package.
func (d *dnf) Show(ctx context.Context, name string) (*Package, error) {
	if err := validate.PackageName(name); err != nil {
		return nil, err
	}
	out, err := readOut(ctx, d.r, "dnf", "info", "-q", name)
	if err != nil {
		return nil, err
	}

	pkg := &Package{Name: name, Status: "available"}
	scanner := newLineScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Version"):
			pkg.Version = parseColonValue(line)
		case strings.HasPrefix(line, "Release"):
			if pkg.Version != "" {
				pkg.Version += "-" + parseColonValue(line)
			}
		case strings.HasPrefix(line, "Architecture"):
			pkg.Architecture = parseColonValue(line)
		case strings.HasPrefix(line, "Size"):
			size, err := parseSize(parseColonValue(line))
			if err != nil {
				return nil, err
			}
			pkg.Size = size
		case strings.HasPrefix(line, "Summary"):
			pkg.Description = parseColonValue(line)
		case strings.HasPrefix(line, "Repository"):
			pkg.Repository = parseColonValue(line)
		}
	}

	installed, err := d.IsInstalled(ctx, name)
	if err != nil {
		return nil, err
	}
	if installed {
		pkg.Status = "installed"
	}
	pinned, err := d.IsPinned(ctx, name)
	if err != nil {
		return nil, err
	}
	pkg.Pinned = pinned
	return pkg, nil
}

// ListVersions lists the versions available for a package.
func (d *dnf) ListVersions(ctx context.Context, name string) (*VersionInfo, error) {
	if err := validate.PackageName(name); err != nil {
		return nil, err
	}
	out, err := readOut(ctx, d.r, "dnf", "list", "--showduplicates", "-q", name)
	if err != nil {
		return nil, err
	}

	info := &VersionInfo{Name: name}
	installed, err := d.InstalledVersion(ctx, name)
	if err != nil {
		return nil, err
	}
	info.Installed = installed

	seen := make(map[string]bool)
	scanner := newLineScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "Installed") || strings.HasPrefix(line, "Available") {
			continue
		}
		fields := strings.Fields(line) // name.arch  version  repo
		if len(fields) < 3 {
			continue
		}
		version := fields[1]
		if seen[version] {
			continue
		}
		seen[version] = true
		info.Versions = append(info.Versions, AvailableVersion{
			Version:    version,
			Repository: fields[2],
		})
	}
	return info, nil
}

// LocalPackageInfo reads the canonical NAME/VERSION-RELEASE/ARCH out of a local
// .rpm via `rpm -qp --qf` (an unprivileged read). %{NAME} from a crafted .rpm is
// untrusted, so it is re-validated with validate.RpmPackageName (the RPM grammar —
// which allows '+' for libstdc++ but no flag/metacharacter) before being
// returned. The shared rpmLocalPackageInfo helper keeps dnf and zypper in lockstep.
func (d *dnf) LocalPackageInfo(ctx context.Context, path string) (*LocalPackage, error) {
	return rpmLocalPackageInfo(ctx, d.r, path)
}

// IsInstalled reports whether a package is installed (rpm -q exits 0).
func (d *dnf) IsInstalled(ctx context.Context, name string) (bool, error) {
	if err := validate.PackageName(name); err != nil {
		return false, err
	}
	res, err := runRead(ctx, d.r, "rpm", "-q", name)
	if err != nil {
		return false, err
	}
	if res.ExitCode == 0 {
		return true, nil
	}
	if res.ExitCode == 1 {
		return false, nil
	}
	return false, asCommandError("rpm", res)
}

// InstalledVersion returns the installed version of a package, or "" if absent.
func (d *dnf) InstalledVersion(ctx context.Context, name string) (string, error) {
	if err := validate.PackageName(name); err != nil {
		return "", err
	}
	res, err := runRead(ctx, d.r, "rpm", "-q", "--queryformat", "%{VERSION}-%{RELEASE}", name)
	if err != nil {
		return "", err
	}
	if res.ExitCode == 1 {
		return "", nil // not installed
	}
	if res.ExitCode != 0 {
		return "", asCommandError("rpm", res)
	}
	version := strings.TrimSpace(res.Stdout)
	if version == "" {
		return "", fmt.Errorf("%w: rpm returned an empty version", ErrMalformedOutput)
	}
	return version, nil
}

// InstalledCount returns the number of installed packages.
func (d *dnf) InstalledCount(ctx context.Context) (int, error) {
	out, err := readOut(ctx, d.r, "rpm", "-qa", "--qf", ".\n")
	if err != nil {
		return 0, err
	}
	return countNonEmptyLines(out), nil
}

// HasUpdates reports whether updates are available (dnf check-update exit 100).
func (d *dnf) HasUpdates(ctx context.Context, securityOnly bool) (bool, error) {
	args := []string{"check-update", "-q"}
	if securityOnly {
		args = append(args, "--security")
	}
	res, err := runRead(ctx, d.r, "dnf", args...)
	if err != nil {
		return false, err
	}
	switch res.ExitCode {
	case 0:
		return false, nil
	case 100:
		return true, nil
	default:
		return false, asCommandError("dnf", res)
	}
}

// IsPinned reports whether a package is versionlocked. Tolerant of an absent
// plugin (reports false rather than erroring).
func (d *dnf) IsPinned(ctx context.Context, name string) (bool, error) {
	if err := validate.PackageName(name); err != nil {
		return false, err
	}
	out, ok, err := probe(ctx, d.r, "dnf", 1, "versionlock", "list", "-q")
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil // versionlock plugin absent → not pinned
	}
	scanner := newLineScanner(out)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" && parseNEVRAName(line) == name {
			return true, nil
		}
	}
	return false, nil
}

// ListPinned lists versionlocked packages (installing the plugin if needed).
func (d *dnf) ListPinned(ctx context.Context) ([]Package, error) {
	if err := d.ensureVersionLock(ctx); err != nil {
		return nil, err
	}
	out, err := readOut(ctx, d.r, "dnf", "versionlock", "list", "-q")
	if err != nil {
		return nil, err
	}

	packages := make([]Package, 0)
	scanner := newLineScanner(out)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		name := parseNEVRAName(line)
		version, err := d.InstalledVersion(ctx, name)
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

func (d *dnf) getPinnedSet(ctx context.Context) (map[string]bool, error) {
	out, ok, err := probe(ctx, d.r, "dnf", 1, "versionlock", "list", "-q")
	if err != nil {
		return nil, err
	}
	if !ok {
		return map[string]bool{}, nil // versionlock plugin absent → nothing pinned
	}
	pinned := make(map[string]bool)
	scanner := newLineScanner(out)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			pinned[parseNEVRAName(line)] = true
		}
	}
	return pinned, nil
}

func parseSize(s string) (int64, error) {
	return parseSizeWithUnits(s, []sizeUnit{
		{" k", 1024},
		{" K", 1024},
		{" M", 1024 * 1024},
		{" G", 1024 * 1024 * 1024},
	})
}
