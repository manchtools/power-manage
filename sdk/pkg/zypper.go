package pkg

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/redos"
	"github.com/manchtools/power-manage/sdk/validate"
)

// zypper drives the openSUSE/SLES package manager (zypper / rpm) over an
// injected Runner.
type zypper struct {
	r pmexec.Runner
}

var _ Manager = (*zypper)(nil)

// zypperLockRe matches a `zypper locks` table row, capturing the package name.
var zypperLockRe = redos.MustVet(`^\s*\d+\s*\|\s*(\S+)`)

// isZypperInfoExit reports whether code is a success or one of zypper's
// informational exit codes (100 update-needed, 101 security, 102 reboot,
// 103 restart) — none of which are failures.
func isZypperInfoExit(code int) bool {
	return code == 0 || (code >= 100 && code <= 103)
}

func (z *zypper) Backend() Backend { return Zypper }

func (z *zypper) write(ctx context.Context, args ...string) (pmexec.Result, error) {
	res, err := runPriv(ctx, z.r, true, nil, "zypper", args...)
	if err != nil {
		return pmexec.Result{}, err
	}
	return res, asCommandError("zypper", res)
}

// Version returns the zypper version string.
func (z *zypper) Version(ctx context.Context) (string, error) {
	out, err := readOut(ctx, z.r, "zypper", "--version")
	if err != nil {
		return "", err
	}
	parts := strings.Fields(out) // "zypper 1.14.59"
	if len(parts) >= 2 {
		return parts[1], nil
	}
	return "", fmt.Errorf("%w: zypper returned no version", ErrMalformedOutput)
}

// Install installs packages. opts.Version pins a single package (name=version);
// opts.AllowDowngrade adds --oldpackage.
func (z *zypper) Install(ctx context.Context, opts InstallOptions, packages ...string) (pmexec.Result, error) {
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
	args := []string{"--non-interactive", "install"}
	if opts.AllowDowngrade {
		args = append(args, "--oldpackage")
	}
	if opts.Version != "" {
		args = append(args, fmt.Sprintf("%s=%s", packages[0], opts.Version))
	} else {
		args = append(args, packages...)
	}
	return z.write(ctx, args...)
}

// InstallLocal installs a local .rpm file through zypper, resolving its
// dependencies from the configured repositories. opts.AllowDowngrade adds
// --oldpackage so a file older than the installed version is accepted.
// opts.AllowUnsigned adds the per-package --allow-unsigned-rpm (NOT the global
// --no-gpg-checks, which would also drop repository-metadata verification).
// validate.LocalPackagePath requires an absolute path, so the operand can never
// be flag-shaped.
func (z *zypper) InstallLocal(ctx context.Context, path string, opts InstallLocalOptions) (pmexec.Result, error) {
	if err := validate.LocalPackagePath(path); err != nil {
		return pmexec.Result{}, err
	}
	flags := []string{"--non-interactive", "install"}
	if opts.AllowUnsigned {
		flags = append(flags, "--allow-unsigned-rpm")
	}
	if opts.AllowDowngrade {
		flags = append(flags, "--oldpackage")
	}
	return z.write(ctx, append(flags, path)...)
}

// Remove removes packages. zypper does not distinguish purge from remove, so
// opts.Purge is a no-op.
func (z *zypper) Remove(ctx context.Context, _ RemoveOptions, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	return z.write(ctx, append([]string{"--non-interactive", "remove"}, packages...)...)
}

// Update refreshes the repositories.
func (z *zypper) Update(ctx context.Context) (pmexec.Result, error) {
	return z.write(ctx, "--non-interactive", "refresh")
}

// Upgrade upgrades the named packages, or runs a full dist-upgrade with no names.
func (z *zypper) Upgrade(ctx context.Context, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil // empty is a no-op; UpgradeAll does a full upgrade
	}
	return z.write(ctx, append([]string{"--non-interactive", "update"}, packages...)...)
}

// UpgradeAll performs a full distribution upgrade (zypper dist-upgrade).
func (z *zypper) UpgradeAll(ctx context.Context, opts UpgradeOptions) (pmexec.Result, error) {
	if opts.SecurityOnly {
		// zypper patches are security-categorised; patch --category security
		// applies only the security patches.
		return z.write(ctx, "--non-interactive", "patch", "--category", "security")
	}
	return z.write(ctx, "--non-interactive", "dist-upgrade")
}

// Autoremove is a no-op: zypper has no single-shot unneeded-package removal
// matching apt/dnf autoremove semantics.
func (z *zypper) Autoremove(ctx context.Context) (pmexec.Result, error) {
	return pmexec.Result{}, nil
}

// Search searches packages (exit 104 = no matches).
func (z *zypper) Search(ctx context.Context, query string) ([]SearchResult, error) {
	if err := validate.SearchQuery(query); err != nil {
		return nil, err
	}
	res, err := runRead(ctx, z.r, "zypper", "--non-interactive", "search", query)
	if err != nil {
		return nil, err
	}
	if res.ExitCode == 104 {
		return []SearchResult{}, nil
	}
	if res.ExitCode != 0 {
		return nil, asCommandError("zypper", res)
	}

	results := make([]SearchResult, 0)
	scanner := newLineScanner(res.Stdout)
	headerPassed := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+-") {
			headerPassed = true
			continue
		}
		if !headerPassed {
			continue
		}
		parts := strings.Split(line, "|") // S | Name | Summary | Type
		if len(parts) < 3 {
			continue
		}
		name := strings.TrimSpace(parts[1])
		if name == "" {
			continue
		}
		results = append(results, SearchResult{
			Name:        name,
			Description: strings.TrimSpace(parts[2]),
		})
	}
	return results, nil
}

// List lists installed packages (via rpm).
func (z *zypper) List(ctx context.Context) ([]Package, error) {
	out, err := readOut(ctx, z.r, "rpm", "-qa", "--queryformat",
		"%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SIZE}\t%{SUMMARY}\n")
	if err != nil {
		return nil, err
	}

	pinned, err := z.getPinnedSet(ctx)
	if err != nil {
		return nil, err
	}

	packages := make([]Package, 0)
	scanner := newLineScanner(out)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
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
	return packages, nil
}

// ListUpgradable lists packages with an available upgrade. zypper signals
// "updates available" / "patches needed" with informational exit codes
// (100–103) that are not failures, so those are accepted alongside 0.
func (z *zypper) ListUpgradable(ctx context.Context) ([]PackageUpdate, error) {
	res, err := runRead(ctx, z.r, "zypper", "--non-interactive", "list-updates")
	if err != nil {
		return nil, err
	}
	if !isZypperInfoExit(res.ExitCode) {
		return nil, asCommandError("zypper", res)
	}

	updates := make([]PackageUpdate, 0)
	scanner := newLineScanner(res.Stdout)
	headerPassed := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+-") {
			headerPassed = true
			continue
		}
		if !headerPassed {
			continue
		}
		// S | Repository | Name | Current Version | Available Version | Arch
		parts := strings.Split(line, "|")
		if len(parts) < 5 {
			continue
		}
		name := strings.TrimSpace(parts[2])
		if name == "" {
			continue
		}
		arch := ""
		if len(parts) > 5 {
			arch = strings.TrimSpace(parts[5])
		}
		updates = append(updates, PackageUpdate{
			Name:           name,
			Repository:     strings.TrimSpace(parts[1]),
			CurrentVersion: strings.TrimSpace(parts[3]),
			NewVersion:     strings.TrimSpace(parts[4]),
			Architecture:   arch,
		})
	}
	return updates, nil
}

// Show returns detailed information about a package.
func (z *zypper) Show(ctx context.Context, name string) (*Package, error) {
	if err := validate.PackageName(name); err != nil {
		return nil, err
	}
	out, err := readOut(ctx, z.r, "zypper", "--non-interactive", "info", name)
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
		case strings.HasPrefix(line, "Arch"):
			pkg.Architecture = parseColonValue(line)
		case strings.HasPrefix(line, "Summary"):
			pkg.Description = parseColonValue(line)
		case strings.HasPrefix(line, "Installed Size"):
			size, err := parseZypperSize(parseColonValue(line))
			if err != nil {
				return nil, err
			}
			pkg.Size = size
		case strings.HasPrefix(line, "Repository"):
			pkg.Repository = parseColonValue(line)
		case strings.HasPrefix(line, "Status"):
			if strings.Contains(strings.ToLower(parseColonValue(line)), "installed") {
				pkg.Status = "installed"
			}
		}
	}

	installed, err := z.IsInstalled(ctx, name)
	if err != nil {
		return nil, err
	}
	if installed {
		pkg.Status = "installed"
	}
	pinned, err := z.IsPinned(ctx, name)
	if err != nil {
		return nil, err
	}
	pkg.Pinned = pinned
	return pkg, nil
}

// ListVersions lists the versions available for a package.
func (z *zypper) ListVersions(ctx context.Context, name string) (*VersionInfo, error) {
	if err := validate.PackageName(name); err != nil {
		return nil, err
	}
	// search exits 104 for "no matches" (as Search treats it) — a benign empty
	// result, not a failure. A runner/context failure still propagates.
	res, err := runRead(ctx, z.r, "zypper", "--non-interactive", "search", "-s", "--match-exact", name)
	if err != nil {
		return nil, err
	}

	info := &VersionInfo{Name: name}
	installed, err := z.InstalledVersion(ctx, name)
	if err != nil {
		return nil, err
	}
	info.Installed = installed

	if res.ExitCode == 104 {
		return info, nil // no matching package
	}
	if res.ExitCode != 0 {
		return nil, asCommandError("zypper", res)
	}

	seen := make(map[string]bool)
	scanner := newLineScanner(res.Stdout)
	headerPassed := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+-") {
			headerPassed = true
			continue
		}
		if !headerPassed {
			continue
		}
		// S | Name | Type | Version | Arch | Repository
		parts := strings.Split(line, "|")
		if len(parts) < 6 {
			continue
		}
		if strings.TrimSpace(parts[1]) != name {
			continue
		}
		version := strings.TrimSpace(parts[3])
		if seen[version] {
			continue
		}
		seen[version] = true
		info.Versions = append(info.Versions, AvailableVersion{
			Version:    version,
			Repository: strings.TrimSpace(parts[5]),
		})
	}
	return info, nil
}

// LocalPackageInfo reads the canonical NAME/VERSION-RELEASE/ARCH out of a local
// .rpm via the shared rpmLocalPackageInfo helper (an unprivileged `rpm -qp --qf`
// read), re-validating the untrusted %{NAME} with validate.RpmPackageName before
// returning it.
func (z *zypper) LocalPackageInfo(ctx context.Context, path string) (*LocalPackage, error) {
	return rpmLocalPackageInfo(ctx, z.r, path)
}

// IsInstalled reports whether a package is installed (rpm -q exits 0).
func (z *zypper) IsInstalled(ctx context.Context, name string) (bool, error) {
	if err := validate.PackageName(name); err != nil {
		return false, err
	}
	res, err := runRead(ctx, z.r, "rpm", "-q", name)
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
func (z *zypper) InstalledVersion(ctx context.Context, name string) (string, error) {
	if err := validate.PackageName(name); err != nil {
		return "", err
	}
	res, err := runRead(ctx, z.r, "rpm", "-q", "--queryformat", "%{VERSION}-%{RELEASE}", name)
	if err != nil {
		return "", err
	}
	if res.ExitCode == 1 {
		return "", nil
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

// InstalledCount returns the number of installed packages (via rpm).
func (z *zypper) InstalledCount(ctx context.Context) (int, error) {
	out, err := readOut(ctx, z.r, "rpm", "-qa", "--qf", ".\n")
	if err != nil {
		return 0, err
	}
	return countNonEmptyLines(out), nil
}

// HasUpdates reports whether any update is available (list-updates: exit 100, or
// exit 0 with an update/patch table row).
func (z *zypper) HasUpdates(ctx context.Context, securityOnly bool) (bool, error) {
	args := []string{"--non-interactive", "list-updates"}
	if securityOnly {
		args = append(args, "--type", "patch", "--category", "security")
	}
	res, err := runRead(ctx, z.r, "zypper", args...)
	if err != nil {
		return false, err
	}
	if !isZypperInfoExit(res.ExitCode) {
		return false, asCommandError("zypper", res)
	}
	if res.ExitCode != 0 {
		return true, nil
	}
	scanner := newLineScanner(res.Stdout)
	headerPassed := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "v |") || strings.Contains(line, "i |") {
			return true, nil
		}
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+-") {
			headerPassed = true
			continue
		}
		if securityOnly && headerPassed && strings.Count(line, "|") >= 2 && strings.Trim(strings.ReplaceAll(line, "|", ""), " -+") != "" {
			return true, nil
		}
	}
	return false, nil
}

// Pin holds packages back (zypper addlock).
func (z *zypper) Pin(ctx context.Context, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	return z.write(ctx, append([]string{"--non-interactive", "addlock"}, packages...)...)
}

// Unpin releases held packages (zypper removelock).
func (z *zypper) Unpin(ctx context.Context, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	return z.write(ctx, append([]string{"--non-interactive", "removelock"}, packages...)...)
}

// ListPinned lists locked packages.
func (z *zypper) ListPinned(ctx context.Context) ([]Package, error) {
	out, err := readOut(ctx, z.r, "zypper", "--non-interactive", "locks")
	if err != nil {
		return nil, err
	}

	packages := make([]Package, 0)
	scanner := newLineScanner(out)
	headerPassed := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+-") {
			headerPassed = true
			continue
		}
		if !headerPassed {
			continue
		}
		m := zypperLockRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		version, err := z.InstalledVersion(ctx, m[1])
		if err != nil {
			return nil, err
		}
		packages = append(packages, Package{
			Name:    m[1],
			Version: version,
			Status:  "installed",
			Pinned:  true,
		})
	}
	return packages, nil
}

// IsPinned reports whether a package is locked.
func (z *zypper) IsPinned(ctx context.Context, name string) (bool, error) {
	if err := validate.PackageName(name); err != nil {
		return false, err
	}
	out, ok, err := probe(ctx, z.r, "zypper", -1, "--non-interactive", "locks")
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	scanner := newLineScanner(out)
	for scanner.Scan() {
		if match := zypperLockRe.FindStringSubmatch(scanner.Text()); len(match) >= 2 && match[1] == name {
			return true, nil
		}
	}
	return false, nil
}

func (z *zypper) getPinnedSet(ctx context.Context) (map[string]bool, error) {
	out, ok, err := probe(ctx, z.r, "zypper", -1, "--non-interactive", "locks")
	if err != nil {
		return nil, err
	}
	if !ok {
		return map[string]bool{}, nil
	}
	pinned := make(map[string]bool)
	scanner := newLineScanner(out)
	for scanner.Scan() {
		if m := zypperLockRe.FindStringSubmatch(scanner.Text()); len(m) >= 2 {
			pinned[m[1]] = true
		}
	}
	return pinned, nil
}

func parseZypperSize(s string) (int64, error) {
	return parseSizeWithUnits(s, []sizeUnit{
		{" KiB", 1024},
		{" MiB", 1024 * 1024},
		{" GiB", 1024 * 1024 * 1024},
		{" B", 1},
	})
}
