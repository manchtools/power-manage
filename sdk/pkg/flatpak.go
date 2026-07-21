package pkg

import (
	"context"
	"fmt"
	"strings"

	pmexec "github.com/manchtools/power-manage/sdk/exec"
	"github.com/manchtools/power-manage/sdk/rollback"
	"github.com/manchtools/power-manage/sdk/validate"
)

// flatpak drives the cross-distro application bundle manager over an injected
// Runner. system selects the --system installation (escalated) over --user
// (unprivileged); see WithUserScope.
type flatpak struct {
	r      pmexec.Runner
	system bool
}

var (
	_ Manager        = (*flatpak)(nil)
	_ FlatpakManager = (*flatpak)(nil)
)

func (f *flatpak) Backend() Backend { return Flatpak }

// scope returns the installation-scope flag for the configured mode.
func (f *flatpak) scope() string {
	if f.system {
		return "--system"
	}
	return "--user"
}

// write runs a privileged flatpak command. It escalates only in system scope;
// --user operations run unprivileged. The command Result is returned on both
// the success and non-zero-exit paths.
func (f *flatpak) write(ctx context.Context, args ...string) (pmexec.Result, error) {
	res, err := runPriv(ctx, f.r, f.system, nil, "flatpak", args...)
	if err != nil {
		return pmexec.Result{}, err
	}
	return res, asCommandError("flatpak", res)
}

// Version returns the flatpak version string ("Flatpak 1.14.4").
func (f *flatpak) Version(ctx context.Context) (string, error) {
	out, err := readOut(ctx, f.r, "flatpak", "--version")
	if err != nil {
		return "", err
	}
	parts := strings.Fields(out)
	if len(parts) >= 2 {
		return parts[1], nil
	}
	return "", fmt.Errorf("%w: flatpak returned no version", ErrMalformedOutput)
}

// Install installs application bundles. Flatpak does not support traditional
// version pinning, so opts.Version is validated but ignored (use commits/refs
// for exact version control). All named bundles are installed at latest.
func (f *flatpak) Install(ctx context.Context, opts InstallOptions, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if err := validate.PackageVersion(opts.Version); err != nil {
		return pmexec.Result{}, err
	}
	if opts.Remote != "" {
		if err := validate.FlatpakRemoteName(opts.Remote); err != nil {
			return pmexec.Result{}, err
		}
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	// An explicit remote is the operator's disambiguation of which remote provides
	// the app; it precedes the app refs (`flatpak install <scope> <remote> <refs>`).
	// validate.FlatpakRemoteName has rejected a flag-shaped value, so it is a safe operand.
	args := []string{"install", "-y", "--noninteractive", f.scope()}
	if opts.Remote != "" {
		args = append(args, opts.Remote)
	}
	args = append(args, packages...)
	return f.write(ctx, args...)
}

// InstallLocal installs a local flatpak bundle (a single-file .flatpak) or a
// .flatpakref. A bundle has no version-ordering concept, so opts.AllowDowngrade
// is ignored; opts.AllowUnsigned is a no-op (a bundle's signing is not a
// per-file GPG check). System scope escalates, --user does not.
// validate.LocalPackagePath requires an absolute path, so the operand can never
// be flag-shaped.
func (f *flatpak) InstallLocal(ctx context.Context, path string, _ InstallLocalOptions) (pmexec.Result, error) {
	if err := validate.LocalPackagePath(path); err != nil {
		return pmexec.Result{}, err
	}
	flags := []string{"install", "-y", "--noninteractive", f.scope()}
	return f.write(ctx, append(flags, path)...)
}

// Remove uninstalls bundles; opts.Purge also deletes per-app data (--delete-data).
func (f *flatpak) Remove(ctx context.Context, opts RemoveOptions, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	args := []string{"uninstall", "-y", "--noninteractive"}
	if opts.Purge {
		args = append(args, "--delete-data")
	}
	args = append(args, f.scope())
	args = append(args, packages...)
	return f.write(ctx, args...)
}

// Update refreshes appstream metadata for the configured remotes.
func (f *flatpak) Update(ctx context.Context) (pmexec.Result, error) {
	return f.write(ctx, "update", "--appstream", "-y", "--noninteractive", f.scope())
}

// Upgrade updates the named bundles, or all installed bundles with no names.
func (f *flatpak) Upgrade(ctx context.Context, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	if len(packages) == 0 {
		return pmexec.Result{}, nil // empty is a no-op; UpgradeAll updates everything (flatpak update with no refs)
	}
	args := append([]string{"update", "-y", "--noninteractive", f.scope()}, packages...)
	return f.write(ctx, args...)
}

// UpgradeAll updates every installed app/runtime (flatpak update with no refs).
func (f *flatpak) UpgradeAll(ctx context.Context, opts UpgradeOptions) (pmexec.Result, error) {
	if opts.SecurityOnly {
		// flatpak has no security/non-security update distinction — it updates
		// apps/runtimes to latest. Fail closed rather than do a full update.
		return pmexec.Result{}, ErrSecurityOnlyUnsupported
	}
	return f.write(ctx, "update", "-y", "--noninteractive", f.scope())
}

// Autoremove removes unused runtimes/extensions (flatpak uninstall --unused).
func (f *flatpak) Autoremove(ctx context.Context) (pmexec.Result, error) {
	return f.write(ctx, "uninstall", "--unused", "-y", "--noninteractive", f.scope())
}

// Search searches configured remotes (exit 1 = no matches).
func (f *flatpak) Search(ctx context.Context, query string) ([]SearchResult, error) {
	if err := validate.SearchQuery(query); err != nil {
		return nil, err
	}
	res, err := runRead(ctx, f.r, "flatpak", "search", query)
	if err != nil {
		return nil, err
	}
	if res.ExitCode == 1 {
		return []SearchResult{}, nil
	}
	if res.ExitCode != 0 {
		return nil, asCommandError("flatpak", res)
	}

	results := make([]SearchResult, 0)
	scanner := newLineScanner(res.Stdout)
	// The first line is a header iff it has no tab; otherwise it is data.
	if scanner.Scan() {
		first := scanner.Text()
		if strings.Contains(first, "\t") {
			if r := parseFlatpakSearchLine(first); r != nil {
				results = append(results, *r)
			}
		}
	}
	for scanner.Scan() {
		if r := parseFlatpakSearchLine(scanner.Text()); r != nil {
			results = append(results, *r)
		}
	}
	return results, nil
}

// List lists installed application bundles.
func (f *flatpak) List(ctx context.Context) ([]Package, error) {
	out, err := readOut(ctx, f.r, "flatpak", "list",
		"--columns=application,version,arch,size,description,origin", f.scope())
	if err != nil {
		return nil, err
	}

	pinned, err := f.getPinnedSet(ctx)
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
		desc := ""
		if len(fields) > 4 {
			desc = fields[4]
		}
		repo := ""
		if len(fields) > 5 {
			repo = fields[5]
		}
		size, err := parseFlatpakSize(fields[3])
		if err != nil {
			continue
		}
		packages = append(packages, Package{
			Name:         fields[0],
			Version:      fields[1],
			Architecture: fields[2],
			Status:       "installed",
			Size:         size,
			Description:  desc,
			Repository:   repo,
			Pinned:       pinned[fields[0]],
		})
	}
	return packages, nil
}

// ListUpgradable lists bundles with an available update.
func (f *flatpak) ListUpgradable(ctx context.Context) ([]PackageUpdate, error) {
	out, err := readOut(ctx, f.r, "flatpak", "remote-ls", "--updates",
		"--columns=application,version,origin", f.scope())
	if err != nil {
		return nil, err
	}

	updates := make([]PackageUpdate, 0)
	scanner := newLineScanner(out)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 2 {
			continue
		}
		repo := ""
		if len(fields) > 2 {
			repo = fields[2]
		}
		current, err := f.InstalledVersion(ctx, fields[0])
		if err != nil {
			return nil, err
		}
		updates = append(updates, PackageUpdate{
			Name:           fields[0],
			NewVersion:     fields[1],
			CurrentVersion: current,
			Repository:     repo,
		})
	}
	return updates, nil
}

// Show returns detailed information about a bundle, falling back to the flathub
// remote when the bundle is not installed.
func (f *flatpak) Show(ctx context.Context, name string) (*Package, error) {
	if err := validate.PackageName(name); err != nil {
		return nil, err
	}
	// A non-zero `flatpak info` exit means the bundle is not installed locally —
	// fall back to the remote. A runner/context failure propagates.
	out, ok, err := probe(ctx, f.r, "flatpak", 1, "info", name, f.scope())
	if err != nil {
		return nil, err
	}
	if !ok {
		return f.showFromRemote(ctx, name)
	}

	pkg := &Package{Name: name, Status: "installed"}
	scanner := newLineScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Version:"):
			pkg.Version = parseFlatpakValue(line)
		case strings.HasPrefix(line, "Arch:"):
			pkg.Architecture = parseFlatpakValue(line)
		case strings.HasPrefix(line, "Description:"):
			pkg.Description = parseFlatpakValue(line)
		case strings.HasPrefix(line, "Installed:"), strings.HasPrefix(line, "Size:"):
			size, err := parseFlatpakSize(parseFlatpakValue(line))
			if err != nil {
				return nil, err
			}
			pkg.Size = size
		case strings.HasPrefix(line, "Origin:"):
			pkg.Repository = parseFlatpakValue(line)
		}
	}

	pinned, err := f.IsPinned(ctx, name)
	if err != nil {
		return nil, err
	}
	pkg.Pinned = pinned
	return pkg, nil
}

func (f *flatpak) showFromRemote(ctx context.Context, name string) (*Package, error) {
	// A runner/context failure propagates; a non-zero exit means the bundle is
	// not offered by the remote.
	out, ok, err := probe(ctx, f.r, "flatpak", 1, "remote-info", "flathub", name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("package not found: %s", name)
	}

	pkg := &Package{Name: name, Status: "available", Repository: "flathub"}
	scanner := newLineScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Version:"):
			pkg.Version = parseFlatpakValue(line)
		case strings.HasPrefix(line, "Arch:"):
			pkg.Architecture = parseFlatpakValue(line)
		case strings.HasPrefix(line, "Description:"):
			pkg.Description = parseFlatpakValue(line)
		case strings.HasPrefix(line, "Download:"), strings.HasPrefix(line, "Size:"):
			size, err := parseFlatpakSize(parseFlatpakValue(line))
			if err != nil {
				return nil, err
			}
			pkg.Size = size
		}
	}
	return pkg, nil
}

// ListVersions reports the single remote (flathub) version for a bundle.
func (f *flatpak) ListVersions(ctx context.Context, name string) (*VersionInfo, error) {
	if err := validate.PackageName(name); err != nil {
		return nil, err
	}
	info := &VersionInfo{Name: name}
	installed, err := f.InstalledVersion(ctx, name)
	if err != nil {
		return nil, err
	}
	info.Installed = installed

	out, ok, err := probe(ctx, f.r, "flatpak", 1, "remote-info", "flathub", name)
	if err != nil {
		return nil, err // runner/context failure
	}
	if !ok {
		return info, nil // not available on flathub
	}
	scanner := newLineScanner(out)
	for scanner.Scan() {
		if line := scanner.Text(); strings.HasPrefix(line, "Version:") {
			info.Versions = append(info.Versions, AvailableVersion{
				Version:    parseFlatpakValue(line),
				Repository: "flathub",
			})
			break
		}
	}
	return info, nil
}

// LocalPackageInfo is not supported for flatpak: a .flatpak bundle has no clean,
// non-installing name-introspection command (its ref must be trusted from the
// bundle metadata, which `flatpak install` itself reads), so rather than guess a
// name from an attacker-influenced bundle this fails closed with a clear error.
func (f *flatpak) LocalPackageInfo(_ context.Context, _ string) (*LocalPackage, error) {
	return nil, fmt.Errorf("pkg: LocalPackageInfo is not supported for flatpak (a bundle has no introspectable local package name)")
}

// IsInstalled reports whether a bundle is installed (flatpak info exits 0).
func (f *flatpak) IsInstalled(ctx context.Context, name string) (bool, error) {
	if err := validate.PackageName(name); err != nil {
		return false, err
	}
	res, err := runRead(ctx, f.r, "flatpak", "info", name, f.scope())
	if err != nil {
		return false, err
	}
	if res.ExitCode == 0 {
		return true, nil
	}
	if res.ExitCode == 1 {
		return false, nil
	}
	return false, asCommandError("flatpak", res)
}

// InstalledVersion returns the installed version of a bundle, or "" if absent.
func (f *flatpak) InstalledVersion(ctx context.Context, name string) (string, error) {
	if err := validate.PackageName(name); err != nil {
		return "", err
	}
	res, err := runRead(ctx, f.r, "flatpak", "info", "--show-version", name, f.scope())
	if err != nil {
		return "", err
	}
	if res.ExitCode == 1 {
		return "", nil
	}
	if res.ExitCode != 0 {
		return "", asCommandError("flatpak", res)
	}
	version := strings.TrimSpace(res.Stdout)
	if version == "" {
		return "", fmt.Errorf("%w: flatpak returned an empty version", ErrMalformedOutput)
	}
	return version, nil
}

// InstalledCount returns the number of installed bundles.
func (f *flatpak) InstalledCount(ctx context.Context) (int, error) {
	out, err := readOut(ctx, f.r, "flatpak", "list", "--columns=application", f.scope())
	if err != nil {
		return 0, err
	}
	return countNonEmptyLines(out), nil
}

// HasUpdates reports whether any bundle has an available update. Flatpak has no
// security-only feed, so securityOnly is ignored.
func (f *flatpak) HasUpdates(ctx context.Context, securityOnly bool) (bool, error) {
	_ = securityOnly
	out, err := readOut(ctx, f.r, "flatpak", "remote-ls", "--updates", "--columns=application", f.scope())
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(out) != "", nil
}

// Pin masks bundles so they are held back from updates. A later mask failure
// restores every earlier bundle's pre-call mask state.
func (f *flatpak) Pin(ctx context.Context, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	return f.changeMasks(ctx, true, packages)
}

// Unpin removes masks atomically across the requested set.
func (f *flatpak) Unpin(ctx context.Context, packages ...string) (pmexec.Result, error) {
	if err := validatePackageNames(packages); err != nil {
		return pmexec.Result{}, err
	}
	return f.changeMasks(ctx, false, packages)
}

func (f *flatpak) changeMasks(ctx context.Context, desired bool, packages []string) (pmexec.Result, error) {
	if len(packages) == 0 {
		return pmexec.Result{}, nil
	}
	pinned, err := f.getPinnedSet(ctx)
	if err != nil {
		return pmexec.Result{}, err
	}
	var last pmexec.Result
	steps := make([]rollback.Step, 0, len(packages))
	seen := make(map[string]bool, len(packages))
	for _, name := range packages {
		if seen[name] || pinned[name] == desired {
			continue
		}
		seen[name] = true
		name := name
		steps = append(steps, rollback.Step{
			Name: "flatpak mask " + name,
			Apply: func(ctx context.Context) error {
				if desired {
					last, err = f.write(ctx, "mask", name, f.scope())
				} else {
					last, err = f.write(ctx, "mask", "--remove", name, f.scope())
				}
				return err
			},
			Rollback: func(ctx context.Context) error {
				if desired {
					_, err := f.write(ctx, "mask", "--remove", name, f.scope())
					return err
				}
				_, err := f.write(ctx, "mask", name, f.scope())
				return err
			},
		})
	}
	runErr := rollback.Run(ctx, steps...)
	return last, runErr
}

// ListPinned lists masked bundles.
func (f *flatpak) ListPinned(ctx context.Context) ([]Package, error) {
	out, err := readOut(ctx, f.r, "flatpak", "mask", f.scope())
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
		version, err := f.InstalledVersion(ctx, name)
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

// IsPinned reports whether a bundle is masked.
func (f *flatpak) IsPinned(ctx context.Context, name string) (bool, error) {
	if err := validate.PackageName(name); err != nil {
		return false, err
	}
	out, ok, err := probe(ctx, f.r, "flatpak", -1, "mask", f.scope())
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}
	scanner := newLineScanner(out)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == name {
			return true, nil
		}
	}
	return false, nil
}

func (f *flatpak) getPinnedSet(ctx context.Context) (map[string]bool, error) {
	out, ok, err := probe(ctx, f.r, "flatpak", -1, "mask", f.scope())
	if err != nil {
		return nil, err
	}
	if !ok {
		return map[string]bool{}, nil
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

// AddRemote registers a flatpak remote. name must be a valid remote alias and
// url an https repository URL (validated to keep flag/metacharacter and
// plaintext-transport inputs off the argv and out of the trust path).
func (f *flatpak) AddRemote(ctx context.Context, name, url string) error {
	if err := validate.FlatpakRemoteName(name); err != nil {
		return err
	}
	if err := validate.RepoBaseURL(url); err != nil {
		return err
	}
	// Remote management is configuration, not a package transaction, so it keeps
	// the error-only contract; the command output is not surfaced as an action.
	_, err := f.write(ctx, "remote-add", "--if-not-exists", name, url, f.scope())
	return err
}

// RemoveRemote deletes a flatpak remote.
func (f *flatpak) RemoveRemote(ctx context.Context, name string) error {
	if err := validate.FlatpakRemoteName(name); err != nil {
		return err
	}
	_, err := f.write(ctx, "remote-delete", "--force", name, f.scope())
	return err
}

// ListRemotes returns the configured flatpak remote names.
func (f *flatpak) ListRemotes(ctx context.Context) ([]string, error) {
	out, err := readOut(ctx, f.r, "flatpak", "remotes", "--columns=name", f.scope())
	if err != nil {
		return nil, err
	}
	remotes := make([]string, 0)
	scanner := newLineScanner(out)
	for scanner.Scan() {
		if name := strings.TrimSpace(scanner.Text()); name != "" {
			remotes = append(remotes, name)
		}
	}
	return remotes, nil
}

func parseFlatpakSearchLine(line string) *SearchResult {
	// Name\tDescription\tApplication ID\tVersion\tBranch\tRemotes
	fields := strings.Split(line, "\t")
	if len(fields) < 3 {
		return nil
	}
	return &SearchResult{
		Name:        fields[2], // application ID
		Description: fields[1],
	}
}

func parseFlatpakValue(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func parseFlatpakSize(s string) (int64, error) {
	// flatpak's human sizes can carry thousands separators ("1,536 MB"); strip
	// them before the shared unit parser, which only space-trims.
	s = strings.ReplaceAll(s, ",", "")
	return parseSizeWithUnits(s, []sizeUnit{
		{" kB", 1000},
		{" KB", 1000},
		{" KiB", 1024},
		{" MB", 1000 * 1000},
		{" MiB", 1024 * 1024},
		{" GB", 1000 * 1000 * 1000},
		{" GiB", 1024 * 1024 * 1024},
		{" bytes", 1},
	})
}
