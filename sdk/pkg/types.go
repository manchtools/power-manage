package pkg

// Package represents an installed or available package.
type Package struct {
	Name         string
	Version      string
	Architecture string
	Description  string
	Status       string // installed, available, upgradable, pinned
	Size         int64  // installed size in bytes
	Repository   string
	Pinned       bool // whether the package is pinned (hold)
}

// LocalPackage is the identity read out of a LOCAL package file (a .deb, .rpm or
// pacman package on disk) by Manager.LocalPackageInfo. Name is the canonical
// package name — validated against the backend's package-name grammar before it
// is returned, because the value is read out of an attacker-influenced file.
// Version and Arch are best-effort extra fields (a backend that cannot report
// one leaves it empty).
type LocalPackage struct {
	Name    string
	Version string
	Arch    string
}

// PackageUpdate represents an available update for a package.
type PackageUpdate struct {
	Name           string
	CurrentVersion string
	NewVersion     string
	Architecture   string
	Repository     string
}

// SearchResult represents a package search result.
type SearchResult struct {
	Name        string
	Version     string
	Description string
	Repository  string
}

// VersionInfo represents available versions of a package.
type VersionInfo struct {
	Name      string
	Versions  []AvailableVersion
	Installed string // currently installed version, empty if not installed
}

// AvailableVersion represents a specific version available for installation.
type AvailableVersion struct {
	Version    string
	Repository string
	Size       int64
}

// InstallOptions configures an Install call.
type InstallOptions struct {
	// Version pins the install to a specific version. When set, exactly one
	// package name must be given (a version applies to a single package).
	Version string
	// AllowDowngrade permits installing a lower version than the one installed.
	AllowDowngrade bool
	// Remote names the flatpak remote to install FROM (e.g. "flathub"). It is
	// honored only by the flatpak backend — where it disambiguates which remote
	// provides the app instead of relying on flatpak's auto-resolution — and is
	// ignored by the native package managers. Empty selects flatpak's default
	// resolution.
	Remote string
}

// InstallLocalOptions configures an InstallLocal call.
type InstallLocalOptions struct {
	// AllowDowngrade permits installing a package file whose version is lower
	// than the one currently installed. Honored on apt (--allow-downgrades),
	// dnf (retried as an explicit downgrade when the install is rejected) and
	// zypper (--oldpackage). pacman -U downgrades regardless, and a flatpak
	// bundle has no version-ordering concept, so it is a no-op on those two.
	AllowDowngrade bool
	// AllowUnsigned skips the backend's GPG signature check for the local file.
	// It is secure-default-OFF: with the default (false) an unsigned local .rpm
	// is rejected by dnf/zypper. Set it ONLY when the file's authenticity is
	// established out of band — e.g. an HTTPS transport plus a verified SHA256
	// checksum — so the package manager's per-file GPG check is redundant. Per
	// backend:
	//   - dnf:    adds --nogpgcheck
	//   - zypper: adds --allow-unsigned-rpm (per-package; never the global
	//             --no-gpg-checks, which would also drop repo-metadata checks)
	//   - apt:    no-op — a local .deb carries no per-file signature to skip
	//   - pacman: NOT honored — `pacman -U` enforces the repo SigLevel and has no
	//             per-invocation bypass; the install stays signature-checked
	//   - flatpak: no-op — a bundle's signing is not a per-file GPG check
	AllowUnsigned bool
}

// RemoveOptions configures a Remove call.
type RemoveOptions struct {
	// Purge also removes configuration/data where the backend distinguishes it
	// (apt purge / pacman -Rns / flatpak --delete-data). On backends with no
	// such distinction it is equivalent to a plain remove.
	Purge bool
}
