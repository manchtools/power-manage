//go:build linux

package fsafe

import (
	"syscall"
	"unsafe"
)

// openat-family constants the syscall package does not export on linux.
const (
	atFdcwd         = -0x64 // AT_FDCWD
	atRemoveDir     = 0x200 // AT_REMOVEDIR
	renameNoReplace = 0x1   // RENAME_NOREPLACE
)

// renameat2 wraps SYS_RENAMEAT2 (absent from the stdlib syscall surface; the
// syscall number itself is per-arch, see sysnum_*.go). The flags argument is
// what makes an atomic no-clobber rename possible. A package-var seam so a test
// can force the pre-RENAME_NOREPLACE fallback (ENOSYS) without an old kernel.
var renameat2 = func(oldPath, newPath string, flags uint) error {
	oldp, err := syscall.BytePtrFromString(oldPath)
	if err != nil {
		return err
	}
	newp, err := syscall.BytePtrFromString(newPath)
	if err != nil {
		return err
	}
	fdcwd := atFdcwd
	_, _, errno := syscall.Syscall6(sysRenameat2,
		uintptr(fdcwd), uintptr(unsafe.Pointer(oldp)),
		uintptr(fdcwd), uintptr(unsafe.Pointer(newp)),
		uintptr(flags), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// unlinkatFlags wraps SYS_UNLINKAT with flags — syscall.Unlinkat exposes
// none, and AT_REMOVEDIR is required for the fd-anchored rmdir.
func unlinkatFlags(dirfd int, name string, flags int) error {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(syscall.SYS_UNLINKAT,
		uintptr(dirfd), uintptr(unsafe.Pointer(p)), uintptr(flags))
	if errno != 0 {
		return errno
	}
	return nil
}
