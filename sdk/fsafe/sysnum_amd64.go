//go:build linux && amd64

package fsafe

// SYS_RENAMEAT2 on linux/amd64 — stable kernel ABI, absent from the stdlib
// syscall table.
const sysRenameat2 = 316
