//go:build linux && arm64

package fsafe

// SYS_RENAMEAT2 on linux/arm64 — stable kernel ABI, absent from the stdlib
// syscall table.
const sysRenameat2 = 276
