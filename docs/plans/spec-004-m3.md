# SPEC-004 M3 — Filesystem

Milestone: SPEC-004 §9 M3 ([SDK-7..9], AC-9..13). PROC-6 port of the
predecessor `sdk/sys/fs` (MIT, no per-file headers) into `sdk/fsafe` —
the G-7-sanctioned package name — plus a NEW `sdk/fetch` package for
the SSRF/transport guard ([SDK-9] second half, AC-13; the predecessor
has no IP-level guard to port). Mechanical milestone; tests authored
from the matrix below. Delta only; the spec is authoritative.

## Recorded mechanical choices

1. **Package `sdk/fsafe`**, not the predecessor's `fs`: G-7 recorded
   `fsafe` as the mutation-chokepoint prefix at M1, and the name avoids
   shadowing stdlib `io/fs`.
2. **Streaming write core** ([SDK-9] rework, AC-12). The predecessor's
   `safeReplaceFile(path, data []byte, …)` buffers whole contents and
   its backup path does `io.ReadAll`; neither ports. The rewrite core
   is `replaceFileFrom(path string, src io.Reader, …)` — `io.Copy`
   into the O_NOFOLLOW temp fd, fsync, rename — with bounded memory by
   construction. Manager gets `WriteFile(ctx, path, []byte, opts)` as
   convenience over the core and `WriteFileFrom(ctx, path, io.Reader,
   opts)` as the AC-12 surface; the backup copy streams fd→temp.
3. **Protected prefixes symmetric + resolving** ([SDK-8] rework,
   AC-11). `IsUnderProtectedPrefix` ports (subtree prefix roots plus
   the `/` and `/var` exact top-ups — the primary semantic is prefix;
   the exact entries only ADD the two roots whose children stay
   deletable). NEW: `ResolvesUnderProtectedPrefix` resolves symlinks
   (EvalSymlinks on the deepest existing ancestor, predecessor
   `ResolveAndValidatePath` logic) before the prefix test, and BOTH
   `Mkdir` and `RemoveDir` enforce it — create-side enforcement is new;
   the predecessor gated delete only. Predicates stay exported for the
   agent's action layer (operator-supplied paths).
4. **fd-anchored primitives port as-is** ([SDK-7], AC-9): `OpenRealDir`
   (O_DIRECTORY|O_NOFOLLOW), `FchownNoFollow` (O_NOFOLLOW|O_NONBLOCK +
   IsRegular), `SetDirPermissionsNoFollow`, `ResolveOwnership`;
   random-named O_EXCL temps reopened O_NOFOLLOW, RENAME_NOREPLACE
   no-clobber rename (renameat2 on Linux, EEXIST fallback elsewhere),
   rename-replaces-a-planted-symlink swap semantics (AC-10);
   fd-anchored recursive delete (openat/unlinkat walk).
5. **Manager surface** over `exec.Runner` (Direct → fd paths, Sudo/
   Doas → single-root-shell escalated paths): ReadFile, ReadDir,
   WriteFile, WriteFileFrom, Exists, Mkdir, Remove, RemoveDir, Copy,
   CopyTree, SetMode, SetOwnership, SetOwnershipRecursive. The
   predecessor's mount surface (IsReadOnly/RemountRW/ListMounts) does
   NOT port at M3 — no [SDK-7..9] demand; it lands with the spec that
   consumes it. The escalated write's fixed `sh -c` script constant
   with positional args + stdin remains argv-only ([SDK-4]: nothing
   interpolates into the script).
6. **Copy/CopyTree port as-is** (runner `cp`) — recorded ceiling: the
   Direct write path is fd-anchored, but Copy shells `cp` on every
   backend. AC-9..12 do not cover Copy, and [SDK-7]'s named classes
   (chmod/chown, temp files, rename) stay fd-anchored. The
   setuid/setgid refusal (`validateMode`) and `ValidatePath`
   chokepoints port unchanged, as does the escalated-parent safety
   check (refuse a target whose parent a non-root user can write).
7. **NEW `sdk/fetch`** ([SDK-9], AC-13; AG-13a mechanics — the pin
   itself is caller data: mechanism, not policy):
   - `guardAddr(network, address) error` — pure; refuses IPv4/IPv6
     loopback, link-local unicast+multicast (v4 169.254.0.0/16, which
     contains the 169.254.169.254 metadata service; v6 fe80::/10),
     unspecified, and IPv4-mapped-IPv6 spellings of all of these.
     Wired as the transport's DialContext control, so EVERY dial —
     initial, each redirect landing, every DNS-resolved address — is
     validated (AC-13).
   - Client policy: HTTPS-only at every hop; https→http refused;
     redirect hops ≤ 10; cross-origin redirect refused unless the
     fetch carries a checksum pin (AG-13a).
   - `Fetch(ctx, url, dst io.Writer, opts{MaxBytes, PinnedSHA256})` —
     size-bounded streaming; exceeding MaxBytes is an error, never
     truncation; pin verification over the streamed bytes.
   - Test seam: the address guard is a package var; tests override it
     to admit loopback (httptest) while keeping the family under test
     refused, save/restore per test — the pure guard rows cover every
     family exactly.
8. **Guards**: G-7 arms — `fsafe` is the sanctioned home of the banned
   path-mutation calls; no allowlist entries added.
   `modulePackageFloors["sdk"]` 6 → 8 (adds fsafe, fetch).
8a. **No `golang.org/x/sys` dependency.** The predecessor's fd-walk
   uses x/sys/unix; the sdk module is dependency-free and a new dep
   needs operator sign-off. Stdlib `syscall` carries Openat/Fstatat
   and the flag constants on linux; the two gaps — unlinkat WITH
   flags (AT_REMOVEDIR) and renameat2 (RENAME_NOREPLACE) — are two
   small raw-syscall wrappers with locally defined constants
   (linux-ABI-stable). The affected files build `//go:build linux`.
9. **Self-contained rework**: predecessor comments citing WS6/F022/
   F023 inline their rationale; no foreign ticket IDs survive the
   port.
10. **Filesystem test tier**: real `t.TempDir()` trees + real
    symlinks; threat-model rows assert against a TEST-OWNED attack-path
    list (`/etc/shadow`, `/etc/cron.d/x`, symlinked variants) — never
    by iterating the implementation's own set. AC-12's bounded-memory
    claim is structural (`io.Copy`, 32 KiB buffer); the test proves the
    streaming contract via a large generated reader plus the
    mid-stream-error row, not via a heap probe.

## Files

- `sdk/fsafe/fsafe.go` — package doc, errors, WriteOptions/
  MkdirOptions, Manager, New, runner plumbing, validateMode/modeArg,
  ValidatePath, Ownership (choices 5, 6).
- `sdk/fsafe/safe_fd_unix.go` — OpenRealDir, FchownNoFollow,
  SetDirPermissionsNoFollow, ResolveOwnership (choice 4).
- `sdk/fsafe/replace.go` — replaceFileFrom (streaming), backup-and-
  replace, safeRename (renameat2 linux / fallback other) (choices 2, 4).
- `sdk/fsafe/write.go` — WriteFile/WriteFileFrom direct + escalated
  paths, escalated write script (choices 2, 5).
- `sdk/fsafe/protected.go` — prefix roots, exact top-ups,
  IsProtectedPath, IsUnderProtectedPrefix,
  ResolvesUnderProtectedPrefix (choice 3).
- `sdk/fsafe/resolve.go` — ResolveAndValidatePath port (choice 3).
- `sdk/fsafe/dir.go`, `remove_dir_unix.go`, `escalated_parent_unix.go`,
  `read.go`, `readdir.go`, `ownership_unix.go` — ports (choices 4–6).
- `sdk/fetch/fetch.go` — guardAddr, client construction, redirect
  policy, Fetch (choice 7).
- `sdk/guardtest/imports.go` — sdk floor 6 → 8 (choice 8).
- `docs/content/01-specs/00-index.md` — ledger line.

## Test matrix (red-first; port names where the estate ports)

- **AC-9 fd anchoring**: `TestOpenRealDir_RefusesSymlink` /
  `_RefusesNonDirectory`, `TestFchownNoFollow_RefusesSymlink` (planted
  symlink → error, victim untouched), `_RefusesNonRegular` (fifo),
  `TestSetDirPermissionsNoFollow_RefusesSymlinkedDir` + mode-applied
  row, `TestResolveOwnership` rows (names, numerics, unknown → error).
- **AC-10 temp + swap**: `TestReplaceFile_TempIsRandomOEXCL`,
  `TestReplaceFile_SwapReplacesPlantedSymlink` (dest becomes a regular
  file; symlink target untouched), `TestReplaceFile_NoClobber`
  (RENAME_NOREPLACE refuses an existing dest), mid-write temp symlink
  swap → ELOOP.
- **AC-11 protected prefixes**: `TestMkdir_RefusesProtectedPrefix` AND
  `TestRemoveDir_RefusesProtectedPrefix` over the test-owned attack
  list, including child paths and a symlink resolving into `/etc`;
  positive rows for legitimately deletable paths (`/var/log/app`).
- **AC-12 streaming**: `TestWriteFileFrom_LargeContentStreams` (64 MiB
  generated reader → file content correct), `_MidStreamErrorLeavesOriginal`
  (erroring reader → original bytes intact, no temp litter).
- **AC-13 SSRF/transport**: pure `guardAddr` rows (v4/v6 loopback,
  169.254.169.254, fe80::1, ::, v4-mapped loopback; public addr
  allowed); client rows: `http://` refused, https→http redirect
  refused, 11 hops refused (10 allowed), cross-origin unpinned refused
  / pinned followed, redirect-to-metadata refused at dial,
  MaxBytes+1 → error, pin mismatch → error.
- **Escalated tier (FakeRunner)**: WriteFile/Mkdir/Remove/RemoveDir/
  SetMode/SetOwnership argv recorded and exact; ENOENT stderr
  classification; unsafe-parent refusal; setuid mode refused before
  any command.
- **Guards**: suite green with floor 8; G-7 population includes fsafe
  internals only through its sanctioned prefix.

## 8b. G-5 reconciliation (mechanical, discovered at implementation)

The fetch pin check needs `crypto/sha256`; G-5 bans hash imports outside
`sdk/crypto`, and G-6's population floor ("crypto exists" ⇒ "≥1 seal/open
export") rules out landing a digest-only chokepoint before M5. Resolution:
a FILE-keyed G-5 exemption (`hashImportAllow = {crypto, fetch/fetch.go}`)
with rationale — the pin is digest VERIFICATION against a published value,
not a domain-separated construction — and an M5 sunset: fold the digest
into sdk/crypto and drop the key. Narrowness proven red: a second sha256
import elsewhere in the fetch package trips the guard.
