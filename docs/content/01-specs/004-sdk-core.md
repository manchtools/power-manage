---
title: "SPEC-004 — SDK Core"
---
# SPEC-004 — SDK Core

Status: READY FOR IMPLEMENTATION / Builds on: SPEC-000, SPEC-001, SPEC-002 / Enables: SPEC-013, SPEC-014, SPEC-015 / Module(s): `sdk/` (MIT); module-boundary rules also constrain `contract/` (MIT)

## 1. Scope

The `sdk` module: a pure OS-capability library providing safe primitives —
subprocess execution (Runner), privileged filesystem mutation, input validators,
crypto helpers, error contracts, and the managed-policy-file composition
function. This spec also fixes the two-module split between `contract`
(wire contract) and `sdk` (OS mechanism), because the split is enforced from
inside the sdk's own guard suite.

Not in scope: the proto surface itself (SPEC-003), individual capability-manager
behavior per action type (SPEC-014), the agent's probe-and-inject orchestration
(SPEC-013).

## 2. Context capsule

A fresh implementer needs exactly this from prior specs:

- **Monorepo modules (SPEC-002):** `contract/` (proto sources, buf config,
  generated Go + TS; MIT), `sdk/` (this spec; MIT), `server/` (AGPL-3.0),
  `agent/` (GPL-3.0). Directional import allowlist: `contract` and `sdk` import
  no in-repo module; `agent` and `server` import only {`contract`, `sdk`}. The
  permissive modules are dependency leaves; a `sdk`→`server` import would be
  both an architecture and a licensing violation.
- **Process rules (SPEC-000):** spec → failing test → implementation. Every
  invariant ships a self-discovering fitness guard (AST scan, package walk)
  with matches-zero protection — hand-maintained lists of files/functions are
  forbidden because they go stale and fail open. V1 clean breaks; flexibility
  is a clean seam (an interface, an injected dependency), never optionality
  (config knobs, fallback backends, "just in case" paths).
- **Trust model (SPEC-001):** the SDK's primary consumer is the agent, which
  runs as root. Every SDK primitive executes with full privilege; a validator
  bypass or a symlink race in the SDK is a root-level vulnerability on every
  managed device. Fail closed, always: decode error, absent backend, or
  ambiguous input → error, never a permissive default.
- The server also consumes the sdk (shared validators), so validation grammar
  cannot drift between server-side request validation and agent-side execution
  (WIRE-3, SPEC-003).

## 3. Requirements

### 3.1 Module split and philosophy

- **[SDK-0]** Two modules, split at the proto boundary. `contract` holds proto
  sources, buf config, and generated Go + TS — the wire contract of SPEC-003,
  versioned with the release train. `sdk` is the OS capability library with
  **ZERO proto/connect/protobuf imports**, guarded by an import archtest.
  Server, agent, and web consume `contract`; only agent and server consume
  `sdk`. The contract is NOT absorbed into the server: it has three
  first-class consumers, and none of them may inherit the server's dependency
  graph.
- **[SDK-1]** Mechanism, never policy. The SDK provides safe primitives and
  validators; orchestration and decisions stay with the consumer. Identity
  checks key on UID 0, never on name lists. Explicit over clever; no global
  state; every dependency is injected (the `exec.Runner` seam, with a
  `FakeRunner` for tests); constructors fail closed on absent backends. The
  SDK never auto-detects anything — the agent probes the system once and
  injects (AG-4, SPEC-013).
- **[SDK-2]** Security tightening migrates every internal caller in the same
  change. No deprecated-but-alive unsafe sibling APIs.

### 3.2 Runner invariants (structural, not per-call)

- **[SDK-3]** Every subprocess runs under forced `LC_ALL=C`, `LANG=C`,
  `NO_COLOR=1` — an unconditional Runner invariant, not a per-command opt-in.
  Those keys are rejected in per-command env. Parsing prefers exit codes and
  count-diffs over localized strings.
- **[SDK-4]** Child environment is built from a curated allowlist baseline —
  never from `os.Environ()`. `PATH` is explicitly present. All privilege
  escalation routes through the single `exec` chokepoint. Argv is passed as
  argv (never shell strings), with `--` end-of-options before
  operator-supplied operands wherever the tool supports it.
- **[SDK-5]** Cancellation: on ctx cancel, SIGTERM → grace timer → SIGKILL the
  **process group**. Ctx is honored in every wait and read path.
- **[SDK-6]** Numeric narrowing is range-checked (a helper, not ad-hoc casts).
  Any regex that reaches a backtracking engine passes a ReDoS guard that
  propagates nested-group quantifier/alternation state — a per-group check
  that ignores nesting is insufficient.

### 3.3 Filesystem discipline

- **[SDK-7]** All privileged file/dir mutations are fd-anchored and
  symlink-refusing: no path-based chmod/chown on final components, no
  resolve-then-string-reopen, random-named `O_EXCL` temp files + no-clobber
  rename (`mv -T` semantics — never predictable temp + `tee`), parent-dir
  safety checks before every mutation.
- **[SDK-8]** Protected paths are deny-by-default subtree **PREFIXES** — never
  exact match — applied **symmetrically to create AND delete**, with symlink
  resolution included in the check. A path that resolves into a protected
  subtree is refused regardless of how it was spelled.
- **[SDK-9]** Privileged writes are streaming and atomic (bounded memory, temp
  + swap). Remote fetches are size-bounded and pass an SSRF guard:
  loopback/link-local/metadata addresses refused, every redirect re-validated,
  and the URL-transport rules (HTTPS-only, https→http refused, redirect-hop
  cap, cross-origin only when checksum-pinned — AG-13a, SPEC-013) enforced at
  every level with a fail-closed default.

### 3.4 Validators (one grammar, shared server + agent)

- **[SDK-10]** Intent grammars for every operator string that reaches argv or
  a config file: package names, repository names, GPG key references, flatpak
  names, systemd unit names, usernames. Path-embedded IDs are
  ULID-charset-restricted. Grammars must not over-constrain legitimate inputs
  (e.g., repository URL fields must accept `$releasever`-style template
  variables — a strict URL grammar there is a false rejection).
- **[SDK-11]** Any value written into a structured file (sudoers, sshd_config,
  authorized_keys, `.nmconnection` INI, passwd GECOS, deb822) rejects
  `\n`/`\r`/control characters AND the target format's structural delimiters
  (`:`, `,`, spaces in URL lists, section brackets) BEFORE writing.
  Cross-field validation is mandatory where one file is written from several
  fields — each field individually valid does not imply the composed file is.
  When a system tool's error output names a file the SDK just wrote, the SDK
  rolls the file back and fails the operation.
- **[SDK-12]** Login shells are validated against `/etc/shells`. LUKS device
  paths are shape-checked (`/dev/` prefix, no flag-like shapes). Flatpak app
  IDs are validated before any path join.

### 3.5 Crypto helpers

- **[SDK-13]** One AEAD surface: `SealWithAAD` / `OpenWithAAD` with MANDATORY
  non-empty AAD and domain-separation info strings; **no nil-AAD API exists**.
  X25519 + HKDF-SHA256 + AES-256-GCM for sealed transport; AES-256-GCM
  `enc:v1` at rest. Constant-time compares (`subtle` / `hmac.Equal`) for every
  secret and MAC. `crypto/rand` errors are checked. `math/rand` is banned
  outside an explicit jitter allowlist. IDs are ULIDs via `ulidx`. Every
  hash/MAC preimage is length-prefixed and domain-separated, always.
- **[SDK-14]** Empty key material and empty plaintext are rejected
  symmetrically at seal AND open. Documentation claims about algorithms are
  anchored to the code they describe so algorithm-name drift between docs and
  implementation fails a check.

### 3.6 Error contracts

- **[SDK-15]** A query failure is always distinguishable from an empty result:
  tool-absent → typed `ErrBackendUnavailable` (benign only where documented);
  exit-code "absent" vs "could not query" split; NEVER `(nil, nil)` for an
  unreadable resource; `scanner.Err()` always checked; parse helpers return
  errors, never a silent zero value.
- **[SDK-16]** Multi-step system changes roll back on later-step failure. If
  step 3 of 4 fails, steps 1–2 are undone; the system is never left in a
  half-applied state the caller reported as failed but the OS kept.
- **[SDK-17]** Package-manager parsing is fidelity-tested against real tools
  (round-trip: emit → real binary → parse; SPEC-017 lanes): no name truncation
  on dotted versions, no per-package fail-all listing aborts, ARM cpuinfo
  shapes handled, comment-stripping edge cases covered.

### 3.7 Managed-policy-file engine (recorded operator decision: a composition, not a subsystem)

- **[SDK-18]** The managed-policy-file behavior is ONE SDK function composed
  strictly from primitives this spec already mandates — fd-anchored atomic
  writes ([SDK-7]/[SDK-9]), delimiter/content validation ([SDK-11]), and
  Runner-executed validate/reload commands ([SDK-3..5]) — plus a three-row
  table of managed surfaces. Sequence, in order, fail-closed at every step:

  1. **Hash-compare** current file content for drift; identical → no-op
     (`changed=false`).
  2. **Write candidate** (random `O_EXCL` temp in the target directory).
  3. **Validate the CANDIDATE** — never the live file — with the surface's
     validator (`sshd -t -f <candidate>`, `visudo -c -f <candidate>`).
  4. **Swap** atomically (no-clobber rename semantics).
  5. **Reload** via the surface's reload command.
  6. **Restore the previous file on ANY failure** in steps 2–5 and fail the
     operation.

  The function supports whole-file mode and marker-delimited managed-block
  mode. **Revert-on-unassign replays the stored prior state through this same
  function** — atomicity, validation, revert, and drift detection live in
  exactly one place. The surface table:

  | Surface | Target path class | Candidate validator | Reload |
  |---|---|---|---|
  | SSH (per-action drop-in) | `sshd_config.d` drop-in | `sshd -t -f` | reload sshd |
  | SSHD (global drop-ins) | priority-ordered `sshd_config.d` drop-in | `sshd -t -f` | reload sshd |
  | ADMIN_POLICY (sudoers) | `sudoers.d` file | `visudo -c -f` | none (sudo reads at invocation) |

  Consumers configure WHICH content goes in (SPEC-014); the SDK owns HOW it
  lands. No new abstraction layer, no plugin registry, no fourth row without a
  new action type to justify it.

## 4. Acceptance criteria

- **AC-1** The `sdk` module compiles with zero imports of proto, connect, or
  protobuf packages; the proto-purity archtest fails when any sdk package adds
  one (verified red by a scoped test fixture).
- **AC-2** `contract` and `sdk` import no in-repo module (directional-import
  archtest, shared with SPEC-002's INV-19 guard).
- **AC-3** Every Runner-spawned child has `LC_ALL=C`, `LANG=C`, `NO_COLOR=1`;
  a per-command env attempting to set any of those keys returns an error.
- **AC-4** A canary variable set in the parent process environment never
  appears in a child's environment; `PATH` is present and equals the curated
  value.
- **AC-5** Operator-supplied operands are preceded by `--` where the tool
  supports it; an operand beginning with `-` is passed verbatim as an operand,
  never interpreted as a flag; no code path builds a shell string.
- **AC-6** Ctx cancellation SIGTERMs the process group, then SIGKILLs after
  the grace timer; a child that spawned a grandchild leaves neither running.
- **AC-7** The narrowing helper rejects out-of-range values with an error;
  a uint32 value above uint16 range never silently truncates.
- **AC-8** The ReDoS guard rejects a nested-group quantifier pattern
  (`(a+)+`-class) and accepts the vetted grammar set; the rejection is an
  error, not a panic.
- **AC-9** A privileged mutation whose final component is a symlink is
  refused; chmod/chown operate on the held fd, never a re-resolved path.
- **AC-10** Temp files are random-named `O_EXCL`; the swap refuses to follow a
  symlink planted at the destination between write and rename.
- **AC-11** Create AND delete under a protected prefix are both refused,
  including child paths of the prefix and symlinks resolving into the subtree.
- **AC-12** Streaming atomic write of a file larger than the process memory
  budget succeeds without buffering the whole content; a mid-stream error
  leaves the original file untouched.
- **AC-13** The SSRF guard refuses loopback, link-local, and metadata
  addresses — including when a redirect lands there — and refuses any
  https→http downgrade.
- **AC-14** Each structured-file validator rejects control characters and its
  format's structural delimiters before any write; a multi-field file whose
  fields are individually valid but jointly unparseable is rejected
  cross-field; a tool error naming the SDK-written file triggers
  rollback-and-fail.
- **AC-15** Shell values outside `/etc/shells`, LUKS paths without `/dev/`
  prefix or with flag shapes, and malformed flatpak app IDs are rejected
  before any argv or path join.
- **AC-16** Seal/open round-trips under X25519+HKDF-SHA256+AES-256-GCM with
  the contract's mandated info strings and context binding (WIRE-23,
  SPEC-003 — this module owns the sole seal/open implementation); seal and
  open reject empty AAD, empty key, and empty plaintext symmetrically; an AAD
  mismatch, wrong info string, or wrong context makes `Open` return an error
  and no plaintext (fail closed).
- **AC-17** All secret/MAC compares are constant-time; the `math/rand` scan
  finds zero uses outside the jitter allowlist; `crypto/rand` read errors
  propagate.
- **AC-18** With the backing tool absent, queries return typed
  `ErrBackendUnavailable`; "package not installed" and "could not query" are
  distinct results; no exported query returns `(nil, nil)`.
- **AC-19** For each multi-step primitive, an injected later-step failure
  restores the earlier steps' pre-state (verified against the real backend in
  a container).
- **AC-20** Round-trip container tests pass against real package managers:
  dotted versions survive unmangled, one malformed entry does not abort a
  listing, output parses under a non-English locale lane.
- **AC-21** Policy-engine sequence: hash-equal content is a no-op; a candidate
  failing its validator never reaches the live path and the previous content
  is byte-identical afterward; a reload failure restores the previous file;
  revert replays prior state through the same function and passes the same
  validator gate.
- **AC-22** The surface table contains exactly the three rows above; the row
  type requires path class, validator, and reload — a row missing any is a
  compile error.

## 5. Rejection paths

| Input / state | Required behavior |
|---|---|
| Per-command env sets `LC_ALL`, `LANG`, or `NO_COLOR` | Error before spawn |
| Env construction from `os.Environ()` | Does not exist; guard G-2 fails the build |
| Shell-string command construction | Does not exist; argv-only API |
| Ctx canceled during child wait/read | SIGTERM → grace → SIGKILL process group; call returns ctx error |
| Narrowing source out of target range | Error, no truncation |
| Regex failing the ReDoS guard | Error before the pattern reaches the engine |
| Final path component is a symlink (mutation) | Refused |
| Create or delete under a protected prefix (incl. via symlink) | Refused, symmetric |
| Fetch URL resolves to loopback/link-local/metadata (incl. post-redirect) | Refused |
| https→http redirect | Refused |
| Structured-file value with `\n`/`\r`/control chars or format delimiters | Error before write |
| Multi-field file cross-field invalid | Error before write |
| Tool error names the file just written | Rollback previous content, fail operation |
| Shell not in `/etc/shells`; LUKS path malformed; flatpak ID malformed | Error before use |
| Seal/open with empty AAD, key, or plaintext | Error, symmetric at both ends |
| Backing tool absent | Typed `ErrBackendUnavailable`, never empty-success |
| Unreadable resource in a query | Error, never `(nil, nil)` |
| Policy candidate fails validator; swap or reload fails | Restore previous file byte-identical, fail operation |

## 6. Test plan (TDD)

Write tests FIRST from the ACs; confirm each fails red for the right reason
(scoped neutralizing edit, never a revert), then implement.

1. **Unit tier (FakeRunner):** Runner env/locale/argv/`--` behavior (AC-3..5),
   narrowing (AC-7), ReDoS guard (AC-8), validators (AC-14, AC-15), crypto
   (AC-16, AC-17), error contracts (AC-18), policy-engine sequencing with a
   scripted validator/reload (AC-21, AC-22).
2. **Filesystem tier (real tmpfs, real symlinks):** AC-9..12; symlink-swap
   races exercised with a planted symlink between steps.
3. **Container tier (real tools — mandatory for system surfaces):** SDK
   behaviors touching real package managers, sshd, visudo, systemd run INSIDE
   containers against the real binaries, round-trip (emit → real binary →
   parse). Lanes per manager (apt, dnf, pacman, zypper, flatpak). At least one
   lane runs under a non-English locale. Rollback tests (AC-19) verify real
   backend state. Split emit/parse fixtures are forbidden — they hid real
   parser bugs.
4. **Threat-model tier:** protected-prefix and deny-list tests assert against
   a test-owned list of attack paths (e.g., `/etc/shadow`, `/etc/cron.d/x`,
   symlinked variants) — NEVER by iterating the implementation's own set,
   which proves nothing.
5. **Full suite under `-race`** in CI; reboot-adjacent tests may use the real
   Runner but the real `shutdown` binary must be unreachable from the test
   environment.

## 7. Guards

All guards are self-discovering with matches-zero protection: each must fail
if its discovery step finds nothing to check.

| # | Guard | Mechanism |
|---|---|---|
| G-1 | Proto purity ([SDK-0]) | Walk all sdk packages; fail on any proto/connect/protobuf import; fail if <1 package discovered |
| G-2 | Env hygiene ([SDK-4]) | AST scan: zero `os.Environ()` calls in sdk outside the Runner-internal allowlist (keyed by function, not file) |
| G-3 | Randomness ([SDK-13]) | AST scan: `math/rand` banned outside the jitter allowlist; discovery must find ≥1 crypto call site |
| G-4 | Regex chokepoint ([SDK-6]) | Discover all `regexp.Compile`/`MustCompile` call sites; each must route through the ReDoS guard package |
| G-5 | Preimage framing ([SDK-13]) | Discover hash/MAC constructions in the crypto surface; each uses the length-prefix/domain helper |
| G-6 | No nil-AAD API ([SDK-13]) | Reflection walk over exported seal/open functions; every one requires an AAD parameter |
| G-7 | Mutation chokepoint ([SDK-7]) | AST scan: `os.Chmod`/`os.Chown`/`os.Rename`/path-based mutation calls banned outside the fd-anchored helpers package |
| G-8 | Directional imports ([SDK-0], SPEC-002) | Module-discovering archtest: `sdk` and `contract` import no in-repo module |
| G-9 | Clock seam (SPEC-000 cross-cutting) | No unabstracted `time.Now()` in sdk, including `SetDeadline` call sites; injected clock only |

## 8. Historical lessons

Each rule above is load-bearing; these incidents are why.

- **Locale drift:** package-manager output parsed under a German locale
  diverged from the English-tested parser; the per-command C-locale opt-in was
  repeatedly forgotten at call sites. Hence [SDK-3] as an unconditional Runner
  invariant.
- **Flag injection:** operator-supplied operands were interpreted as flags
  where `--` was missing from the argv construction. Hence [SDK-4].
- **Orphaned children:** wait/read paths that ignored ctx left children
  running past cancellation. Hence [SDK-5].
- **The 0×0 PTY:** an unchecked uint32→uint16 narrowing produced a zero-size
  PTY. Hence [SDK-6]'s range-checked helper.
- **ReDoS nesting:** a nested-group quantifier passed a naive per-group check;
  the guard must propagate quantifier/alternation state across group nesting.
- **Symlink TOCTOU:** path-based chmod after resolution allowed a symlink swap
  between resolve and operate; predictable temp names + `tee` allowed
  pre-planted symlinks. Hence [SDK-7].
- **Exact-match bypass:** `/etc/cron.d` was protected but `/etc/cron.d/x` was
  not — exact-match protected paths are a bypass by construction. Hence
  prefix semantics in [SDK-8].
- **Delete asymmetry:** the delete path lacked the protected-path check the
  create path had, permitting deletion of `/etc/shadow`. Hence symmetry in
  [SDK-8].
- **Structured-file smuggling:** newline/control/delimiter characters reached
  sshd_config, sudoers, authorized_keys, `.nmconnection`, GECOS, and deb822
  writers on several independent occasions. Hence [SDK-11]'s pre-write
  rejection.
- **The apt-bricking sources file:** a deb822 `.sources` file composed from
  several individually-valid fields was jointly unparseable and bricked apt on
  the device; the tool's own error named our file. Hence cross-field
  validation and rollback-and-fail in [SDK-11].
- **Path-join injection:** a flatpak app ID reached a path join before
  validation. Hence [SDK-12].
- **Asymmetric empty-input handling:** seal accepted inputs that open
  rejected (and vice versa), producing undecryptable stored blobs. Hence
  [SDK-14].
- **Doc drift:** documentation claimed SHA-512 where the code used SHA-256;
  unanchored claims drift silently. Hence [SDK-14]'s anchored doc claims.
- **`(nil, nil)`:** unreadable resources returned empty success; unchecked
  `scanner.Err()` and parse-to-zero helpers hid failures as absence. Hence
  [SDK-15].
- **Half-applied multi-step changes:** firewalld service XML, resolvectl
  dns/domain, CA-trust anchors, and static→DHCP transitions each left stale
  partial state on mid-sequence failure. Hence [SDK-16].
- **Parser fidelity:** dotted versions truncated names, one malformed package
  aborted whole listings, ARM cpuinfo shapes and comment edge cases broke
  parsers that only ever saw fixtures. Hence [SDK-17] and round-trip testing.
- **Fixture self-deception:** split emit/parse fixtures and deny-list tests
  that iterated the implementation's own set passed while the real behavior
  was broken. Hence the test-plan rules in §6.
- **Over-constraint:** a strict URL grammar rejected legitimate
  `$releasever`-style template variables in repository fields. Hence the
  false-rejection clause in [SDK-10].
- **Stale guard lists:** hand-maintained lists in fitness checks went stale
  and failed open. Hence matches-zero protection on every guard in §7.

## 9. Milestones

Each milestone ends with the full suite green (including guards) and is sized
for one implementation session.

This module is the primary PROC-6 (SPEC-000) porting target: the
predecessor's capability library already converged on the §3 design in place,
so M2–M7 default to porting its code and test estates — the package-manager
fidelity suites and container lanes above all — rather than re-deriving them.
The acceptance criteria and guards below gate the port exactly as they would
fresh code; where the port falls short of a §3 requirement, the requirement
wins.

1. **M1 — Skeleton + guards.** Both modules laid out per SPEC-002; guards
   G-1..G-9 implemented and proven red via scoped fixtures, then green.
2. **M2 — Runner.** [SDK-3..6]: env baseline, locale invariant, argv/`--`,
   process-group cancellation, narrowing helper, ReDoS guard. AC-3..8.
3. **M3 — Filesystem.** [SDK-7..9]: fd-anchored mutations, protected
   prefixes, streaming atomic writes, SSRF guard. AC-9..13.
4. **M4 — Validators.** [SDK-10..12]: intent grammars, structural-delimiter
   rejection, cross-field validation, rollback-and-fail. AC-14, AC-15.
5. **M5 — Crypto.** [SDK-13, SDK-14]: AEAD surface, sealed-transport
   primitives, constant-time compares, framing helpers. AC-16, AC-17.
6. **M6 — Error contracts + container lanes.** [SDK-15..17]: typed errors,
   rollback semantics, round-trip fidelity lanes per package manager,
   non-English locale lane. AC-18..20.
7. **M7 — Policy-file engine.** [SDK-18]: the composition function, the
   three-row table, revert path. AC-21, AC-22 (container tier: real `sshd -t`,
   real `visudo -c`).

## 10. Out of scope

- Proto message shapes, validate tags, signing envelopes (SPEC-003).
- Per-action-type manager semantics and the action catalog (SPEC-014).
- The agent's boot probe, capability injection, and executor orchestration
  (SPEC-013).
- Sealed-secret protocol usage — which secrets, which domains, which
  directions (SPEC-015); the SDK only provides the primitives.
- PKI, certificates, enrollment (SPEC-006).
- Server-side storage, search, and handler machinery (SPEC-005, SPEC-009).
