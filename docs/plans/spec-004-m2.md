# SPEC-004 M2 — Runner

Milestone: SPEC-004 §9 M2 ([SDK-3..6], AC-3..8). PROC-6 port from the
predecessor's `sdk/sys/exec` (MIT, no per-file headers to strip) with the
spec-driven reworks below. Mechanical milestone; tests from the matrix.
Delta only; the spec is authoritative.

## Recorded mechanical choices

1. **No go-cmd dependency.** The predecessor builds its process core on
   `github.com/go-cmd/cmd`; a new dependency needs operator sign-off and
   stdlib `os/exec` covers every demanded behavior. The port carries the
   SEMANTICS — `Setpgid` process groups, SIGTERM → grace timer → SIGKILL
   of the group (negative-pid kill), bounded second grace with a best-effort
   snapshot fallback for D-state children, line-buffered streaming with
   per-stream caps, ctx honored in every wait/read select — implemented on
   `os/exec` + `syscall` directly.
2. **Child env is an allowlist BASELINE, never inheritance.** The
   predecessor's default branch iterates `os.Environ()` and filters by
   blocklist — exactly what [SDK-4] forbids. The rewrite's `buildChildEnv`
   composes from constants only: curated
   `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
   plus the forced locale triple, plus validated per-command additions.
   No `os.Environ`, no `os.Getenv` — the existing G-2 env-hygiene guard
   needs NO new allowlist entry (its reserved slot goes unused; noted
   there). The predecessor's name-grammar + blocklist
   (`IsAllowedEnvVar`, `BlockedEnvVars`, reserved `LC_*`/`LANG`/
   `LANGUAGE`/`NO_COLOR`) ports as defense in depth on the additions.
3. **Forced locale triple ports as-is** ([SDK-3]): `forcedEnv` appended
   last in every branch; `ValidateCommandEnv` exported so the FakeRunner
   applies the identical gate; reserved keys rejected before spawn.
4. **Argv discipline ports as-is** ([SDK-4]): `Command{Name, Args, Dir,
   Env, Stdin, ChildPath, Escalate}` — argv-only, no shell-string path
   exists; `SeparatePositionals(flags, positionals...)` always inserts
   `--`, never aliases its input; caller-invoked (the Runner cannot know
   which args are operands — AC-5 tests the helper and the argv-only API).
   Escalation (`Sudo`/`Doas`/`Direct`, `-n`, absolute-path contract,
   denied-detection, pure `Detect`) routes through the same chokepoint.
5. **`sdk/redos` package** ([SDK-6], the M1 G-4 chokepoint path):
   `Vet(pattern string) error` — the predecessor's
   `sys/log/grepguard.go` logic generalized (unbounded-quantifier count,
   nested unbounded groups WITH parent-state propagation, alternation
   under quantifier, bounded repetition of unbounded groups);
   `Compile(pattern) (*regexp.Regexp, error)` = Vet → compile;
   `MustVet(pattern) *regexp.Regexp` for compile-time literals. The
   Runner's `ValidEnvVarName` literal routes through `MustVet`, so the
   exec package carries zero direct `regexp.Compile` sites — G-4's
   discovered population is unchanged (the redos dir itself is excluded
   by prefix from the scan); the win is that every new regex is routed,
   none allowlisted. The predecessor's agent-side duplicate is out of
   scope here (self-contained repo).
6. **`sdk/narrow` package** ([SDK-6], AC-7 — new code, no porting
   source): one generic `To[D, S integer](v S) (D, error)` with the exact
   round-trip check (`S(D(v)) != v` or sign flip ⇒ error, never
   truncation). Hand-rolled `integer` constraint; no x/exp dependency.
7. **Output discipline ports as-is**: `Result{ExitCode, Stdout, Stderr}`,
   `CappedBuffer` (1 MiB per stream, truncation marker, mutex-guarded),
   non-zero exit is a Result, not an error; `CommandError` +
   sentinels (`ErrUnknownBackend`, `ErrEscalationUnavailable`,
   `ErrEscalationDenied`, `ErrReservedEnvVar`, `ErrBlockedEnvVar`,
   `ErrInvalidEnvVar`).
8. **`sdk/exec/exectest.FakeRunner` ports as-is** (AC-3..5 unit tier):
   records calls + contexts, FIFO scripted results, applies
   `ValidateCommandEnv` before recording, honors already-cancelled ctx,
   replays stream lines. The predecessor's `Secret` type does NOT port
   here — no M2 demand needs it (SPEC-015 territory).
9. **Guard ratchets**: `modulePackageFloors["sdk"]` 1 → 6 (config,
   guardtest, exec, exec/exectest, narrow, redos). The M1 dormant/empty
   populations that arm here: G-4 gains the redos package and real
   routed sites; G-3's jitter allowlist stays empty (the Runner has no
   backoff).
10. **Kill-path tests use real processes** (predecessor pattern): a
    SIGTERM-ignoring `sh` child proves grace → SIGKILL of the whole
    group (`killGrace` is a package var tests shorten); a well-behaved
    child reaps on SIGTERM; an already-cancelled ctx short-circuits
    before spawn. No container tier at M2 — [SDK-17] lanes arrive M6.
    The real `shutdown` binary is unreachable by construction (curated
    PATH in tests points at a scratch bin dir).

## Files

- `sdk/exec/runner.go` — Runner interface, Command, NewRunner,
  PrivilegeBackend, escalation helpers, forcedEnv, buildChildEnv
  (choices 2–4).
- `sdk/exec/exec.go` — stdlib process core: spawn (Setpgid), stream,
  await/kill (choice 1).
- `sdk/exec/env.go` — env grammar, blocklist, reserved set,
  ValidateCommandEnv (choice 2).
- `sdk/exec/argv.go` — EndOfOptions, SeparatePositionals (choice 4).
- `sdk/exec/types.go`, `sdk/exec/command_error.go`,
  `sdk/exec/capped_buffer.go`, `sdk/exec/detect.go` (choice 7, 4).
- `sdk/exec/exectest/fakerunner.go` (choice 8).
- `sdk/narrow/narrow.go` (choice 6). `sdk/redos/redos.go` (choice 5).
- `sdk/guardtest/arch.go` — sdk package floor 1 → 6 (choice 9).
- `docs/content/01-specs/00-index.md` — In progress (M2 done); ledger
  line.

## Test matrix (all red-first; port test names where the estate ports)

- **AC-3 locale**: `TestRunner_ForcesDeterministicEnv`,
  `TestRunner_RejectsReservedEnv` (each of LC_ALL/LANG/NO_COLOR/LC_*/
  LANGUAGE, case-insensitive), FakeRunner equivalents.
- **AC-4 env baseline**: `TestRunner_CanaryNeverReachesChild` (canary in
  parent env, child `env` output must lack it), `TestRunner_PathIsCurated`
  (child PATH equals the constant), `TestBuildChildEnv_NoInheritBranch`
  (empty Command.Env still yields exactly baseline+forced),
  `TestRunner_EnvBlocklistRejectedBeforeExec`,
  `TestRunner_AllowedEnvReachesChild`, `TestRunner_ChildPathIsAuthoritative`.
- **AC-5 argv**: `TestSeparatePositionals_InsertsEndOfOptions`,
  `_DoesNotMutateFlags`, `TestRunner_DashOperandPassesVerbatim` (operand
  `-rf` after `--` reaches child argv unchanged), no-shell-string API
  (type-level; noted, not tested).
- **AC-6 cancellation**: `TestRunner_WellBehavedChildReapsOnSIGTERM`,
  `TestRunner_SIGKILLsChildThatIgnoresSIGTERM` (group gone, grandchild
  included), `TestRunner_RespectsAlreadyCancelledContext`.
- **AC-7 narrowing**: `TestTo_ExactValuesCross` (uint32→uint16 above
  range errors; boundary values exact; negative→unsigned errors;
  widening always succeeds; wrap values 65536/65537 rejected not
  wrapped).
- **AC-8 redos**: `TestVet_RejectsNestedQuantifiers` ((a+)+, ((a+))+
  propagation case, (a|a)+, (.*a){11}), `TestVet_AcceptsVettedGrammars`
  (the env-name grammar and representative sane patterns),
  `TestCompile_ErrorNotPanic`, `TestMustVet_CompileTimeLiteral`.
- **Ports retained**: escalation matrix, streaming/stdin/dir/caps rows,
  CappedBuffer concurrency, CommandError, Detect, FakeRunner suite.
- **Guards**: existing suite must stay green with the ratcheted floor;
  G-4's armed population now includes the redos-internal compile (allowed
  by prefix) and zero unrouted sites.
