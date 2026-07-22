---
name: verification
description: The pre-commit/pre-push gate and the output-handling rules that keep verification honest. Activates before every commit and push.
---

# Verification

## The gate

`./scripts/verify.sh` from the repo root runs the canonical checks for every
module: gofmt diff, `go vet`, `staticcheck`, `go test -count=1`, buf
lint/breaking (contract/), and the guard suites. All gates green before any
commit. Report results plainly: what passed, what failed, what was skipped —
never round a partial run up to "verified".

## Output handling — non-negotiable

- **Never truncate a command's only copy of its output.** No `| tail -N` or
  `| head -N` on test, build, review, or CI output. Truncation once hid 6 of
  7 findings from a 5-minute review run and forced a full re-run.
- For anything expensive or of unpredictable size:
  `cmd 2>&1 | tee /tmp/out.log` FIRST, then grep/read the file. Truncation is
  only allowed on a re-readable file.
- Judge pass/fail by grepping the FULL output for `FAIL` and reading why each
  failed — not by eyeballing the last lines.
- When piping, use `set -o pipefail` / check `PIPESTATUS[0]` — otherwise the
  pipe reports the grep's exit code, not the build's.

## Gate scripts fail closed

A check script with a quietly disabled stage is fail-open — the worst kind,
because it keeps printing OK. In verify/CI/guard scripts:

- No `|| true`, no `2>/dev/null`, no unchecked `$(...)` on a check's only
  error signal; every stage records its own FAIL on a nonzero exit.
- A required tool that is missing FAILS the gate — never a silent skip.
- Discovery-driven stages (module walks, package lists) carry a matches-zero
  floor: discovering less than the known population fails the gate.
- The gate has a self-test against fixtures (planted failure turns it red),
  run as a gate stage itself.
  <!-- lesson: the scaffold's gofmt stage swallowed parse errors via
       2>/dev/null + || true; caught only in PR #1 review -->

## Command and dependency hygiene

- `docref suggest` is repository-wide and verbose: tee its full output before
  filtering. With docref 0.1.1, use `docref claim` for marker blocks and
  `docref approve` for reviewed prose; there is no `docref fix` command.
- Commit-range lint requires a head revision. Its base value may be empty or
  unknown, in which case `ci-commits` deliberately checks the head fallback.
- Before accepting a version correction or pin change, verify the upstream
  release/tag and installable artifact. Treat a newly published release's
  initial 404 as potentially transient and re-check its assets before
  proposing a downgrade.
- A new direct dependency uses the newest verified stable version supported by
  the toolchain unless a documented compatibility bound requires otherwise.
  Transitive alignment alone is not a reason to select an older version.
- Before `go mod tidy` in this multi-module workspace, inspect the local-module
  requirement convention. Do not persist workspace-local pseudo-versions when
  sibling manifests deliberately rely on `go.work`.
- Multi-step validation commands use `set -e -o pipefail` unless each failure
  is deliberately captured; later success must not mask an earlier failure.
- Resolve every path against the command's declared working directory before
  running or rerunning it. Keep checks requiring different working directories
  in separate invocations.
- Keep repository work at the repository root. Format root-relative paths and
  run module checks with `go ... -C <module>`; do not combine root-relative
  formatting with a module-local command.
- When `workdir` is a module directory, arguments are module-relative and do
  not name that module or a sibling as their first path component. Cross-module
  scans and repository-wide CLIs run from the repository root.
- `staticcheck` gets its own module-scoped command. When a Go command combines
  `-C` with flags such as `-race` or `-run`, put `-C <module>` first.
- Before the canonical gate, derive the complete modified/untracked,
  non-generated Go-file inventory from Git and run gofmt over that set.
- Run repository-wide `docref` commands from the root with root-relative paths.
  Go symbol references use `path#Symbol`; named regions use `path#@region` and
  are confirmed with `docref anchors` before claiming.
- `docref approve` always requires one or more explicit root-relative paths;
  never invoke it without path arguments.
- Follow-up reads use only paths actually returned by prior `rg --files` or
  `find` discovery. A known directory is not a file inventory; never append a
  guessed sibling filename, including inside the same shell command.
- If a read reports a missing path, stop that inspection and complete a fresh
  `rg --files` inventory of the parent before retrying; do not correct the name
  from memory.
- Use bare `docref` to print the installed CLI usage. Do not pass `--help` to a
  docref subcommand; this release treats subcommand arguments as paths.

## Red checks

- Prove a test can fail: neutralize the code under test with a scoped edit
  (comment the guard, flip one branch), run, confirm the RED is for the right
  reason, restore that exact edit.
- Never `git checkout`/`git restore` a file holding uncommitted work — it
  discards ALL uncommitted changes in that file. Commit first, or undo with
  a scoped inverse edit, or stash.

## Before push

- Self-review the full diff — read it as a hostile reviewer: every new error
  path, every log line (secrets?), every list (self-discovering?).
- Sibling sweep: the bug you just fixed — grep for the same pattern in
  sibling files/handlers and fix them in the same change.
- `gofmt -w` on touched Go files; conventional commit message; no AI
  attribution anywhere.

## After push

- Poll CI to completion in the same session — background poll loop, not
  foreground sleep. Fix failures immediately; batch review + CI fixes into
  one commit rather than a dribble.
- A "passed" from an external reviewer that actually errored or was
  rate-limited is a fake skip — read the review body, not just the check
  status. When that happens, say so in the PR (one line: which review was
  skipped and what covered it instead, e.g. the local run) — otherwise the
  green check stands in for a review that never happened at merge time.
