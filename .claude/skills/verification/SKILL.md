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
  status.
