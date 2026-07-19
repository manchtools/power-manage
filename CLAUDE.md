# CLAUDE.md

Instructions for working in this repository. These are binding.

## What this repo is

The Power Manage monorepo: `contract/` (protos + generated, MIT), `sdk/` (pure
OS capability library, MIT), `server/` (control + gateway, AGPL-3.0), `agent/`
(device agent, GPL-3.0). The web UI is a separate repository and out of scope.

This repo is **self-contained**: never reference issues, ADRs, specs, or files
from any other repository. All rationale lives in `docs/`. CI enforces this.

## How work happens here

Every session implements **one milestone of one spec** from `docs/content/01-specs/`, in
build order, following the pipeline in `docs/content/01-specs/000-development-process.md`:

1. Read the spec you are implementing IN FULL, plus the "Context capsule" of
   every spec it builds on. Do not start from memory of the codebase.
2. Write tests from the spec's acceptance criteria FIRST. Run them. Confirm
   they FAIL, for the right reason, before writing implementation code.
3. Implement the minimum that turns them green.
4. Run `./scripts/verify.sh`. Everything must pass.
5. Update the status ledger in `docs/content/01-specs/00-index.md` (milestone → done).
6. Commit with a conventional-commit message. Code changes go through a PR;
   docs/spec changes may go direct to main.

The specs are pre-approved by the operator. Implement them as written. A
material deviation (changed behavior, new dependency, skipped guard) requires
operator sign-off first — ask, don't improvise. Small mechanical gaps in a spec
are fixed by editing the spec in the same PR as the code.

## Skills

The skills in `.claude/skills/` encode the non-negotiable working rules:

| Skill | When it applies |
|---|---|
| `spec-driven-dev` | Every implementation session |
| `test-quality` | Writing or reviewing any test |
| `guards` | Any invariant, list, or coverage claim |
| `secure-defaults` | Writing or reviewing any code |
| `go-discipline` | All Go code |
| `verification` | Before every commit and push |

When a skill exists for a topic, follow it. The skill file is authoritative.

## Hard rules (grep-enforced or review-enforced)

- **No AI attribution anywhere**: commits, PRs, comments, docs. No
  `Co-Authored-By`, no "generated with" trailers.
- **ULID everywhere, never UUID.**
- **No `context.Background()` in request paths.**
- **No secrets in logs, events, URLs, or error messages.**
- **`errors` are never silently ignored** — no `_ =` on error returns, no empty
  catch blocks, no proceeding on decode failure.
- **Fail closed**: revocation unavailable → deny; decode error on persisted
  security state → deny; unknown enum → reject; verifier not wired → refuse to
  boot.
- **Never edit a shipped migration** — add a forward one.
- **Generated code is never hand-edited** — regenerate from source.
- **Module imports are one-way**: `contract`/`sdk` import nothing in-repo;
  `agent`/`server` import only `contract`/`sdk` (INV-19). An `agent`→`server`
  import is also a license violation.
- Do not commit `REWRITE_SPEC.md` or any file from outside this repository.

## Verification mechanics

- Never truncate a command's only copy of its output: no `| tail -N` /
  `| head -N` on test or build output. `cmd 2>&1 | tee /tmp/out` first, then
  grep the file.
- Judge test runs by grepping the FULL output for `FAIL`, not by the last lines.
- Use `PIPESTATUS`/`set -o pipefail` when piping build/test commands.
- Run `gofmt -w` on touched Go files before committing.
- After pushing a PR, poll CI to completion; fix failures in the same session.

## Commit and release

- Conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`...).
- Tags `vYYYY.MM.PP` only on explicit operator instruction — never tag
  unprompted.
- Release provenance: monorepo SHA (+ web SHA, recorded externally).
