# CLAUDE.md

<!-- HARD BUDGET: 200 lines. This file is paid for every session.
     Module-specific guidance lives in .claude/rules/ (path-scoped, loaded on
     demand). Process pipelines live in .claude/skills/. Don't inline either
     here. -->

## What this is

Power Manage monorepo: `contract/` (protos, MIT), `sdk/` (pure OS capability
library, MIT), `server/` (control + gateway, AGPL-3.0), `agent/` (device
agent, GPL-3.0). The web UI is a separate repository and out of scope.

The repo is **self-contained**: never reference other repositories' issues,
ADRs, specs, or files — inline the rationale instead. CI enforces this
(`scripts/check-self-contained.sh`).

## How work happens

One session = **one milestone of one spec** from `docs/content/01-specs/`
(status ledger: `00-index.md`). Pipeline (details in the `spec-driven-dev`
skill): read the spec + the context capsules of its Builds-on specs → write
tests RED first → implement to green → `./scripts/verify.sh` → update the
ledger → conventional commit. Code goes through a PR; docs/spec changes may
go direct to main.

Specs are operator-approved: implement as written. Material deviation
(behavior, new dependency, skipped guard) needs operator sign-off first.
Mechanical spec gaps are fixed in the spec in the same PR.

## Autonomous operation

The specs are the operator's standing instructions — work autonomously by
default and proceed without asking wherever they answer the question.

- Resume open work first (open PR / in-flight branch: fix findings, finish to
  merge), then take the next milestone the ledger and Builds-on order dictate.
- Plans in `docs/plans/` need no operator sign-off unless they contain a
  material deviation.
- Merge your own PRs once — re-checked at merge time — every gate is green
  and every review finding is addressed; then continue with the next
  milestone while context allows (PROC-5).
- Stop and ask ONLY for: material deviation from a spec; changing a recorded
  operator decision; tags/releases or anything destructive beyond the repo;
  a spec contradiction that is more than a mechanical gap. When blocked and
  the operator is away, file the question as a GitHub issue and take the
  next milestone that does not depend on the answer.

Merge only after re-checking, at merge time, that every check is green and
every review finding is addressed — never chain watch-and-merge. Review
fixes land as their own commit naming the findings; a fixed defect gets its
regression test proven red first.

## Test authorship and planning

- Sessions run on a top-tier model end to end (operator decision) — no model
  downshifting for implementation.
- Before implementing, save the agreed plan to `docs/plans/<short-name>.md`:
  reference the spec milestone and write only the delta (files, symbols, test
  names) — do not duplicate the spec.
- Trust-boundary milestones (SPEC-003 envelope/sealing, SPEC-005 append core,
  SPEC-006–008, SPEC-015): the failing tests are AUTHORED by the
  `test-writer` agent (Opus) before implementation starts. Mechanical
  milestones: the plan specifies the scenario matrix; row tests are written
  from it.
- **NEVER weaken a test to make it pass.** Implementation sessions do not
  edit test expectations — a failing test is a finding to report, not an
  obstacle. Any test-file change by an implementer must be explicitly
  justified in the PR.
- After substantial changes, run the `reviewer` agent against the plan.

## Commands

- Verify gate (before every commit): `./scripts/verify.sh`
- Build: server/agent binary targets are planned but do not exist yet; their
  commands land with SPEC-005/012/013. Verify the current libraries with the
  canonical gate.
- Test one module: `go test -C <module> ./... -count=1 -race`
- Protos: `cd contract && buf lint && buf generate`

## Always / never

- **No AI attribution anywhere** — commits, PRs, comments, docs. No
  `Co-Authored-By`, no "generated with".
- **ULID everywhere, never UUID** — sortable IDs are load-bearing in the
  event store.
- **Never edit a shipped migration** (the tool tracks by version, not
  content) — add a forward one.
- **Never hand-edit generated code** (`gen/`, sqlc output) — regenerate from
  source.
- **Module imports are one-way** (INV-19): `contract`/`sdk` import nothing
  in-repo; `agent`/`server` import only `contract`+`sdk`. This is also the
  license boundary — an `agent`→`server` import puts AGPL code in a GPL
  binary.
- **Tags `vYYYY.MM.PP` only on explicit operator instruction** — never tag
  unprompted.
- Fail closed, validate-then-authorize, no secrets in logs/URLs/errors/argv
  — full rules load from `.claude/rules/` when you touch code.

## Verification honesty

- Never truncate a command's only copy of its output: `cmd 2>&1 | tee` to a
  file first, then grep the file; `set -o pipefail`. <!-- a tail -30 once
  kept 1 of 7 review findings and forced a full re-run -->
- Judge test runs by grepping the FULL output for `FAIL`, not the last lines.
- Before accepting a version correction or changing a pin, verify the upstream
  release/tag and installable artifact; a claimed version is not availability.
- Multi-step validation commands use `set -e -o pipefail` unless each failure
  is deliberately captured; a later green command must not mask an earlier red.
- Before rerunning a failed command, resolve every path against the command's
  declared working directory; do not reuse a known-bad command verbatim.
- Keep checks that require different working directories in separate command
  invocations, each with an explicit working directory.
- After editing a shell file containing heredocs, inspect the numbered changed
  region; `bash -n` cannot detect code accidentally swallowed as fixture text.
- Negative tests assert the intended failure message, never only a nonzero exit.
- After pushing, poll CI to completion in the same session; fix failures
  immediately.
- No-self-mention instructions for publication apply to commit and PR text;
  do not rewrite unrelated project prose unless requested. The repository-wide
  no-attribution rule above remains unconditional.
- Report plainly: what passed, what failed, what was skipped.

## Navigation

- Specs: `docs/content/01-specs/` — requirement IDs (`[WIRE-24]`, `[ES-4]`)
  are grep-exact; cross-references use the form `(ID, SPEC-NNN)`.
- Operator decisions (final — do not re-litigate):
  `docs/content/02-decisions/01-operator-decisions.md`.
- Go symbols: gopls MCP (go-to-definition, references, symbol search) —
  `.mcp.json`; needs `go install golang.org/x/tools/gopls@latest`.
- Predecessor checkout for PROC-6 ports (SPEC-000): `../power-manage` when
  present. Its sdk capability library is the main porting source (SPEC-004
  §9); specs stay implementable without it.
- When the operator corrects the same thing twice, propose adding it here or
  to the matching rule file. When something here is stale, say so — don't
  work around it.
