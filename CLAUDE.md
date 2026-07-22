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
- Build: recovery and agent-enrollment CLI binaries exist; networked control,
  gateway, and full agent-daemon commands land with SPEC-012/013. Verify the
  repository with the canonical gate.
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
- `docref suggest` is repository-wide and verbose: always tee its full output
  to a file before filtering for the touched documentation.
- With docref 0.1.1, generate marker blocks with `docref claim` and record
  reviewed prose with `docref approve`; there is no `docref fix` command.
- Judge test runs by grepping the FULL output for `FAIL`, not the last lines.
- Before accepting a version correction or changing a pin, verify the upstream
  release/tag and installable artifact; a claimed version is not availability.
- For a new direct dependency, select the newest verified stable version that
  supports the repository toolchain unless a documented compatibility bound
  requires an older one; transitive-version alignment alone is not a reason.
- Before `go mod tidy` in a multi-module workspace, inspect the repository's
  existing local-module requirement convention. Do not persist pseudo-version
  requirements for workspace-local modules when sibling manifests deliberately
  rely on `go.work`.
- For a newly published release, treat an initial 404 as potentially transient:
  re-check the release assets before proposing a downgrade.
- Multi-step validation commands use `set -e -o pipefail` unless each failure
  is deliberately captured; a later green command must not mask an earlier red.
- Before running or rerunning a command, resolve every path against the
  command's declared working directory; do not reuse a known-bad command
  verbatim.
- Keep checks that require different working directories in separate command
  invocations, each with an explicit working directory.
- For a command that formats repository paths and runs module-local Go checks,
  format from the repository root first; never combine the two path contexts.
- Before the canonical gate, derive the full modified/untracked non-generated
  Go-file inventory from Git and run gofmt over that set; formatting only the
  most recently edited package can leave registry edits behind.
- **Before every command, compare `workdir` with every explicit path.** When
  `workdir` is any module directory (`contract/`, `agent/`, `server/`, or
  `sdk/`), arguments must be module-relative and must not name that module or
  a sibling module as their first path component. Run cross-module scans and
  repository-relative formatting from the repository root; split them from
  module-local checks.
- **For repository work, keep `workdir` at the repository root.** Format with
  root-relative paths and run module checks with `go ... -C <module>`; never
  combine `gofmt` and a module-local Go command under one module workdir.
- `staticcheck` gets its own module-scoped command; never prefix a
  module-workdir staticcheck invocation with root-relative formatting or file
  paths.
- When a Go command combines `-C` with flags such as `-race` or `-run`, place
  `-C <module>` first in the Go subcommand's flag list.
- Run repository-wide CLIs, including `docref`, from the repository root with
  repository-relative paths; do not rewrite those paths with `../` from a
  module working directory.
- In docref source references, Go symbols use `path#Symbol` while named code
  regions use `path#@region`; confirm region names with `docref anchors` before
  generating a claim.
- After discovering files with `rg --files` or `find`, build follow-up reads
  only from paths that discovery actually returned; never append a guessed
  sibling filename or substitute a conventional-looking basename in an
  otherwise verified command. A known directory is not a file inventory: run
  `rg --files <directory>` and paste only returned paths into multi-file reads.
- If an inventory and a follow-up read share one shell command, the read list
  must still be a literal subset of the inventory output known before that
  command; do not use a same-command discovery as justification for a guessed
  trailing path.
- Before patching an escaping-sensitive literal, inspect its exact current
  bytes and match that observed form; do not reconstruct it through an extra
  shell, JSON, or JavaScript escaping layer.
- When a patch touches several distant hunks or files, inspect every current
  target and apply small file-local patches; do not let one stale context make
  an otherwise independent multi-file correction fail wholesale.
- After adding a call site, resolve every new identifier against an existing
  declaration or add that declaration in the same patch; reuse values already
  returned by test factories instead of inventing accessor helpers. Before
  adding a package-level test helper, search the package for that name. After
  code generation, inspect generated field/method spelling before referencing it;
  when handwritten and generated types differ only by casing, verify each use
  against its receiver type after patching.
- Build listener-boundary registration keys from `guardtest.ListenerSites`
  output after the production call sites exist; do not infer receiver syntax.
- In PostgreSQL migrations, explicitly name table-level constraints so they
  cannot collide with PostgreSQL's `<table>_<column>_check` names for
  column-level checks; exercise every new migration from an empty database.
- Projection-corruption fixtures must write constraint-valid but semantically
  wrong values unless the schema constraint itself is under test; compare the
  fixture mutation against the current migration before running it.
- A unit test for behavior behind a root-owned-parent precondition must either
  use a root-owned container path or isolate that precondition through the
  package seam; `t.TempDir()` is not root-owned under normal development.
- Before adding an importable test-support package with dynamic database calls,
  inspect repository static-SQL guards; any necessary exemption must be keyed
  to the exact file and method with a matches-zero-protected call count.
- Review an uncommitted milestone with
  `coderabbit review --base main --include-untracked`; plain text is the
  default in the installed CLI, so do not pass the removed `--plain` or
  `--type` flags.
- After editing a shell file containing heredocs, inspect the numbered changed
  region; `bash -n` cannot detect code accidentally swallowed as fixture text.
- Negative tests assert the intended failure message, never only a nonzero exit.
- Before the local review gate, scan every changed negative-test branch,
  including table subtests, and pair each `err != nil` expectation with the
  exact intended sentinel or stable error category.
- Every optimistic-conflict retry loop must combine fresh-state
  re-authorization with backoff and a finite internal retry budget; caller
  cancellation alone is not a bound because production callers may use a
  context without a deadline.
- On public credential-gated paths, perform structural validation first,
  authorize second, and invoke private-key signing only after authorization;
  never let invalid credentials drive a signer as pre-authentication work.
- When a stream server sends an early response after the client has already
  written a bounded request, drain that bounded request before close; unread
  bytes can convert a valid response into a trailing connection reset.
- Preserve stable multiword error categories as contiguous phrases; place
  operation-specific qualifiers after the category so callers and negative
  tests do not lose the recognizer text.
- Go error strings begin lowercase and omit terminal punctuation so wrapped
  errors compose cleanly and pass staticcheck ST1005.
- After pushing, poll CI to completion in the same session; fix failures
  immediately.
- For `gh --json` status inspection, use only fields listed by that command;
  query the GitHub API when nested job-step data is required.
- Run standard-library `go doc` probes with `GOWORK=off` when workspace
  resolution is unnecessary, one symbol per invocation, and inspect
  module/workspace sums afterward.
- Split file reads use non-overlapping ranges; include line numbers at joins
  before diagnosing apparent duplicate source text.
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
