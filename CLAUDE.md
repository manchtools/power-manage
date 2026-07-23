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
In linked-worktree checkouts, merge from the clean worktree that owns the base
branch; after any merge-command error, check remote PR state before retrying.

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
  obstacle. Before approving RED, acceptance paths are mutually satisfiable and fixtures preserve values before reset or
  replacement, keep negative crypto inputs constructible (or explicitly malformed when shared signers reject them), and fixed-date TLS sets `Config.Time`. Any test-file change
  by an implementer must be explicitly justified in the PR.
- After substantial changes, run the `reviewer` agent against the plan.

## Commands

- Verify gate (before every commit): `./scripts/verify.sh`
- Build: recovery and agent-enrollment CLI binaries exist; networked control,
  gateway, and full agent-daemon commands land with SPEC-012/013. Verify the
  repository with the canonical gate.
- Test one module: `go test -C <module> ./... -count=1 -race`
- Protos: `cd contract && buf lint && buf generate`; guards accept Buf's canonical tags (exact bytes use `len`).

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
- Fail closed; validate deserialized state before indexing; required JSON object fields track presence and reject null;
  discard pooled sessions after uncertain cleanup; no secrets in logs/URLs/errors/argv.

## Verification honesty

- Load the `verification` skill before every commit or push. It owns the
  canonical gate, full-output handling, dependency checks, and command/path
  hygiene; keep those process rules out of this session-wide index.
- Before running a compound verification command, choose its working directory
  once and resolve every command/path argument against that directory; do not
  mix a module workdir with repository-root-relative paths.
- For docref 0.1.1, use bare `docref` to print usage. Never pass `--help` to
  `docref` or its subcommands because subcommand arguments are treated as paths.
- Before patching an escaping-sensitive literal, inspect its exact current
  bytes and match that observed form; do not reconstruct it through an extra
  shell, JSON, or JavaScript escaping layer.
- When a patch touches several distant hunks or files, inspect every current
  target and apply small file-local patches; do not let one stale context make
  an otherwise independent multi-file correction fail wholesale.
- After any `apply_patch` context failure, every remaining patch in that turn
  is single-file and based on freshly printed surrounding lines; do not retry a
  combined code-and-documentation patch.
- After adding a call site, reuse declared join keys and resolve every new identifier and composite-literal embedded field against an existing
  declaration or add that declaration in the same patch; reuse values already
  returned by test factories instead of inventing accessor helpers. Before
  adding a package-level test helper, search the package for that name. After
  code generation, inspect generated field/method spelling before referencing it;
  when handwritten and generated types differ only by casing, verify each use
  against its receiver type after patching.
- Build guard ownership from production call sites, never inferred receiver
  syntax; cardinality-changing refactors update exact sets and liveness fixtures.
- In PostgreSQL migrations, explicitly name table-level constraints so they
  cannot collide with PostgreSQL's `<table>_<column>_check` names for
  column-level checks; test empty and populated pre-upgrade states, failing
  when identity-bearing data cannot be backfilled exactly.
- Parameterized pgx `Exec` calls carry one SQL statement; split test-fixture
  mutations instead of sending multiple commands through the prepared path.
- Projection-corruption fixtures must write constraint-valid but semantically
  wrong values unless the schema constraint itself is under test; compare the
  fixture mutation against the current migration before running it.
- A unit test for behavior behind a root-owned-parent precondition must either
  use a root-owned container path or isolate that precondition through the
  package seam; `t.TempDir()` is not root-owned under normal development.
- Before adding an importable test-support package with dynamic database calls, inspect repository
  static-SQL guards; any exemption is exact and matches-zero-protected;
  blocking and observer fixtures stay outside the application pool, and synthetic triggers exclude follow-on work.
- Review uncommitted work with `coderabbit review --base main --include-untracked`;
  do not pass removed output flags. Before declaring remote review complete,
  query unresolved PR threads even when the newest-head check is rate-limited;
  a head status does not summarize earlier reviews.
- After editing a shell file containing heredocs, inspect the numbered changed
  region; `bash -n` cannot detect code accidentally swallowed as fixture text.
- Successive fixture states are observably distinct; negative tests assert the intended failure message, never only a nonzero exit.
- Before the local review gate, scan every changed negative-test branch,
  including table subtests, and pair each `err != nil` expectation with the
  exact intended sentinel or stable error category.
- Bound every concurrent-test channel wait with a timeout, including setup and
  readiness receives; shared test recorders synchronize concurrent writes.
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
