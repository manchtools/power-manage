# Error journal

## 2026-07-21 — Repeated mistake: escaped the repository with a docref path

**What happened**: I ran `docref approve ../docs/...` from a module directory
twice. The CLI first resolves the repository root, so the supplied `../` path
escaped the workspace and the approval failed without changing files.

**What the user said**: Not user-initiated; I caught both failures in the
command output.

**Root cause**: I treated `docref` like a shell command resolving paths against
the declared working directory, despite it being a repository-wide tool with
root-relative path handling.

**Harness fix**: `CLAUDE.md` now requires repository-wide CLIs such as `docref`
to run from the repository root with repository-relative paths.

**Prevention**: Module-local Go checks and repository-wide documentation checks
run in separate commands from their respective roots.

## 2026-07-21 — Shallow analysis: treated URL secrecy as a transport ban

**What happened**: I proposed rejecting every artifact URL containing a query
string, despite the existing presigned-URL redaction path and the URL-fetched
APP_IMAGE/AGENT_UPDATE design.

**What the user said**: Reject URL userinfo, but preserve presigned query URLs;
if query hardening is desired, require a checksum pin instead of banning the
query outright.

**Root cause**: I read the global “no secrets in URLs” rule without tracing the
fetch call contract and downstream artifact requirements end to end.

**Harness fix**: `.claude/rules/go-security.md` now distinguishes forbidden URL
userinfo and URL disclosure from redacted presigned artifact/checksum queries,
whether integrity uses an inline pin or a separate `checksum_url`.

**Prevention**: Future URL-security changes must preserve presigned artifact and
checksum downloads and test both acceptance and error redaction before
tightening transport validation.

## 2026-07-21 — Ignored project rule: reintroduced a mandatory pin indirectly

**What happened**: After the first correction, I still proposed rejecting
query-bearing fetch URLs unless they had an inline checksum pin.

**What the user said**: AGENT_UPDATE deliberately defaults to a separate
`checksum_url`, and ACT-21 records that an inline pin must never become
mandatory; both the artifact URL and checksum URL may legitimately be
presigned.

**Root cause**: I traced the artifact download but not the second external URL,
and failed to check the action catalog's recorded operator reversal before
adding a pin-dependent restriction.

**Harness fix**: `.claude/rules/go-security.md` now explicitly preserves query
strings for both artifact and checksum URLs regardless of inline-pin selection,
while requiring raw-URL redaction and rejecting userinfo.

**Prevention**: Fetch-boundary changes must trace every URL input through
SPEC-013 and SPEC-014 and must not make ACT-21's optional inline pin mandatory,
directly or indirectly.

## 2026-07-21 — Shallow analysis: promoted an inference into a project rule

**What happened**: I recorded that query preservation followed from ACT-21's
optional inline-pin decision, although that decision governs integrity choice,
not URL grammar.

**What the user said**: The sound justification is the repository's repeated
validator convention—reject URL userinfo and preserve query content—not a
claimed collision with ACT-21.

**Root cause**: I accepted a strengthened argument without separating the
spec's explicit statement from an inference about its consequences.

**Harness fix**: `.claude/rules/go-security.md` now states only the verified
repository convention and removes the unsupported ACT-21 linkage.

**Prevention**: Project rules must distinguish explicit recorded decisions from
inferences; an inference cannot be cited as the reason another policy is
mandatory.

## 2026-07-21 — Silent failure: shell fixture helper was swallowed by a heredoc

**What happened**: I inserted a shell helper inside a generated Go fixture's
heredoc; later scenarios printed `command not found` but still passed because
they expected the gate to exit nonzero for another reason.

**What the user said**: Not user-initiated; I detected the false-green output
while reviewing the complete test log.

**Root cause**: I patched against an unqualified closing brace inside a heredoc
and trusted `bash -n`, which cannot distinguish intended heredoc content from an
accidentally embedded helper.

**Harness fix**: `CLAUDE.md` now requires numbered post-edit inspection around
shell heredocs, and the Buf fixture now requires the named generation stage to
fail rather than accepting any nonzero exit.

**Prevention**: Shell test changes with heredocs are inspected after patching,
and negative tests assert the specific failure signal so setup errors cannot
satisfy the scenario.

## 2026-07-21 — Silent failure: later green command masked an earlier path error

**What happened**: A multi-command verification ran `gofmt` with a root-relative
path from inside `contract/`; it failed, but later successful commands made the
combined shell invocation exit zero.

**What the user said**: Not user-initiated; I detected the path error in the
complete command output.

**Root cause**: The validation command enabled `pipefail` but not `errexit`, so
only the final command determined the overall result.

**Harness fix**: `CLAUDE.md` now requires `set -e -o pipefail` for multi-step
validation commands unless individual failures are deliberately captured.

**Prevention**: A later green check can no longer mask an earlier failed
validation step.

## 2026-07-21 — Repeated mistake: rerun kept the same invalid working-directory path

**What happened**: After identifying a root-relative path used from inside the
`contract/` module, I added `errexit` but reran the command with the same invalid
path. It correctly stopped immediately, but performed no validation.

**What the user said**: Not user-initiated; I caught the repeated mistake in the
command result.

**Root cause**: I corrected the shell's failure propagation without correcting
the failing command's path relative to its declared working directory.

**Harness fix**: `CLAUDE.md` now requires resolving every path against the
declared working directory before rerunning a failed validation command.

**Prevention**: A failed command is not rerun verbatim after a path diagnosis;
both its control flow and its path resolution are checked first.

## 2026-07-21 — Repeated mistake: mixed root and module checks in one command

**What happened**: I combined a repository-root `rg` inspection with
module-local static analysis while declaring `contract/` as the sole working
directory. The root inspection failed before the module checks could run.

**What the user said**: Not user-initiated; I caught the repeated path-class
mistake from the immediate command failure.

**Root cause**: The individual paths were valid in different directories, but
I grouped them into one invocation for convenience.

**Harness fix**: `CLAUDE.md` now forbids combining checks that require different
working directories in one shell invocation.

**Prevention**: Repository-root inspections and module-local validations run as
separate commands with explicit working directories.

## 2026-07-21 — Wrong scope: applied a publication rule to project prose

**What happened**: I treated “no self mention” as a ban on first-person
narrative in `docs/error-journal.md` and prepared to rewrite unrelated prose.

**What the user said**: The instruction applies to commit and PR attribution;
ordinary first-person project prose is unaffected.

**Root cause**: A publication-specific instruction was interpreted as a
repository-wide writing rule.

**Harness fix**: `CLAUDE.md` now keeps the repository-wide attribution ban
separate from no-self-mention requests, which apply to commit and PR text unless
a broader scope is explicitly requested.

**Prevention**: Publication metadata is checked for attribution without
rewriting unrelated documentation.

## 2026-07-21 — Silent failure: malformed ECDSA input panicked during validation

**What happened**: The signing-key validator called `ecdsa.PublicKey.Bytes`
after approving the curve but before rejecting nil coordinates; an adversarial
key caused a process panic instead of a validation error.

**What the user said**: Not user-initiated; the pre-commit adversarial review
requested an approved-curve malformed-key fixture, which exposed the panic.

**Root cause**: The implementation assumed the serialization helper returned an
error for every malformed point, but its nil-coordinate path dereferences the
coordinates first.

**Harness fix**: `.claude/rules/go-security.md` now requires potentially
panicking public-key serialization calls to be isolated and converted into
validation errors.

**Prevention**: Key-profile tests include approved-curve malformed points and
validators convert standard-library serialization panics into errors.

## 2026-07-21 — User correction: acknowledged a version claim before verification

**What happened**: I agreed that docref `v0.1.1` was available before checking
the configured upstream; its release API, remote tags, and package metadata
currently expose only `v0.1.0`.

**What the user said**: Asked why CI used `0.1.0` when `0.1.1` was available.

**Root cause**: The correction was acknowledged before verifying that the named
version had an installable release artifact.

**Harness fix**: `CLAUDE.md` now requires checking the upstream release/tag and
installable artifact before accepting a version correction or changing a pin.

**Prevention**: CI pins are selected from verified, checksum-bearing release
assets rather than an unverified version claim.

## 2026-07-21 — User correction: treated a new-release 404 as final

**What happened**: After a CI download returned 404, I recommended downgrading
the pin instead of accounting for the expected release still being published.

**What the user said**: Version `0.1.1` was released.

**Root cause**: The verification rule covered unverified version claims but not
the propagation window of a newly published release.

**Harness fix**: `CLAUDE.md` now requires rechecking newly published release
assets before proposing a downgrade after an initial 404.

**Prevention**: A transient publication delay will be retried rather than
mistaken for proof that the requested version does not exist.

## 2026-07-21 — Wrong scope: root-relative paths under a module working directory

**What happened**: A formatting-and-test command declared `server/` as its
working directory but passed formatter paths prefixed with `server/`. The
formatter failed before changing files or running tests.

**What the user said**: Not user-initiated; the invalid paths were visible in
the immediate command result.

**Root cause**: The working directory was selected for the Go commands, but the
formatter arguments were copied from a repository-root invocation.

**Harness fix**: `CLAUDE.md` now requires resolving command paths against the
declared working directory before first execution as well as before retries.

**Prevention**: Mixed formatter/test invocations use paths relative to their
explicit module working directory, or run as separate root and module commands.

## 2026-07-21 — Wrong interface: requested job steps from run JSON

**What happened**: A read-only GitHub Actions status query requested `steps`
from `gh run view --json`, but that command exposes run-level fields rather than
nested job steps and rejected the request.

**What the user said**: Not user-initiated; the CLI printed its supported field
list immediately.

**Root cause**: The job-selection flag was assumed to change the JSON schema to
a job response without checking the command's advertised fields.

**Harness fix**: `CLAUDE.md` now requires using the command's listed JSON fields
and falling back to the GitHub API for nested job-step inspection.

**Prevention**: Status polling uses run-level fields for completion and the
Actions jobs API only when individual step state is needed.

## 2026-07-22 — Hidden mutation: Go documentation probe expanded workspace sums

**What happened**: A standard-library `go doc` probe ran from a workspace
module and rewrote `go.work.sum` with unrelated transitive module hashes.

**What the user said**: Not user-initiated; the unexpected lockfile diff was
caught during the next worktree inspection.

**Root cause**: The probe needed only standard-library documentation but
inherited workspace module resolution, allowing the Go command to update the
workspace checksum file.

**Harness fix**: `CLAUDE.md` now requires `GOWORK=off` for standard-library
documentation probes when workspace resolution is unnecessary and a checksum
inspection afterward.

**Prevention**: Documentation-only Go probes run outside workspace resolution;
any checksum change without a dependency change is removed before proceeding.

## 2026-07-22 — Misread output: overlapping ranges looked like duplicate source

**What happened**: Two consecutive file reads used ranges `1,360` and
`360,760`. Both printed line 360, which contained a struct field declaration;
the repeated output was incorrectly diagnosed as a duplicate declaration in
the file.

**What the user said**: Not user-initiated; the test-writer checked the shared
file and confirmed that the declaration occurred exactly once.

**Root cause**: The diagnostic output was read as one continuous source stream
without noticing that the split ranges overlapped at their boundary.

**Harness fix**: `CLAUDE.md` now requires non-overlapping split ranges and line
numbers at joins before apparent duplicate source text is diagnosed.

**Prevention**: Large-file reads use `1,360` followed by `361,760`, or numbered
output is checked against the actual file before reporting duplication.

## 2026-07-22 — Masked rejection: TLS test peer waited on an open pipe

**What happened**: Real TLS rejection tests reached the expected class or trust
failure on one endpoint, but the test helper left the in-memory connection open.
The peer remained blocked until the five-second context deadline, masking the
real rejection as a timeout.

**What the user said**: Not user-initiated; the first implementation test run
showed every rejecting server handshake timing out in the shared helper.

**Root cause**: The concurrent handshake helper waited for both results but did
not close or cancel the peer transport after the first endpoint failed.

**Harness fix**: The test-writer instructions now require concurrent protocol
helpers to unblock both endpoints as soon as either side rejects.

**Prevention**: Real-handshake rejection helpers close the shared transport on
the first error and assert the protocol error rather than accepting a timeout.

## 2026-07-22 — Truncated inspection: docref suggestions were not logged first

**What happened**: A repository-wide `docref suggest` ran directly alongside
the focused approval and check commands. Its large existing suggestion set
exceeded the direct output limit, so the command's only complete output was not
preserved.

**What the user said**: Not user-initiated; the tool reported that its output
had been truncated.

**Root cause**: The suggestion command was treated like the compact docref
check even though it scans and reports prose across the entire repository.

**Harness fix**: `CLAUDE.md` now names `docref suggest` as an always-tee command
whose saved output is filtered only after completion.

**Prevention**: Docref suggestion passes write their complete report to a log,
then inspect entries for the documentation changed by the current milestone.

## 2026-07-22 — Deprecated API: certificate-pool size inferred via Subjects

**What happened**: The initial TLS builders and their test helper used
`x509.CertPool.Subjects` to detect or compare trust roots. Staticcheck rejected
the call because it is deprecated and incomplete for system pools.

**What the user said**: Not user-initiated; the canonical verification gate
reported SA1019 before the change was committed.

**Root cause**: A list-returning method was used as a convenient size/equality
proxy without checking its deprecation contract; the supported `Equal` method
already expressed both needs.

**Harness fix**: The Go rules now prohibit deprecated APIs and direct work
toward the supported standard-library replacement.

**Prevention**: Certificate-pool emptiness and equality use `CertPool.Equal`;
staticcheck remains the pre-commit enforcement layer.

## 2026-07-22 — Wrong path context: root-relative files from a module directory

**What happened**: A combined formatting and verification command ran from the
`contract` module but passed repository-root paths such as
`contract/identity/identity.go`. `gofmt` failed immediately because those paths
resolved to a nonexistent nested `contract/contract` tree.

**What the user said**: Not user-initiated; the command failed before editing
or testing any files.

**Root cause**: Repository-wide formatting and module-local Go checks were
combined under one working directory even though their path conventions differ.

**Harness fix**: `CLAUDE.md` now explicitly requires formatting repository
paths from the root before running module-local checks separately.

**Prevention**: Run `gofmt` from the repository root, then run `go test` and
`staticcheck` from the module directory in a separate command.

## 2026-07-22 — Repeated path context: combined formatting ignored the rule

**What happened**: During the review-fix pass, another command ran from the
`contract` module while asking `gofmt` to open
`contract/archtest/denylist_test.go`. It failed before formatting or testing.

**What the user said**: Not user-initiated; this repeated an earlier internal
path-resolution mistake despite the first harness entry.

**Root cause**: The earlier rule described the two path contexts but did not
provide a concrete preflight that made the invalid argument obvious at command
construction time.

**Harness fix**: `CLAUDE.md` now states the literal invariant: a command whose
working directory is `/contract` cannot receive a `contract/`-prefixed file
argument, and formatting must be split from module checks.

**Prevention**: Before executing a module-local command, compare its workdir
suffix with every explicit path prefix; run repository-path formatting in its
own root-scoped command.

## 2026-07-22 — Stale CLI option: CodeRabbit `--plain`

**What happened**: The local review command passed the removed `--plain`
option and omitted the now-explicit flag that includes untracked milestone
files, so CodeRabbit exited at argument parsing without reviewing the change.

**What the user said**: Not user-initiated; the installed CLI reported the
unsupported option and its current working-tree flags.

**Root cause**: The review invocation was reused from an older CLI contract
without checking it against the installed command help.

**Harness fix**: `CLAUDE.md` now records the supported pre-commit invocation:
`coderabbit review --base main --include-untracked`, with plain text as the
default.

**Prevention**: Local reviews include new test and production files and avoid
the removed option, so the mandatory pre-commit review actually runs.

## 2026-07-22 — Repeated stale CodeRabbit invocation despite corrected guidance

**What happened**: The local review again used the obsolete
`coderabbit review --plain --type uncommitted` form even though the repository
harness already recorded the installed CLI's supported invocation.

**What the user said**: Not user-initiated; the installed CLI rejected both
removed options before reviewing the change.

**Root cause**: A prior conversational summary was trusted over the current
repository guidance, so the earlier correction was not applied at execution
time.

**Harness fix**: `CLAUDE.md` now explicitly bans both removed flags, `--plain`
and `--type`, alongside the exact supported command.

**Prevention**: Copy the repository's literal review command; do not reconstruct
it from remembered or summarized CLI syntax.

## 2026-07-22 — Conversational summary overrode CodeRabbit harness again

**What happened**: After context compaction, the local review command was once
again reconstructed from the summary as `--plain --type uncommitted`. The
installed CLI rejected it before a review ran, despite the exact supported
command already being present in `CLAUDE.md` and two journal entries.

**What the user said**: Not user-initiated; the local CLI exposed the repeated
harness bypass during the required pre-commit review.

**Root cause**: The summary was treated as executable tooling guidance without
re-reading the repository harness immediately before invoking the command.

**Harness fix**: `CLAUDE.md` now requires re-reading and literally copying the
recorded CodeRabbit command before every local review, and explicitly states
that conversational summaries are not CLI authority.

**Prevention**: Resolve mutable CLI syntax from the repository harness at the
moment of use; summaries may describe intent but never supply the command.

## 2026-07-22 — Go `-C` ordered after another build flag

**What happened**: A supplementary race test invoked `go test -race -C server`.
The Go command requires `-C` to be its first build flag, so argument parsing
failed before the test ran.

**What the user said**: Not user-initiated; the Go CLI reported the ordering
constraint.

**Root cause**: The existing root-workdir rule required `-C` but did not state
its ordering when combined with other build flags.

**Harness fix**: `CLAUDE.md` now requires `-C <module>` before `-race`, `-run`,
and other Go subcommand flags.

**Prevention**: Compose module checks as `go test -C <module> ...` before adding
any remaining flags.

## 2026-07-22 — Third path-context failure: sibling modules from `contract/`

**What happened**: A source probe ran with `contract/` as its working directory
but asked `rg` to scan sibling paths `agent/` and `server/`. The scan failed
before producing the evidence it was meant to collect.

**What the user said**: Not user-initiated; `rg` reported that both paths did
not exist under the selected working directory.

**Root cause**: The previous strengthened rule still named the narrow
`contract/contract` example, so command construction did not apply the same
preflight to sibling-module paths.

**Harness fix**: `CLAUDE.md` now makes the preflight mandatory before every
command and generalizes it to all module workdirs: module-local arguments stay
relative, while sibling or cross-module paths require the repository root.

**Prevention**: Every explicit path is checked against the declared workdir;
cross-module scans cannot be launched from a module directory.

## 2026-07-22 — Fourth path-context failure: mixed formatting and module test

**What happened**: A command again ran from `contract/`, passed the
root-relative path `contract/sign/sign.go` to `gofmt`, and therefore failed
before reaching the focused test.

**What the user said**: Not user-initiated; `gofmt` reported the nonexistent
`contract/contract/sign/sign.go` path.

**Root cause**: Despite the generalized preflight rule, mixed formatting and
module-testing operations still encouraged switching workdirs and carrying
the wrong path convention into the combined command.

**Harness fix**: `CLAUDE.md` now makes the repository root the default workdir
for task commands and requires `go ... -C <module>` for module checks.
Formatting and Go checks cannot share a module-local workdir.

**Prevention**: Root-relative file paths and module selection are now
orthogonal: `gofmt` runs from root, while Go selects its module with `-C`.

## 2026-07-22 — Repeated root-path formatting under the server workdir

**What happened**: A combined command used `server/` as its working directory,
then passed `server/internal/testpostgres/harness.go` to `gofmt` before running
module-local staticcheck. Formatting failed on the nonexistent
`server/server/...` path, so staticcheck did not run.

**What the user said**: Not user-initiated; `gofmt` reported the invalid path.

**Root cause**: The existing root-workdir rule was again bypassed to combine a
root-relative formatting step with a tool that expects a module workdir.

**Harness fix**: `CLAUDE.md` now explicitly gives staticcheck its own
module-scoped command and forbids sharing that command with root-path
formatting.

**Prevention**: Formatting always runs from the repository root; staticcheck
runs separately from its module without explicit repository paths.

## 2026-07-22 — Capitalized Go error string in shared test infrastructure

**What happened**: The shared Postgres harness wrapped a connection failure
with `Postgres connection string`, beginning the error text with a capital
letter. Staticcheck rejected it under ST1005.

**What the user said**: Not user-initiated; the required staticcheck pass named
the exact line and rule.

**Root cause**: Product-name capitalization was carried into an error prefix
instead of following Go's lowercase composable-error convention.

**Harness fix**: `CLAUDE.md` now explicitly requires lowercase, unpunctuated Go
error strings.

**Prevention**: New error prefixes are read as fragments that may follow other
wrapping context, not as standalone prose sentences.

## 2026-07-22 — Docref region referenced as a symbol

**What happened**: A schema claim used
`005_registration_tokens.sql#registration-tokens-schema`. Docref interpreted
the suffix as a symbol path and rejected it even though the named region marker
existed.

**What the user said**: Not user-initiated; docref reported that the suffix was
not a symbol and requested a region marker.

**Root cause**: The `#@region` form was not checked against `docref anchors`
before constructing the claim.

**Harness fix**: `CLAUDE.md` now distinguishes `path#Symbol` from
`path#@region` and requires region discovery before claim generation.

**Prevention**: Schema and shell regions are copied from `docref anchors`, so
claim commands cannot silently fall back to symbol syntax.

## 2026-07-22 — Shared Postgres test harness tripped the static-SQL guard

**What happened**: Moving template-database creation into an importable
test-support package changed it from `_test.go` code to a normal Go package.
The server's static-SQL guard correctly discovered its dynamic `CREATE` and
`DROP DATABASE` `Exec` calls.

**What the user said**: Not user-initiated; the server guard named both direct
database call sites.

**Root cause**: The test-helper refactor considered code reuse and package
visibility but did not include the repository's production-file SQL scanner in
its initial design.

**Harness fix**: The guard now permits exactly two `Exec` calls at the exact
test-harness file/method key and fails if that allowance matches any other
count. `CLAUDE.md` requires this preflight for importable database test support.

**Prevention**: Dynamic test-only DDL remains visible and narrowly justified;
new or orphaned direct database calls still fail the exact-count guard.

## 2026-07-22 — Stable error category split by an operation qualifier

**What happened**: The registration-token nil-context error was written as
`nil registration-token context`, so the red-first test could not recognize
the intended stable category `nil context`.

**What the user said**: Not user-initiated; the focused acceptance test exposed
the message-contract mismatch.

**Root cause**: Operation detail was inserted inside a multiword error category
instead of following it.

**Harness fix**: `CLAUDE.md` now requires stable multiword error categories to
remain contiguous, with qualifiers appended afterward.

**Prevention**: Validation errors lead with their reusable category (for
example, `nil context`) before naming the affected operation.

## 2026-07-22 — Projection-corruption fixture violated the schema

**What happened**: The registration-token rebuild test tried to corrupt the
optional owner by storing SQL `NULL`, but the projection represents absence as
the non-null empty string. PostgreSQL rejected the fixture before rebuild ran.

**What the user said**: Not user-initiated; PostgreSQL returned SQLSTATE 23502
for the test setup.

**Root cause**: The adversarial fixture was written from the domain-level idea
of an optional owner without checking the projection's concrete non-null
representation.

**Harness fix**: `CLAUDE.md` now requires projection-corruption fixtures to
remain constraint-valid unless they are specifically testing constraint
enforcement.

**Prevention**: Rebuild tests corrupt values within the schema's accepted
domain, ensuring the projector—not an earlier constraint failure—is what the
test exercises.

## 2026-07-22 — PostgreSQL check-constraint name collision

**What happened**: The registration-token migration combined a column-level
`uses >= 0` check with an explicitly named table-level upper-bound check. The
explicit name matched PostgreSQL's generated `<table>_<column>_check` name, so
the clean migration failed before creating the table.

**What the user said**: Not user-initiated; PostgreSQL returned SQLSTATE 42710
for the duplicate constraint name.

**Root cause**: The explicit table constraint was named without accounting for
PostgreSQL's automatic naming convention for the earlier column constraint.

**Harness fix**: `CLAUDE.md` now requires collision-safe explicit names for
table-level checks and an empty-database migration run for every new schema.

**Prevention**: Multi-column checks use a semantic suffix such as
`_use_bound_check`, while column checks retain PostgreSQL's generated names.

## 2026-07-22 — Unnecessary undefined test accessor introduced

**What happened**: An idempotence assertion called a new `servicePool` helper
that did not exist, even though the test factory already returned the required
Postgres pool.

**What the user said**: Not user-initiated; immediate post-patch inspection
caught the unresolved identifier before compilation.

**Root cause**: The new assertion was written around the service value alone
without reusing the factory's second return value.

**Harness fix**: `CLAUDE.md` now requires every new call-site identifier to
resolve in the same patch and prefers existing factory returns over invented
accessors.

**Prevention**: Test setup retains every resource needed by later assertions;
new helper names are not introduced speculatively.

## 2026-07-22 — Repeated patch mismatch in a distant multi-hunk edit

**What happened**: A single patch attempted to change guard call sites, guard
implementation, harness guidance, and the journal together. One stale guard
context caused the entire otherwise-independent correction to fail.

**What the user said**: Not user-initiated; `apply_patch` rejected the combined
hunk before writing anything.

**Root cause**: Earlier excerpts were reused for a large patch instead of
re-reading every distant target and applying file-local changes.

**Harness fix**: `CLAUDE.md` now requires small file-local patches when a
change spans distant hunks or multiple files.

**Prevention**: Each target file is inspected immediately before its patch;
unrelated corrections no longer share one all-or-nothing context match.

## 2026-07-22 — Patch mismatch from an unnecessary escaping layer

**What happened**: A corrective patch expected backslash-escaped JSON inside a
Go raw string, but the file already contained the correct unescaped literal.
The hunk failed before changing the file.

**What the user said**: Not user-initiated; `apply_patch` reported that the
expected escaped lines did not exist.

**Root cause**: The literal was reconstructed through the surrounding
JavaScript patch string instead of matching the exact current file content.

**Harness fix**: `CLAUDE.md` now requires inspecting and matching the observed
bytes before patching escaping-sensitive literals.

**Prevention**: Raw strings, regular strings, and nested tool-call strings are
kept as separate escaping layers; a patch is based on the file's displayed
form, not a mentally re-encoded form.

## 2026-07-22 — Repeated CLI misuse: multiple symbols in one `go doc`

**What happened**: A standard-library probe again passed three independent
symbols to one `go doc` invocation, which printed usage instead of the needed
API documentation.

**What the user said**: Not user-initiated; `go doc` rejected the command
shape.

**Root cause**: The existing probe rule covered workspace isolation but did
not state that this CLI accepts only one symbol query per invocation.

**Harness fix**: `CLAUDE.md` now requires one symbol per `go doc` invocation.

**Prevention**: Multi-symbol research runs as separate explicit probes, so a
usage error cannot replace all requested documentation.

## 2026-07-22 — Guessed source path after an authoritative inventory

**What happened**: A read command first listed the real files under
`server/internal`, then appended a guessed `server/internal/store/projector.go`
path that was not in that inventory. The valid read completed, but the command
still exited with a nonexistent-file error.

**What the user said**: Not user-initiated; `sed` reported that the guessed
file did not exist.

**Root cause**: File discovery and file selection were treated as separate
mental steps, allowing a conventional-looking filename to bypass the evidence
already returned by the repository.

**Harness fix**: `CLAUDE.md` now requires follow-up reads to use only paths
actually returned by `rg --files` or `find`; guessed siblings are forbidden.

**Prevention**: Repository inventories are the source of truth for subsequent
file reads, so a valid discovery cannot be undermined by an unverified suffix.

## 2026-07-22 — Negative transition tests accepted any error

**What happened**: The first registration-token transition tests proved that
invalid events failed, but did not prove that the mint-order invariant caused
the failure. The nil-store constructor test had the same weak shape.

**What the user said**: Not user-initiated; the local CodeRabbit gate found the
test-quality gap before publication.

**Root cause**: The general negative-test rule was applied to table-driven
validation cases but missed standalone constructor and transition branches.

**Harness fix**: `CLAUDE.md` now requires a pre-review scan of every changed
negative branch, including table subtests, for a sentinel or stable category
assertion.

**Prevention**: Failure tests now distinguish the intended invariant from
unrelated database, validation, or wiring errors.

## 2026-07-22 — Token CAS retries had no operational bound

**What happened**: Registration-token consume and disable correctly re-read
and re-authorized after expected-version conflicts, but retried immediately
and relied only on caller cancellation to terminate.

**What the user said**: Not user-initiated; the local CodeRabbit gate identified
the availability risk before publication.

**Root cause**: The bounded-use correctness analysis counted committed state
progress but did not account for sustained contention, corrupted projections,
or callers using a context without a deadline.

**Harness fix**: `CLAUDE.md` now requires optimistic-conflict loops to have
fresh-state authorization, backoff, and a finite internal retry budget.

**Prevention**: Token CAS retries use short jittered waits, stop after a fixed
production budget, and have a real-Postgres regression for stale projection
state.

## 2026-07-22 — Repeated guessed-path read despite the inventory rule

**What happened**: A SPEC-006 inspection command guessed
`docs/content/01-specs/006-pki-lifecycle.md` even though the repository had not
returned that basename. The actual file is `006-pki-and-identity.md`; the
failed reads added noise while the remaining verified reads completed.

**What the user said**: Not user-initiated; `sed` reported the nonexistent
path during the autonomous milestone inspection.

**Root cause**: The prior rule prohibited appending a guessed sibling after
discovery, but the same failure mode slipped through as substitution of a
conventional-looking spec basename before using the discovery result.

**Harness fix**: `CLAUDE.md` now explicitly forbids conventional basename
substitution as well as guessed sibling paths.

**Prevention**: Spec and plan reads are built directly from `rg --files`
output. A remembered number or naming convention may filter the inventory,
but it never constructs the path.

## 2026-07-22 — New descriptor test collided with existing helpers

**What happened**: The first SPEC-006 M4 contract red test declared
`findService` and `fieldRules`, names already defined in another test file in
the same package. The intended absent-RPC failure was masked by compile-time
redeclaration and call-shape errors.

**What the user said**: Not user-initiated; the focused red run reported the
helper collisions.

**Root cause**: Production identifiers were searched before the patch, but
the package's existing test helpers were not included in that symbol check.

**Harness fix**: `CLAUDE.md` now requires a package-wide name search before a
new package-level test helper is introduced.

**Prevention**: Descriptor tests reuse the shared package helpers and give
new assertion-only helpers domain-specific names.

## 2026-07-22 — Assumed acronym casing in sqlc output

**What happened**: The first device projector compile referenced
`CertificateDER`, but sqlc generated `CertificateDer` for the
`certificate_der` column.

**What the user said**: Not user-initiated; the focused store build reported
the unknown generated field.

**Root cause**: The handwritten projector was completed before the newly
generated sqlc structs were inspected, and Go acronym style was assumed to
match the generator's casing policy.

**Harness fix**: `CLAUDE.md` now requires inspecting generated identifier
spelling immediately after generation and before adding call sites.

**Prevention**: Generated structs and parameter types are the source of truth
for all handwritten query-layer references.

## 2026-07-22 — Casing fix crossed handwritten/generated struct boundaries

**What happened**: The first `CertificateDer` correction changed the return
literal for the handwritten `Device` type while leaving `CertificateDER` in
the sqlc parameter literal. The follow-up compile therefore reported both
opposite casing errors.

**What the user said**: Not user-initiated; the focused store build exposed
the mis-targeted replacement.

**Root cause**: A repeated field label was patched by text shape without
checking the enclosing struct type at both sites.

**Harness fix**: `CLAUDE.md` now requires receiver-type verification when
handwritten and generated identifiers differ only by casing.

**Prevention**: Casing fixes use numbered, enclosing-type contexts and are
checked at every remaining spelling before recompilation.

## 2026-07-22 — Enrollment plan placed CA signing before authorization

**What happened**: The first M4 security-ordering plan placed certificate
construction after CSR validation but before registration-token admission.
That would let unauthenticated callers repeatedly invoke the private CA signer
even though no certificate was returned.

**What the user said**: Not user-initiated; the issue was caught while mapping
the red handler tests to the implementation order.

**Root cause**: Avoiding token consumption on a rare signer failure was given
priority over keeping expensive private-key operations behind authorization.

**Harness fix**: `CLAUDE.md` now states that public credential-gated paths
authorize before invoking a private-key signer.

**Prevention**: Enrollment validates hostile structure first, consumes the
token second, and only then signs and persists the issued identity. Post-auth
infrastructure failures fail closed without returning certificate material.

## 2026-07-22 — Inferred listener registry receiver syntax

**What happened**: The M4 B10 registrations used `(Server)` keys, while the
listener discovery guard represents pointer receivers as `(*Server)`. The
guard correctly reported two orphan registrations and the real sites as
unregistered.

**What the user said**: Not user-initiated; the focused boundary join exposed
the exact-key mismatch.

**Root cause**: The registration keys were transcribed from a prior summary
instead of being copied from the discovery mechanism after the call sites
existed.

**Harness fix**: `CLAUDE.md` now requires listener keys to come from
`guardtest.ListenerSites` output rather than inferred receiver formatting.

**Prevention**: New listener code lands first, discovery supplies its exact
keys, and only those keys enter the boundary registry.

## 2026-07-22 — No-clobber test accidentally exercised root ownership

**What happened**: The first `WriteFileNew` behavior tests used `t.TempDir()`
without isolating the existing privileged-parent gate. Under the normal
unprivileged test user, the create was correctly refused before reaching the
atomic no-overwrite behavior the tests intended to cover.

**What the user said**: Not user-initiated; the focused SDK test reported
`ErrUnsafeParentDir`.

**Root cause**: The fixture assumed mode `0700` was sufficient and overlooked
that the production primitive deliberately also requires uid 0 ownership.

**Harness fix**: `CLAUDE.md` now states how unit tests behind root-owned-parent
preconditions must isolate or reproduce that prerequisite.

**Prevention**: No-clobber tests stub only the established parent-ownership
seam; the existing parent-safety tests continue to prove the production gate.

## 2026-07-22 — Initially selected an older available x/term release

**What happened**: Dependency setup first selected `golang.org/x/term` v0.39.0
to align with an existing transitive `x/sys` version even though the version
inventory showed the compatible stable v0.45.0 release.

**What the user said**: Earlier feedback explicitly challenged using an older
available CI/tool release; the same principle applies to a new library pin.

**Root cause**: Minimizing transitive upgrades was treated as sufficient reason
to choose a stale direct dependency without an actual compatibility bound.

**Harness fix**: `CLAUDE.md` now requires the newest verified stable compatible
version for new direct dependencies unless a documented bound says otherwise.

**Prevention**: Version inventory and toolchain compatibility are checked
before `go get`; transitive alignment does not override an available current
release.

## 2026-07-22 — Guessed config companion file after prior path corrections

**What happened**: A config-guard inspection read the verified
`sdk/config/config.go` and then appended a conventional `sdk/config/doc.go`
path that does not exist; the documentation generator lives in `config.go`.

**What the user said**: Not user-initiated; `sed` reported the nonexistent
companion during autonomous guard remediation.

**Root cause**: Knowing the package directory was incorrectly treated as an
inventory of conventional source filenames, repeating the earlier guessed
basename failure in a different subtree.

**Harness fix**: `CLAUDE.md` now explicitly says a known directory is not a
file inventory and requires `rg --files` output for multi-file reads.

**Prevention**: Every path in a multi-file inspection is pasted from the
immediately preceding subtree inventory; conventional companion names are not
inferred.

## 2026-07-22 — Module tidy rewrote workspace-local dependencies

**What happened**: Running `go mod tidy` inside the agent and server modules
added pseudo-version requirements and checksums for the workspace-local
contract and SDK modules, and expanded `go.work.sum` with unrelated graph
entries, contrary to the repository's established `go.work` convention.

**What the user said**: Not user-initiated; manifest review caught the
requirements early and final staged review caught the residual sum noise
before commit.

**Root cause**: Dependency cleanup was run without first comparing the target
manifests with sibling-module conventions and the pre-change files.

**Harness fix**: `CLAUDE.md` now requires that convention check before module
tidying in a multi-module workspace.

**Prevention**: Add and verify only the external requirements needed by the
change; inspect manifests and all module/workspace sums for workspace-local
pseudo-versions or unrelated expansion before accepting a tidy diff.

## 2026-07-22 — Combined cleanup patch used stale manifest context

**What happened**: A single cleanup patch mixed module, test, harness, and
journal edits after `go mod tidy` had changed the manifest layout, so one stale
context rejected the entire patch.

**What the user said**: Not user-initiated; the patch failure was detected
immediately and changed no files.

**Root cause**: An existing small-patch rule was not followed during cleanup
of files with different change histories.

**Harness fix**: The existing rule to keep patches small and local already
covers this failure; no additional standing rule is needed.

**Prevention**: Split cleanup by concern and re-read any generated or
tool-rewritten file immediately before patching it.

## 2026-07-22 — Symbol search result was replaced with an inferred filename

**What happened**: An fsafe review found `replaceFileFrom` in
`replace_linux.go`, but the follow-up read named an inferred `write_linux.go`.
Because the inspection used fail-fast command sequencing, the remaining reads
did not run.

**What the user said**: Not user-initiated; the missing-file error exposed the
mistake during the pre-commit review.

**Root cause**: The exact symbol-search result was not carried into the next
command, despite an existing rule requiring discovered paths to be reused.

**Harness fix**: The existing `CLAUDE.md` path-inventory rule already covers
this case; no new standing rule is needed.

**Prevention**: Run `rg --files` for the subtree and paste the returned path
verbatim before any multi-file inspection.

## 2026-07-22 — Nonexistent top-level SDK test glob stopped a review read

**What happened**: A guard review used `sdk/*_test.go`, but SDK tests live in
subpackage directories. `rg` reported the nonexistent path and fail-fast
sequencing prevented the intended fsafe source read.

**What the user said**: Not user-initiated; the command error was caught
during the same pre-commit review.

**Root cause**: A shell glob was used as a substitute for the repository file
inventory immediately after the prior path correction.

**Harness fix**: The existing discovered-path rule remains sufficient; the
problem was adherence, not missing guidance.

**Prevention**: Search from a verified directory root with `--glob` filters,
and use exact returned files for subsequent reads.

## 2026-07-22 — Docref treated `--help` as a path

**What happened**: A help probe used `docref suggest --help` and
`docref check --help`. This CLI accepts path positionals rather than those
subcommand help flags, so it ran an uncaptured suggestion discovery instead
of the required tee-backed scan and then failed trying to open a literal
`--help` path.

**What the user said**: Not user-initiated; the installed CLI's output made
the argument interpretation clear during documentation preparation.

**Root cause**: A conventional flag shape was assumed instead of using the
already-established repository invocation forms, and the help assumption was
allowed to bypass the standing full-output capture rule.

**Harness fix**: `CLAUDE.md` already documents the supported docref workflow
and full-output capture requirement; no new standing rule is needed.

**Prevention**: Invoke only the repository's known `docref suggest`,
`docref claim`, `docref approve`, and `docref check --strict` forms and capture
repository-wide scan output before filtering.

## 2026-07-22 — Used a removed docref `fix` command

**What happened**: After the suggestion scan, `docref fix` was invoked to
insert a marker. Docref 0.1.1 has no such command; its supported flow is
`claim` to generate marker blocks and `approve` after reviewing prose. The
failed invocation made no edits.

**What the user said**: Earlier feedback established that docref 0.1.1 is the
available release; the local usage output supplied its exact command set.

**Root cause**: A command from an older or assumed CLI shape was used without
checking it against the installed release's usage output.

**Harness fix**: `CLAUDE.md` now records the 0.1.1 `claim`/`approve` workflow
and explicitly rules out `fix`.

**Prevention**: Generate paste-ready markers with `docref claim <ref...>`,
place them around reviewed prose, and run `docref approve` followed by strict
check.

## 2026-07-22 — Early relay rejection closed with unread request bytes

**What happened**: The agent race suite observed the sixth rate-limited local
enrollment response as valid JSON followed by a connection-reset error. The
relay responded without reading the request that `Submit` had already sent.

**What the user said**: Not user-initiated; the required full race suite
exposed the protocol-level failure before commit.

**Root cause**: Exact response decoding was added without making the server's
early-rejection close behavior compatible with a client that writes and
half-closes before reading.

**Harness fix**: `CLAUDE.md` now records that bounded stream requests must be
drained before an early response is closed.

**Prevention**: The rate-limit path drains at most one local protocol frame,
then emits its generic response; the real Unix-socket sixth-attempt test runs
under the race detector.

## 2026-07-22 — Repeated nonexistent Makefile path after inventory output

**What happened**: A generation-gate inspection listed the contract's actual
Buf configuration files, then the same command named `contract/Makefile`,
which was absent from that inventory. `rg` reported the missing path while
still showing useful matches from the verified files.

**What the user said**: Not user-initiated; the pre-commit inspection exposed
the recurrence.

**Root cause**: Same-command discovery was incorrectly treated as permission
to include a conventional trailing path that had not been discovered.

**Harness fix**: `CLAUDE.md` now makes explicit that even a combined inventory
and read command may use only paths known before that command begins.

**Prevention**: Use the canonical verification script for Buf/sqlc drift and
keep any ad hoc inspection to exact files returned by a prior completed
inventory command.

## 2026-07-22 — Listener registry was omitted from the gofmt set

**What happened**: The first canonical M4 gate found
`sdk/guardtest/listeners.go` unformatted. Earlier formatting commands named the
new enrollment packages but omitted this modified shared registry.

**What the user said**: Not user-initiated; the canonical gofmt stage failed
closed before commit.

**Root cause**: Formatting scope followed the most recent implementation
files instead of the complete Git change inventory.

**Harness fix**: `CLAUDE.md` now requires deriving all modified and untracked
Go files from Git before the canonical gate and formatting that set.

**Prevention**: The milestone's full changed-Go inventory is formatted in one
repository-root pass before verification is rerun.

## 2026-07-22 — Local review found four minor completion gaps

**What happened**: The pre-commit review found that the M4 status update lacked
its milestone ledger row, X25519 negative tests used string fragments instead
of stable sentinels, and two TLS/local-protocol negative tests accepted any
error rather than the intended failure category.

**What the user said**: Not user-initiated; the required local review reported
four minor findings after the canonical gate was green.

**Root cause**: The existing ledger-parity and changed-negative-test review
rules were not applied exhaustively before invoking the reviewer.

**Harness fix**: Existing `CLAUDE.md` rules already require the ledger update
and an exact sentinel or stable category for every changed negative-test
branch; no additional standing rule is needed.

**Prevention**: M4 now has a ledger row, X25519 exposes malformed/low-order
sentinels, TLS 1.2 pins the protocol-version failure, and trailing local JSON
pins its internal sentinel before the local review is rerun.

## 2026-07-22 — Dependency cleanup happened after docref approval

**What happened**: Restoring the server module's pre-existing indirect
protobuf requirement after sum cleanup changed the `server/go.mod` anchor, so
the next canonical gate correctly reported the historical SPEC-005 M1 claim
as stale.

**What the user said**: Not user-initiated; strict docref caught the ordering
mistake before the feature commit.

**Root cause**: Docref was approved before the final dependency-manifest
cleanup instead of after every anchor-affecting edit was complete.

**Harness fix**: The existing strict docref gate is sufficient and failed
closed; no new standing rule is needed.

**Prevention**: Dependency manifests and sums are finalized first, then every
affected claim diff is reviewed and approved immediately before the final
canonical gate.

## 2026-07-22 — SPEC filename was inferred instead of discovered

**What happened**: The M5 review searched the SPEC-006 directory successfully,
then tried to read an inferred `006-pki-and-lifecycle.md` path. The actual file
is `006-pki-and-identity.md`, so the command failed before the intended source
and test reads ran.

**What the user said**: Not user-initiated; the missing-path error was visible
during the implementation pass.

**Root cause**: A content-search result was treated as a file inventory even
though it did not print the matched filename in the captured output.

**Harness fix**: The verification skill now requires an immediate fresh
`rg --files` inventory after any missing-path error before another read is
attempted.

**Prevention**: Complete file discovery as its own command and paste the exact
returned path into the next read.

## 2026-07-22 — Unsupported docref help flags were retried

**What happened**: The documentation pass invoked `docref --help` and chained
subcommand help probes even though this installed CLI prints usage from bare
`docref` and treats subcommand arguments as paths. The first unsupported flag
stopped the remaining probes.

**What the user said**: Earlier feedback established docref 0.1.1 as the
installed release; this pass's usage output confirmed its command shape.

**Root cause**: Conventional CLI help syntax was assumed instead of following
the repository's already-recorded docref workflow.

**Harness fix**: The verification skill now states that bare `docref` is the
only help/usage probe and that `--help` must not be passed to its subcommands.

**Prevention**: Use the documented `claim`, `diff`, `approve`, and `check`
forms directly, and use bare `docref` only when the command list is needed.

## 2026-07-22 — M5 surfaces omitted three shared guard integrations

**What happened**: The first full race sweep found that the two certificate
response messages had no reviewed near-copy rationale, the renewal projection
query had no projector owner in the root guard, and the renewal handler test
mixed stdlib JSON with generated protobuf imports.

**What the user said**: Not user-initiated; the repository-wide guard suites
failed before the canonical gate.

**Root cause**: Focused package tests were used while adding the new contract,
sqlc mutator, and handler test, but their cross-module guards were not run at
the moment each surface was introduced.

**Harness fix**: The guards skill now requires the near-copy,
projection-owner, and protojson guards to run when their corresponding surface
is created, with registry ownership or rationale recorded in the same patch.

**Prevention**: New RPC messages carry a deliberate near-copy decision, every
projection mutation names its projector owner and raises the discovery floor,
and JSON event decoding lives in a test file that does not import generated
protobufs.

## 2026-07-22 — M5 plan duplicated normative spec detail

**What happened**: The pre-commit review found that the initial M5 plan copied
behavioral requirements, security ordering, acceptance narratives, and
out-of-scope policy instead of remaining a delta-only implementation index.

**What the user said**: Not user-initiated; the required local review caught
the documentation scope before commit.

**Root cause**: The implementation plan was written as a self-contained design
document even though SPEC-006 already owns those approved requirements.

**Harness fix**: The spec-development skill now repeats the delta-only plan
boundary at the session step where the spec and touched code are read.

**Prevention**: Milestone plans list only changed files, symbols, and test
names; normative prose and execution details remain in their owning spec or
skill.

## 2026-07-22 — A review suggestion bypassed the plan-scope rule

**What happened**: A local review requested explicit verification commands in
the M5 milestone plan. The suggestion was applied even though the repository's
delta-only rule excludes commands and process notes; the remote review caught
the contradiction.

**What the user said**: Not user-initiated; the conflicting review findings
made the rule violation visible before merge.

**Root cause**: The suggested patch was checked for reproducibility but not
reconciled with the plan's governing scope rule before application.

**Harness fix**: The spec-development skill now explicitly names verification
commands and process notes as excluded and requires conflicting review advice
to be rejected.

**Prevention**: Validate every review suggestion against the owning repository
rule before applying it, even when the suggestion is otherwise reasonable.

## 2026-07-22 — Docref approval omitted its required paths

**What happened**: I invoked `docref approve` without path arguments while
refreshing reviewed M5 claims. The CLI rejected the command without changing
files.

**What the user said**: Not user-initiated; the command output exposed the
mistake during the documentation gate.

**Root cause**: I remembered that approval follows review but omitted the
installed CLI's explicit-path requirement.

**Harness fix**: The verification skill now states that `docref approve` must
always receive one or more root-relative paths.

**Prevention**: Pass the exact reviewed documentation paths to every docref
approval invocation, then run the strict repository-wide check separately.

## 2026-07-22 — Commit-range lint omitted its head revision

**What happened**: I invoked `check-conventions.sh ci-commits` with only the
base revision. The script rejected the command because the required head
revision was missing.

**What the user said**: Not user-initiated; the pre-push commit inspection
surfaced the incomplete command.

**Root cause**: I inferred the command shape from verification output instead
of checking the script's required arguments.

**Harness fix**: The verification skill now records that the head revision is
mandatory while an empty or unknown base deliberately selects the fallback.

**Prevention**: Always supply the head revision; supply a known base when one
exists or an empty base to exercise the documented fallback.

## 2026-07-22 — Repeated server-workdir formatting path failure

**What happened**: A combined command again declared `server/` as its working
directory while passing repository-root paths to `gofmt`. Formatting failed
before the focused tests ran and changed no files.

**What the user said**: Not user-initiated; `gofmt` immediately reported the
nonexistent root-prefixed paths under the module directory.

**Root cause**: Formatting and module testing were still grouped into one tool
call despite the existing repository-root formatting rule.

**Harness fix**: The verification skill now requires every `gofmt` invocation
to be a separate tool call whose declared workdir is the Git repository root;
module tests follow in a separate call using `go test -C`.

**Prevention**: Never optimize formatting and module tests into one executor
call. Format first from the root, then test the module through Go's `-C` flag.

## 2026-07-22 — Logged canonical gate omitted pipefail

**What happened**: The canonical verification gate found stale docref claims
and printed `VERIFY FAILED`, but its surrounding `tee` pipeline returned zero
because the invocation omitted `set -o pipefail`.

**What the user said**: Not user-initiated; the preserved full gate output
made the discrepancy visible before commit.

**Root cause**: The output-preservation pattern was copied without the
failure-propagation prefix already required by the verification skill.

**Harness fix**: The verification skill now records the literal logged gate
shape with `set -o pipefail` as a mandatory prefix.

**Prevention**: Every canonical gate piped through `tee` uses the recorded
literal command shape so the tool result and the gate summary agree.

## 2026-07-22 — Manual formatting rule ambiguously covered the gate

**What happened**: The strengthened formatting rule said every `gofmt`
invocation must be a separate tool call, which could be read as forbidding the
canonical verification script from running formatting and tests as internal
stages.

**What the user said**: Not user-initiated; the remote review identified the
scope ambiguity before merge.

**Root cause**: The rule described the executor boundary without distinguishing
ad hoc commands from commands orchestrated inside the repository gate.

**Harness fix**: The verification skill now scopes separate-call and workdir
requirements to manually issued commands and explicitly exempts
`verify.sh`'s internal stages.

**Prevention**: Tooling rules name their execution layer so they cannot
accidentally constrain the canonical script they are intended to protect.

## 2026-07-22 — Logged gate example used shell metasyntax

**What happened**: The verification skill presented `tee <log>` as a literal
command even though angle brackets are shell redirection syntax, so copying the
example could fail instead of preserving the gate output.

**What the user said**: Not user-initiated; the final local review caught the
non-executable placeholder before commit.

**Root cause**: A prose placeholder was embedded inside a command explicitly
described as literal and copyable.

**Harness fix**: The logged canonical gate now uses the concrete path
`/tmp/verify.log`.

**Prevention**: Literal command examples contain only executable shell tokens;
variable placeholders are defined separately before use.

## 2026-07-22 — Renewal-loop tests had unbounded readiness waits

**What happened**: Two concurrent renewal-loop tests bounded completion but
used bare channel receives while waiting for the renewer to start, so a setup
regression could hang the suite indefinitely. The retry-observability test also
accepted any non-nil reported error instead of the configured cause.

**What the user said**: Not user-initiated; the final local review found both
test-quality gaps before publication.

**Root cause**: Completion synchronization received careful timeout coverage,
but readiness synchronization and the wrapped sentinel assertion were not
audited with the same intent-level standard.

**Harness fix**: `CLAUDE.md` now requires timeout bounds on every
concurrent-test channel wait, including readiness. The retry test retains and
asserts its configured sentinel through the reporting wrapper.

**Prevention**: Concurrent tests cannot hang before their completion select,
and negative observability checks prove the exact intended cause.

## 2026-07-22 — The recorded docref help rule was repeated

**What happened**: The M6 documentation pass invoked `docref approve --help`
even though an earlier same-day journal entry and the verification skill state
that docref 0.1.1 treats subcommand arguments as paths.

**What the user said**: Earlier feedback established that docref 0.1.1 is the
installed system version.

**Root cause**: Generic CLI help habits were followed without checking the
repository's already-recorded command rule.

**Harness fix**: The prohibition now also appears in the session-wide
verification-honesty rules, next to the exact supported usage probe.

**Prevention**: Run bare `docref` for usage and invoke known subcommands
directly; never probe docref subcommands with `--help`.

## 2026-07-22 — Verification paths did not match the working directory

**What happened**: A compound verification command selected `server/` as its
working directory while still passing repository-root-relative paths such as
`server` and `server/internal/...`; `make` rejected the nonexistent nested
path before any check ran.

**What the user said**: Not user-initiated; the command failed immediately
during the M6 pre-publication checks.

**Root cause**: The command list was composed for the repository root and its
working directory was changed independently.

**Harness fix**: The session-wide verification rules now require choosing one
working directory and resolving every path in a compound command against it.

**Prevention**: Keep repository-wide commands at the repository root, and use
module-relative arguments only when intentionally running from a module.

## 2026-07-22 — A stale multi-file patch rule was repeated

**What happened**: The first M6 connected-CRL integration-test patch combined
code and plan edits while assuming imports that the test file already carried.
The stale import context caused the patch tool to reject every hunk without
changing files.

**What the user said**: Not user-initiated; the patch failed during the M6
acceptance-path test addition.

**Root cause**: The plan context was inspected, but the code import block was
reconstructed from memory instead of copied from the current file, repeating
an already-recorded patch-context mistake.

**Harness fix**: A context failure now activates a strict single-file patch
rule for the rest of the turn, with freshly printed surrounding lines required
before each patch.

**Prevention**: Patch the code and documentation separately, and never include
an already-present import in an additive import hunk.

## 2026-07-22 — Linked-worktree merge cleanup obscured remote success

**What happened**: `gh pr merge --rebase --delete-branch` was run from a
feature worktree while `main` was checked out in the primary worktree. The
remote merge succeeded, but the command then failed during local base-branch
checkout and cleanup, making the successful remote mutation initially unclear.

**What the user said**: Not user-initiated; the post-merge state check showed
that the PR had merged before the local worktree error was reported.

**Root cause**: The merge command was launched from the changed worktree
instead of the worktree that already owned the base branch, and the local
cleanup failure was read before checking the remote PR state.

**Harness fix**: `CLAUDE.md` now requires PR merges to run from the clean
worktree that owns the base branch and requires a remote state check before any
retry after a merge-command error.

**Prevention**: Linked-worktree merges avoid an unnecessary checkout conflict,
and an ambiguous post-merge error can never cause a duplicate merge attempt.

## 2026-07-22 — Parameterized fixture combined multiple SQL commands

**What happened**: A scoped projection-corruption fixture combined an
argument-bearing `UPDATE` and a `DELETE` in one pgx `Exec`. The extended query
protocol rejected the prepared statement before either mutation ran.

**What the user said**: Not user-initiated; the affected store package test
reported SQLSTATE 42601 during the M6 rebase verification.

**Root cause**: A formerly argument-free multi-command fixture gained a bound
device ID without being split at the prepared-statement boundary.

**Harness fix**: `CLAUDE.md` now requires parameterized pgx `Exec` calls to
contain exactly one SQL statement.

**Prevention**: Scoped fixture mutations retain their predicates while each
prepared call remains valid under pgx's extended protocol.

## 2026-07-23 — Manual gofmt was bundled with a read-only probe

**What happened**: A successful repository-root `gofmt` invocation shared one
executor call with a preceding `rg` query instead of running as the required
standalone manual formatting step.

**What the user said**: Not user-initiated; the process violation was caught
before the affected tests ran.

**Root cause**: Independent read and formatting steps were grouped for
throughput even though the established command-hygiene rule prioritizes an
unambiguous formatter boundary.

**Harness fix**: This journal now records that “separate tool call” means the
manual formatter is the only shell command in that executor call, including no
read-only prefix or suffix.

**Prevention**: Run repository-root `gofmt` alone, wait for it to complete, and
start module tests in a later call. This rule applies to a manual formatter
invocation; the canonical verification script retains its own output-capture
harness.

## 2026-07-23 — RED-suite clone helper discarded its source

**What happened**: The trust-state test clone helper replaced the root slice
before copying its elements, so every mutation case received empty
fingerprints and one case panicked before exercising production behavior.

**What the user said**: Not user-initiated; the defect surfaced on the first
focused green run after the independently approved RED checkpoint.

**Root cause**: RED review checked scenario coverage and expected failures but
did not execute the clone helper far enough to prove that copied claims
preserved every covered field.

**Harness fix**: `CLAUDE.md` now requires clone helpers to preserve their
source before replacing the destination as part of RED approval.

**Prevention**: Mutation tests retain a stable source snapshot, so each case
reaches the intended validation or cryptographic assertion instead of failing
inside test setup.

## 2026-07-23 — Proto guard required a lint-forbidden tag shape

**What happened**: The trust-bundle descriptor guard required equal
`min_len`/`max_len` byte rules even though Buf lint requires the equivalent
exact-length rule to use `len`.

**What the user said**: Not user-initiated; `buf lint` rejected the first
production proto that satisfied the RED guard.

**Root cause**: The guard pinned a descriptor encoding instead of the security
invariant and was not checked against Buf's canonical rule representation.

**Harness fix**: `CLAUDE.md` now requires descriptor guards to accept Buf's
canonical validation-tag form.

**Prevention**: Exact-byte guards assert the same length invariant through
the canonical `len` field, allowing both the security test and lint gate to
pass without weakening validation.

## 2026-07-23 — Fixed-date trust fixtures depended on the wall clock

**What happened**: Real TLS checks created authorities around a fixed future
instant but left `tls.Config.Time` unset, while an overlap phase erased its
transition proof before reading it and a non-CA mutation produced a template
that `x509.CreateCertificate` itself rejects.

**What the user said**: Not user-initiated; the first focused green run failed
inside TLS and fixture construction rather than at the intended assertions.

**Root cause**: RED review did not prove that fixed-time integration fixtures
were independent of the machine clock or that setup mutations still produced
valid adversarial inputs.

**Harness fix**: `CLAUDE.md` now requires fixed-date TLS tests to install the
matching `Config.Time` seam and fixtures to preserve values before reset or
replacement.

**Prevention**: Trust tests run deterministically at any wall-clock instant,
and negative certificates reach production validation instead of failing in
their constructors.

## 2026-07-23 — Migration-report gateway fixture used the agent lifetime

**What happened**: The CA migration report's shared leaf factory assigned a
365-day lifetime before switching only the identity and EKU fields for its
gateway branch. Production validation correctly rejected that gateway before
the cryptographic issuer-classification assertion ran.

**What the user said**: Not user-initiated; the focused store test exposed the
fixture/profile mismatch during SPEC-006 M8 implementation.

**Root cause**: The shared fixture treated class-specific certificate profiles
as only identity and EKU differences and missed the gateway's 45-day lifetime.

**Harness fix**: `CLAUDE.md` now requires approved RED certificate fixtures to
match the current production certificate profile before implementation begins.

**Prevention**: Shared certificate factories must set every class-specific
profile field before signing, so negative tests reach the behavior they name.

## 2026-07-23 — Issuer-scoped work fixture promoted embedded fields in a literal

**What happened**: The new CRL retry fixture initialized `WorkItem` using
promoted `Work` fields directly. Go permits promoted field selection but not
promoted keys in a composite literal, so the RED package did not compile once
the production symbols reached that test.

**What the user said**: Not user-initiated; the focused PKI compile exposed the
fixture construction error during SPEC-006 M8 implementation.

**Root cause**: RED review checked the work-item semantics but did not compile
the embedded-struct literal against its actual declaration.

**Harness fix**: `CLAUDE.md` now requires composite literals to resolve
embedded fields through the declared embedded field name.

**Prevention**: Test fixtures mirror the declared data shape and reach the
intended retry/idempotency behavior instead of failing at compile time.

## 2026-07-23 — A second non-CA mutation retained CA-only path length

**What happened**: The rotation transition-proof factory set `IsCA=false` for
an adversarial case but retained `MaxPathLenZero=true`, causing
`x509.CreateCertificate` to reject the fixture before production validation.

**What the user said**: Not user-initiated; the canonical rotation matrix
reached this fixture after the manager began compiling and running.

**Root cause**: The earlier correction covered another certificate factory,
but the RED review rule described profile preservation too generally and did
not explicitly require CA-only fields to be cleared after a non-CA mutation.

**Harness fix**: `CLAUDE.md` now calls out constructibility after CA/profile
mutations, and this shared proof factory normalizes CA-only path-length fields.

**Prevention**: Every negative certificate mutation is signed in isolation
during RED review, so constructor rejection cannot masquerade as boundary
validation coverage.

## 2026-07-23 — Zero-consumer agent gates were required to fail and succeed unchanged

**What happened**: The invalid-edge matrix required agent `Migrate` and
`Normalize` calls to fail with no active consumers, while canonical paths
required the same zero-consumer gates to succeed without adding any state.

**What the user said**: Not user-initiated; the contradiction surfaced when
the first canonical manager behavior reached the invalid-edge matrix.

**Root cause**: Gateway-only intrinsic-control gates were applied to both CA
classes in shared test maps even though the role matrix deliberately excludes
control as an agent-root consumer.

**Harness fix**: `CLAUDE.md` now requires RED acceptance paths to be mutually
satisfiable. The gated migrate/normalize negatives are scoped to gateway
rotation; agent zero-consumer gates remain deliberately vacuous.

**Prevention**: Shared class matrices must justify every class-specific row
against the closed role matrix before RED approval.

## 2026-07-23 — Invalid trust claims were rejected by the test signer

**What happened**: Negative manager cases mutated claims into forbidden role,
missing-fingerprint, or zero-CRL shapes and then called the shared signing API.
That API correctly rejected the invalid claim before the manager saw it.

**What the user said**: Not user-initiated; the consumer-gate suite failed in
fixture signing rather than at the expected manager rejection.

**Root cause**: The RED fixtures assumed a validated signing helper could
create semantically invalid signed input, conflating signing-contract tests
with trust-boundary rejection tests.

**Harness fix**: `CLAUDE.md` now requires negative crypto inputs either to be
constructible or explicitly malformed when the shared signer rejects them.
The fixture supplies a non-empty invalid signature in that case.

**Prevention**: Structurally valid mutation cases remain genuinely signed;
structurally forbidden cases still reach the manager and prove fail-closed
rejection without weakening any acceptance expectation.

## 2026-07-23 — Fence test expected a raw database error over RPC

**What happened**: The issuance commit-failure test required the enrollment
RPC error to contain the trigger's internal PostgreSQL exception text.

**What the user said**: Not user-initiated; the full SPEC-006 PKI run reached
the assertion after the real shared-fence path was wired.

**Root cause**: The RED fixture conflated proof of rollback with observability
of a private storage failure, contradicting the existing generic enrollment
error boundary.

**Harness fix**: The test now requires the stable generic internal error,
explicitly rejects leaked trigger text, and still proves that no identity row
was committed and both fences were released.

**Prevention**: Failure-injection tests must verify public error contracts and
durable side effects separately; private dependency details are never an RPC
acceptance criterion.
