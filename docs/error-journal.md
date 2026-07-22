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
