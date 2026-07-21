# Error journal

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
