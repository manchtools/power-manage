---
name: spec-driven-dev
description: The mandatory pipeline for every implementation session in this repo — pick one spec milestone, TDD it red-first, verify green, update the ledger. Activates at the start of any feature, handler, or behavior change.
---

# Spec-driven development

No code without a spec. No spec without acceptance criteria. No acceptance
criterion without a test. The specs live in `docs/content/01-specs/`, numbered in build
order; `docs/content/01-specs/00-index.md` is the status ledger.

## The session loop

1. **Pick**: resume open work first — an open PR or in-flight branch is
   finished (findings fixed, merged) before anything new starts. Otherwise
   take the next unimplemented milestone from the ledger (or the one the
   operator names): lowest-numbered spec whose `Builds on:` specs are far
   enough along, next milestone in its §9. One milestone in flight at a time —
   milestones are sized so a session never needs long-lived context.
2. **Read** the whole spec, its "Context capsule", and the capsules of every
   spec in its `Builds on:` header. Read the existing code the milestone
   touches. Never start from memory or assumption.
3. **Red**: write tests from the acceptance criteria and rejection-path table.
   Run them. Every new test must FAIL, and fail for the right reason (assert on
   the failure message, not just the exit code). A test that passes before the
   implementation exists is testing nothing.
4. **Green**: implement the minimum that passes. Match surrounding style.
5. **Guards**: if the milestone introduces an invariant, ship its
   self-discovering guard in the same change (see the `guards` skill).
6. **Verify**: `./scripts/verify.sh` — all gates green, full output captured.
7. **Ledger**: mark the milestone done in `docs/content/01-specs/00-index.md`.
8. **Commit**: conventional commit; tests and implementation ship together in
   the same commit/PR — never split them.
9. **Ship**: push the branch and open the PR (spec section + AC IDs in the
   body), run the `reviewer` agent, batch review + CI fixes into one commit
   naming the findings (fixed defects get their regression test proven red
   first), poll CI to completion, and merge yourself once — re-checked at
   merge time — every gate is green and every finding is addressed. Then
   return to step 1 and take the next milestone while context allows.

## Deviation rules

- The specs are operator-approved. Implement as written.
- Behavior change, new dependency, or skipped guard → STOP and ask the
  operator. A focused question beats a confident guess. If the operator is
  not around, record the question as a GitHub issue on this repository and
  continue with the next milestone that does not depend on the answer; stop
  only when nothing is unblocked.
- Mechanical spec gap (typo, missing field name, obvious omission) → fix the
  spec in the same PR and note it in the PR description.
- Never defer in-scope work with TODOs or "follow-up" notes without explicit
  operator approval. The refactor IS the work — continue until a true
  roadblocker.

## Bug fixes

A bug fix REQUIRES a regression test that fails on the buggy version and passes
with the fix. Prove the red: neutralize the fix with a scoped edit (comment the
guard, flip the branch), run, confirm the test fails for the right reason, then
restore. Never prove red by `git checkout`/`git restore` — that discards
uncommitted work.

Fix the root cause, not the symptom: before editing, find every caller of the
function you're about to touch. One guard in the shared path beats N guards in
N callers.
