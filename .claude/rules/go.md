---
paths:
  - "**/*.go"
---

# Go discipline

## Errors

- Never silently ignore an error: no `_ =` on error returns, no empty
  branches after a failed call. Genuinely ignorable → say why in a comment on
  that line.
- Wrap with context: `fmt.Errorf("what was attempted: %w", err)`.
- Sentinel recognition goes through the store's recognizer (e.g.
  `store.IsNotFound(err)`), never `errors.Is(err, store.ErrNotFound)` at call
  sites — generated/driver code returns the raw backend error
  (`sql.ErrNoRows`), so the direct branch is dead code. A guard enforces this.
- Map errors to wire codes in exactly one place per binary.
- No `goto`.

## Seams

- No naked `time.Now()` — everything time-dependent takes the clock seam,
  including `SetDeadline`. Guard-enforced.
- Functions that shell out or touch the host are package-var seams
  (`var runCmd = func(...)`) so tests save/restore and override.
- No interface for a single implementation — the package-var seam is the
  stubbing tool; interfaces are for genuinely multiple implementations.

## Context and goroutines

- No `context.Background()` in request paths — request context or a
  lifecycle context wired from main. Guard-enforced.
- Every goroutine launched from a request or stream handler goes through the
  panic-recovering spawn helper.

## Hygiene

- `gofmt -w` on touched files before committing.
- No deprecated APIs; use the supported stdlib replacement and let
  `staticcheck` reject compatibility shims around obsolete calls.
- New dependencies need operator sign-off — stdlib or an already-imported
  dep first.
- Comments state constraints the code can't express, not narration; match
  surrounding density and naming.
