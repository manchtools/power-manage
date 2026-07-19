---
name: go-discipline
description: Go-specific conventions for this repo — error handling, clock/exec seams, context flow, projector patterns, generated code. Activates for all Go code.
---

# Go discipline

## Errors

- Never silently ignore an error: no `_ =` on error returns, no empty
  branches after a failed call. If an error is genuinely ignorable, say why
  in a comment on that line.
- Wrap with context: `fmt.Errorf("scope: %w", err)`. The message names what
  was being attempted, not the function name.
- **Sentinel recognition goes through the store's recognizer** (e.g.
  `store.IsNotFound(err)`), never `errors.Is(err, store.ErrNotFound)` at call
  sites. Driver/generated code returns the raw backend error
  (`sql.ErrNoRows`), so the direct `errors.Is` branch is dead code that a
  green suite never notices. A guard enforces this.
- Map errors to wire codes in exactly one place per binary; handlers return
  domain errors.
- No `goto`.

## Seams (testability without mocks-everywhere)

- **Clock**: no naked `time.Now()` — everything time-dependent takes the
  clock seam, including deadlines (`SetDeadline`). Enforced by guard.
- **Exec/hot-path**: functions that shell out or touch the host are
  package-var seams (`var runCmd = func(...)`) so tests save/restore and
  override. Low-risk, no interface ceremony.
- Do not create an interface for a single implementation; the package-var
  seam is the tool for stubbing. (Interfaces are for genuinely multiple
  implementations, e.g. per-package-manager backends.)

## Context

- No `context.Background()` in request paths — use the request context or a
  lifecycle context. Background-worker loops get a lifecycle context wired
  from main. Enforced by guard.
- Every goroutine launched from a request or stream handler goes through the
  panic-recovering spawn helper — a panic in a stray goroutine must not kill
  the process.

## Event sourcing specifics

- Projectors run in-transaction with the append; projection tables are only
  written by projectors. Queries read projections, never the event log.
- Every event type registers exactly one projector; registry-parity guard
  enforces both directions.
- Payload decode in a projector uses the typed generic decoder; a decode
  failure fails the transaction (never skip-and-continue past a corrupt
  event).
- Migrations are append-only: never edit a shipped migration, add a forward
  one (the migration tool tracks by version, not content).

## Hygiene

- `gofmt -w` on touched files before every commit.
- Generated code (`sqlc`, `protoc`/`buf` output) is never hand-edited —
  change the source, regenerate.
- Match the surrounding code's comment density and naming. Comments state
  constraints code can't express, not narration.
- Keep dependencies few. Before adding one: stdlib? already-imported dep? a
  few lines by hand? A new module needs operator sign-off.
