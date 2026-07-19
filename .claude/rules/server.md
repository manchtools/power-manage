---
paths:
  - "server/**"
---

# Server module

## Event sourcing

- Projectors run IN the append transaction; projection tables are written
  only by projectors; queries read projections, never the event log.
- Every event type ↔ exactly one registered projector, both directions
  (registry-parity guard). New event type without a projector must fail the
  guard, not silently project nothing.
- Payload decode in a projector uses the typed generic decoder; decode
  failure fails the transaction — never skip past a corrupt event.
- CAS appends (`AppendEventWithVersion`) are never auto-retried — a retry
  loop defeats the optimistic lock's purpose; surface the conflict.
- Async work exists ONLY as Postgres work tables (`FOR UPDATE SKIP LOCKED`,
  in-tx outbox). No queue product, no cache product — a preserved operator
  decision.

## Handlers

- CRUD goes through the table-driven kernel (API-1) — a hand-written handler
  family for a kernel-shaped domain is a finding.
- `store.IsNotFound(err)` — never raw `errors.Is` against store sentinels.
- Non-owner/out-of-scope reads return NotFound; scope is enforced at the
  handler level per grant.

## Storage

- Migrations: append-only, never edit shipped ones; wrap statements in the
  goose StatementBegin/StatementEnd markers.
- sqlc via `make sqlc-generate` (pinned toolchain); never hand-edit
  `generated/`.
- Every table carries exactly one storage classification (schema-walk guard).
