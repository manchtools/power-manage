# SPEC-005 M1 — Core append and in-transaction projection

Milestone: SPEC-005 §9 M1, AC-1..4.

## Delta

<!-- docref: begin src=server/go.mod:4f158330 -->
- `server/go.mod`, `server/go.sum`: pinned pgx, goose, and Postgres
  testcontainers dependencies required by SPEC-005.
<!-- docref: end -->
<!-- docref: begin src=server/internal/store/migrations/001_events.sql#@events-schema:902b4a87,server/internal/store/generated/events.sql.go#CurrentStreamVersion:1af6ae91,server/internal/store/generated/events.sql.go#InsertEvent:dc7d90d3,server/internal/store/store.go#AppendEvent:59053c99,server/internal/store/store.go#ProjectionTx:fbd1c222,server/internal/store/store.go#Projector:77e93082 -->
- `server/internal/store/migrations/001_events.sql`,
  `server/internal/store/migrations/embed.go`: `events` schema and embedded goose
  migration.
- `server/internal/store/queries/events.sql`,
  `server/internal/store/sqlc.yaml`, `server/internal/store/generated/*`,
  `server/Makefile`: generated event queries and reproducible sqlc drift check.
- `server/internal/store/store.go`: `Event`, `PersistedEvent`, `ProjectionTx`,
  `Projector`, `Store`, `New`, `Migrate`, and `AppendEvent`.
<!-- docref: end -->
<!-- docref: begin src=server/internal/testpostgres/harness.go#Run:fc59d866,server/internal/testpostgres/harness.go#Database:9fb07883 -->
- `server/internal/testpostgres/harness.go`,
  `server/internal/store/postgres_test.go`, `server/internal/store/store_test.go`:
  one shared Postgres testcontainer, template-cloned databases, and the M1
  acceptance tests below.
<!-- docref: end -->
<!-- docref: begin src=server/Makefile#@sqlc-check:cbafa3bc,scripts/verify.sh#@sqlc-generated-gate:4b342fe3 -->
- `scripts/verify.sh`, `scripts/verify_test.sh`: non-mutating sqlc generated-code
  gate and failure fixture.
<!-- docref: end -->
- `docs/content/01-specs/00-index.md`: SPEC-005 M1 status and ledger row.

## Acceptance tests

<!-- docref: begin src=server/internal/store/store_test.go#TestEventsUniqueStreamVersion_ConcurrentConflict:440295cb,server/internal/store/store_test.go#TestAppendEvent_AutoVersionsConcurrentFacts:324f203a,server/internal/store/store_test.go#TestAppendEvent_UnregisteredTypeWritesNothing:f32ff24a,server/internal/store/store_test.go#TestAppendEvent_ProjectorFailureRollsBack:c7d6a08a,server/internal/store/store_test.go#TestAppendEvent_ReadAfterWriteProjection:8ca76df8 -->
- `TestEventsUniqueStreamVersion_ConcurrentConflict`
- `TestAppendEvent_AutoVersionsConcurrentFacts`
- `TestAppendEvent_UnregisteredTypeWritesNothing`
- `TestAppendEvent_ProjectorFailureRollsBack`
- `TestAppendEvent_ReadAfterWriteProjection`
<!-- docref: end -->

## Review regressions

<!-- docref: begin src=server/internal/store/store_test.go#TestAppendEvent_ProjectorTransactionIsCapabilityLimited:9192d5b9,server/internal/store/store_test.go#TestAppendEvent_LowercaseULIDPersistsCanonicalID:d2d45985,server/internal/store/store_test.go#TestIsStreamVersionConflict_ExactPostgresError:8b19850d,server/internal/store/store_test.go#TestWaitAppendRetry_CancelledContext:dc1fba4d -->
- `TestAppendEvent_ProjectorTransactionIsCapabilityLimited`
- `TestAppendEvent_LowercaseULIDPersistsCanonicalID`
- `TestIsStreamVersionConflict_ExactPostgresError`
- `TestWaitAppendRetry_CancelledContext`
<!-- docref: end -->
