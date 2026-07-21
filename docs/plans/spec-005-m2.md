# SPEC-005 M2 — Append discipline

Spec milestone: SPEC-005 M2 (`ES-4`, `ES-5`; AC-8..10).

## Delta

<!-- docref: begin src=server/internal/store/store.go#AppendEventWithVersion:26fb7916,server/internal/store/store.go#AppendEvents:a1222293,server/internal/store/store.go#IsVersionConflict:4310f6f0 -->
- `server/internal/store/store.go`
  - add `AppendEventWithVersion` with one expected-version insert attempt and a
    recognizable version-conflict error;
  - add `AppendEvents` with one attempt and one transaction for the full
    ordered batch; exact stream conflicts surface without retry;
  - share validation, projector lookup, persistence, and rollback mechanics
    across all three append APIs.
<!-- docref: end -->
<!-- docref: begin src=server/internal/store/store_test.go#TestAppendEventWithVersion_ConcurrentConsume:471ff391,server/internal/store/store_test.go#TestAppendEventWithVersion_ConflictDoesNotRetry:b1f960c7,server/internal/store/store_test.go#TestAppendEventWithVersion_FutureExpectedVersionConflicts:dddb6a9b,server/internal/store/store_test.go#TestAppendEventWithVersion_NegativeExpectedVersionRejected:9c007724,server/internal/store/store_test.go#TestAppendEvents_ProjectorFailureRollsBackBatch:4952b89b,server/internal/store/store_test.go#TestAppendEvents_ConflictOnSecondInsertDoesNotRetry:a300f533,server/internal/store/store_test.go#TestAppendEvents_SameStreamUsesConsecutiveVersions:3b1103fa -->
- `server/internal/store/store_test.go`
  - `TestAppendEventWithVersion_ConcurrentConsume`
  - `TestAppendEventWithVersion_ConflictDoesNotRetry`
  - `TestAppendEventWithVersion_FutureExpectedVersionConflicts`
  - `TestAppendEventWithVersion_NegativeExpectedVersionRejected`
  - `TestAppendEvents_ProjectorFailureRollsBackBatch`
  - `TestAppendEvents_ConflictOnSecondInsertDoesNotRetry`
  - `TestAppendEvents_SameStreamUsesConsecutiveVersions`
<!-- docref: end -->

## Mechanical activation floor

No state-changing server RPC is implemented yet, so AC-10 has no real handler
subject in this milestone. Its behavioral test activates with the first such
handler; no placeholder endpoint or test-only production handler is added.
