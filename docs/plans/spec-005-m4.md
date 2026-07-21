# SPEC-005 M4 — Durable work queue

Spec milestone: SPEC-005 M4 (`ES-8`, `ES-11`; AC-12).

## Delta

<!-- docref: begin src=server/internal/store/migrations/002_work_items.sql#@work-items-schema:6a33ec91,server/internal/store/work.go#Work:767d2715,server/internal/store/work.go#WorkItem:8dbceaa3,server/internal/store/work.go#WorkHandler:99c9430b,server/internal/store/work.go#WorkQueue:ac7c52fa,server/internal/store/work.go#NewWorkQueue:8970ac37,server/internal/store/work.go#EnqueueWork:3ac86be8,server/internal/store/work.go#RunOnce:6ea88905,server/internal/store/work.go#Stats:93b813bc,server/internal/store/generated/work.sql.go#InsertWork:b2e4673e,server/internal/store/generated/work.sql.go#TryWorkQueueLock:7eea1459,server/internal/store/generated/work.sql.go#ClaimDueWork:e8003631,server/internal/store/generated/work.sql.go#CompleteWork:5363b262,server/internal/store/generated/work.sql.go#RecordWorkFailure:ec6ac14d,server/internal/store/generated/work.sql.go#WorkStats:0b6f96ed -->
- `server/internal/store/migrations/002_work_items.sql`
  - add the bounded Postgres work table with source-event identity, due/retry
    scheduling, kind/payload size limits, attempt limits, and retained exhausted
    rows.
- `server/internal/store/work.go`
  - let in-transaction projectors enqueue work tied to the motivating event;
  - drain due work under a transaction-scoped advisory lock and
    `FOR UPDATE SKIP LOCKED`;
  - run handlers with `context.WithoutCancel`, a timeout, and panic recovery;
  - delete successes, persist bounded failure details and exponential retry
    timing, and expose queue-depth/exhaustion health.
- `server/internal/store/queries/work.sql`, generated sqlc output
  - insert, claim, complete, retry, and inspect work using static SQL only.
<!-- docref: end -->
<!-- docref: begin src=server/internal/store/work_test.go#TestNewWorkQueue_InvalidRegistryRejected:6b9be212,server/internal/store/work_test.go#TestNewWorkQueue_HandlerRegistryDefensivelyCopied:4750389a,server/internal/store/work_test.go#TestAppendEvent_InvalidWorkWritesNothing:4575fc51,server/internal/store/work_test.go#TestWorkItems_SizeConstraints:1bba413e,server/internal/store/work_test.go#TestAppendEvent_EnqueuesWorkAtomically:8de601a5,server/internal/store/work_test.go#TestAppendEvent_EnqueueThenProjectorFailureRollsBack:7c1aba2f,server/internal/store/work_test.go#TestWorkQueue_ConcurrentWorkersProcessOnce:2dfe8028,server/internal/store/work_test.go#TestWorkQueue_AdvisoryLockSerializesQueue:934bd380,server/internal/store/work_test.go#TestWorkQueue_SkipLockedProcessesAnotherRow:f4964c0f,server/internal/store/work_test.go#TestWorkQueue_HonorsRunAtAndRetryBackoff:3b4953b7,server/internal/store/work_test.go#TestWorkQueue_PostEffectFailureRedeliversStableSource:79207d4c,server/internal/store/work_test.go#TestWorkQueue_ExhaustedRemainsVisible:317dd96f,server/internal/store/work_test.go#TestWorkQueue_HandlerPanicRecovered:ac9036cd,server/internal/store/work_test.go#TestWorkQueue_HandlerTimeoutRecorded:47ebb840,server/internal/store/work_test.go#TestWorkQueue_HandlerFinishesAfterCallerCancellation:0dbcf199,server/internal/store/work_test.go#TestRebuildAll_DoesNotReenqueueWork:3d306f06 -->
- `server/internal/store/work_test.go`
  - `TestNewWorkQueue_InvalidRegistryRejected`
  - `TestNewWorkQueue_HandlerRegistryDefensivelyCopied`
  - `TestAppendEvent_InvalidWorkWritesNothing`
  - `TestWorkItems_SizeConstraints`
  - `TestAppendEvent_EnqueuesWorkAtomically`
  - `TestAppendEvent_EnqueueThenProjectorFailureRollsBack`
  - `TestWorkQueue_ConcurrentWorkersProcessOnce`
  - `TestWorkQueue_AdvisoryLockSerializesQueue`
  - `TestWorkQueue_SkipLockedProcessesAnotherRow`
  - `TestWorkQueue_HonorsRunAtAndRetryBackoff`
  - `TestWorkQueue_PostEffectFailureRedeliversStableSource`
  - `TestWorkQueue_ExhaustedRemainsVisible`
  - `TestWorkQueue_HandlerPanicRecovered`
  - `TestWorkQueue_HandlerTimeoutRecorded`
  - `TestWorkQueue_HandlerFinishesAfterCallerCancellation`
  - `TestRebuildAll_DoesNotReenqueueWork`
<!-- docref: end -->

## Activation floor

The work-health SQL is the doctor-facing seam. Registration in the doctor
check catalog activates with the SPEC-016 doctor framework; M4 does not add a
second placeholder check runner.
