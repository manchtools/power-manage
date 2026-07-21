# SPEC-005 M3 — Replay and rebuild

Spec milestone: SPEC-005 M3 (`ES-2`, `ES-3`, `ES-7`; AC-6, AC-7).

## Delta

<!-- docref: begin src=server/internal/store/store.go#RebuildTarget:1cd7119a,server/internal/store/store.go#New:ff592594,server/internal/store/rebuild.go#RebuildAll:02b0c7a2,server/internal/store/generated/events.sql.go#ListEventsForReplayPage:b8ed1a35,server/internal/store/generated/events.sql.go#RebuildTableClosure:afc91dce -->
- `server/internal/store/store.go`
  - require exact projector/rebuild-target parity at construction;
  - keep defensive copies of target metadata and reject duplicate ownership.
- `server/internal/store/rebuild.go`
  - compute the live FK-dependent closure before destructive work;
  - reset and replay one target through the existing projectors in one
    repeatable-read transaction, preserving a stable event snapshot without
    blocking concurrent appends.
- `server/internal/store/queries/events.sql`, generated sqlc output
  - load target events in bounded keyset pages and deterministic per-stream
    order;
  - discover the recursive public-schema FK closure.
<!-- docref: end -->
<!-- docref: begin src=server/internal/store/rebuild_test.go#TestRebuildAll_ReproducesProjection:306c31cd,server/internal/store/rebuild_test.go#TestRebuildAll_FKDependentRefused:4d3c1de6,server/internal/store/rebuild_test.go#TestNew_ProjectorWithoutRebuildTargetRejected:a8ef1ddc,server/internal/store/rebuild_test.go#TestNew_RebuildTargetWithoutProjectorRejected:b97881e6,server/internal/store/rebuild_test.go#TestRebuildAll_DoesNotBlockConcurrentAppend:7617577f,server/internal/store/rebuild_test.go#TestRebuildAll_ProjectorFailureRollsBackReset:8b979194,server/internal/store/rebuild_test.go#TestNew_RebuildTargetsDefensivelyCopied:fb566021,server/internal/store/rebuild_test.go#TestNew_DuplicateRebuildOwnershipRejected:1a737181,server/internal/store/rebuild_test.go#TestAppendEvent_StreamOutsideRebuildTargetWritesNothing:2d71ab4c -->
- `server/internal/store/rebuild_test.go`, `store_test.go`
  - `TestRebuildAll_ReproducesProjection`
  - `TestRebuildAll_FKDependentRefused`
  - `TestRebuildAll_DoesNotBlockConcurrentAppend`
  - `TestRebuildAll_ProjectorFailureRollsBackReset`
  - `TestNew_ProjectorWithoutRebuildTargetRejected`
  - `TestNew_RebuildTargetWithoutProjectorRejected`
  - `TestNew_RebuildTargetsDefensivelyCopied`
  - `TestNew_DuplicateRebuildOwnershipRejected`
  - `TestAppendEvent_StreamOutsideRebuildTargetWritesNothing`
<!-- docref: end -->

## Mechanical activation floors

- AC-11 activates with M5's first production projection and its
  `projection_version` update guard; no test-only production projector is
  added.
- The recovery CLI subcommand is wired in M5 with that same first production
  target; an empty command that can rebuild nothing is not added here.
