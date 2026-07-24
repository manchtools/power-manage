# SPEC-005 M5 — Guards and storage tiers

Spec milestone: SPEC-005 M5. Requirements: (ES-1, SPEC-005), (ES-2,
SPEC-005), (ES-6, SPEC-005), (ES-9, SPEC-005), (ES-10, SPEC-005), and
(ES-12, SPEC-005). Acceptance: (AC-5, SPEC-005), (AC-11, SPEC-005),
(AC-13, SPEC-005), (AC-14, SPEC-005), and (AC-15, SPEC-005).

## Delta

<!-- docref: begin src=server/internal/store/migrations/003_inventory.sql#@inventory-snapshots-schema:ba8dd66a,server/internal/store/inventory.go#NewProduction:90e147fc,server/internal/store/inventory.go#InventorySnapshotEvent:53edfa8e,server/internal/store/inventory.go#InventoryTombstoneEvent:c28922aa,server/internal/store/inventory.go#projectInventorySnapshot:4434cec2,server/internal/store/inventory.go#projectInventoryTombstone:1f93361d,server/internal/store/inventory.go#validateGoldenEventCorpus:ddb6c04f,server/internal/store/inventory.go#validateEventPayloadTypes:cb8577dd -->
- Add the first production event registry: versioned inventory snapshot and
  tombstone events, deterministic payload codecs, an exact golden corpus, and
  an inventory projection whose `projection_version` rejects older writes and
  deletes. Canonicalize case-insensitive agent IDs before event construction.
<!-- docref: end -->
<!-- docref: begin src=server/internal/store/migrations/004_execution_outputs.sql#@execution-output-schema:2f07a118,server/internal/store/telemetry.go#NewTelemetryStore:7bf5e1f7,server/internal/store/telemetry.go#AppendExecutionOutput:3bee2ddc,server/internal/store/telemetry.go#ReadExecutionOutput:2aa76b16 -->
- Add bounded operational execution-output storage. Enforce byte, chunk-count,
  and per-chunk caps at the transaction that accepts output, retain an explicit
  truncation marker, canonicalize execution IDs before SQL, and make reads
  LIMIT-bounded. No output or terminal recording body is an event payload.
<!-- docref: end -->
<!-- docref: begin src=server/internal/store/classification.go#ProductionTableClassification:0cb9e1c9,server/internal/store/classification.go#CheckTableClassification:3bdafdf2,server/internal/store/errors.go#IsNotFound:61b76e14,server/guards_test.go#TestGuard_ProjectionWritesOnlyFromProjectors:de1f1ac2,server/guards_test.go#TestGuard_SentinelComparisons:d68d6fc2,server/guards_test.go#TestGuard_WorkerDiscipline:a3ef06d2,server/guards_test.go#TestGuard_StaticSQLInventory:0c08b072,sdk/guardtest/astban.go#SentinelComparisons:e1ee2b76,sdk/guardtest/astban.go#defaultImportName:376a2bcf -->
- Add a live-schema classification guard with exact, matches-zero-protected
  coverage of events, projections, work, operational telemetry, migration
  bookkeeping, artifact tables, and the named encryption-key exception.
- Add self-discovering static guards for projection writes, raw not-found
  sentinel comparisons, singleton-worker discipline, and the static sqlc query
  inventory. Generated projection mutations may only be called by their
  projector or rebuild reset; dynamic projection SQL is rejected, and workers
  must retain their Postgres advisory lock, detached timeout, and panic boundary.
<!-- docref: end -->
<!-- docref: begin src=server/cmd/power-manage-recovery/main.go#run:f60ffb8b,server/cmd/power-manage-recovery/main.go#readDSNFile:b456558d,server/cmd/power-manage-recovery/main.go#rebuildProduction:2031bd12 -->
- Add a CLI-only recovery command that constructs the production registry and
  rebuilds the inventory target. Database credentials enter through a bounded
  file, not command-line arguments.
<!-- docref: end -->

## Acceptance tests

<!-- docref: begin src=server/internal/store/classification_test.go#TestGuard_TableClassification:913db585,server/internal/store/classification_test.go#TestTableClassificationGuard_RejectsUnclassifiedTable:b95ab688,server/internal/store/classification_test.go#TestTableClassificationGuard_MatchesZero:2b991383,server/internal/store/classification_test.go#TestTableClassificationGuard_RejectsDuplicateClass:110d44a2,server/guards_test.go#TestGuard_ProjectionWritesOnlyFromProjectors:de1f1ac2,server/guards_test.go#TestProjectionWriteGuard_FixtureDetected:e8996f95,server/guards_test.go#TestGuard_SentinelComparisons:d68d6fc2,server/guards_test.go#TestSentinelComparisonGuard_FixtureDetected:85c0dbe1,server/guards_test.go#TestGuard_WorkerDiscipline:a3ef06d2,server/guards_test.go#TestWorkerDisciplineGuard_FixtureDetected:df16cd71,server/guards_test.go#TestGuard_StaticSQLInventory:0c08b072,server/guards_test.go#TestStaticSQLGuard_FixtureDetected:9387b025,server/internal/store/errors_test.go#TestIsNotFound_RecognizesDriverSentinels:6857bdde,server/internal/store/inventory_test.go#TestGuard_GoldenEventCorpus:599bf3a4,server/internal/store/inventory_test.go#TestGoldenEventCorpusGuard_RejectsMissingEntry:8b5c15f0,server/internal/store/inventory_test.go#TestGoldenEventCorpusGuard_RejectsChangedSerialization:90c30f7b,server/internal/store/inventory_test.go#TestGuard_EventPayloadBodiesExcluded:a3829974,server/internal/store/inventory_test.go#TestEventPayloadBodyGuard_RejectsNestedContainers:17a5757c,server/internal/store/inventory_test.go#TestInventorySnapshot_ReplacesAndRebuildsLatestState:afea5102,server/internal/store/inventory_test.go#TestInventorySnapshot_OlderSnapshotLeavesNewerProjectionUntouched:32c52f40,server/internal/store/inventory_test.go#TestInventorySnapshot_OlderTombstoneLeavesNewerProjectionUntouched:1d681b88,server/internal/store/inventory_test.go#TestInventoryEvents_CanonicalizeAgentID:2b832de9,server/internal/store/telemetry_test.go#TestExecutionOutput_OversizedChunkMarksTruncated:00ac9df2,server/internal/store/telemetry_test.go#TestExecutionOutput_ByteCapMarksTruncated:b0eef2b5,server/internal/store/telemetry_test.go#TestExecutionOutput_ChunkCapMarksTruncated:1b59c993,server/internal/store/telemetry_test.go#TestExecutionOutput_ConcurrentWritersRespectCaps:0ad33ef9,server/internal/store/telemetry_test.go#TestExecutionOutput_LowercaseIDCanonicalized:6eff8385,server/internal/store/telemetry_test.go#TestExecutionOutput_ReadIsLimitBounded:cc56e6ed,server/internal/store/telemetry_test.go#TestExecutionOutput_SchemaRejectsOversizedChunk:5584fb07,server/cmd/power-manage-recovery/main_test.go#TestRecoveryCLI_RebuildsRegisteredInventoryTarget:62ea9552,server/cmd/power-manage-recovery/main_test.go#TestRecoveryCLI_RejectsUnsupportedTarget:e4ce994a,server/cmd/power-manage-recovery/main_test.go#TestRecoveryCLI_DSNFileIsBounded:2b45cd23,server/cmd/power-manage-recovery/main_test.go#TestRecoveryCLI_RejectsInsecureDSNFilePermissions:b5125120,server/cmd/power-manage-recovery/main_test.go#TestConfigDocs:fc201a82,sdk/guardtest/astban_test.go#TestSentinelComparisons_VersionedImportPathFixture:491ca1ec,sdk/guardtest/astban_test.go#TestSentinelComparisons_VersionLikePackageNames:413045ac -->
- `TestGuard_TableClassification`
- `TestTableClassificationGuard_RejectsUnclassifiedTable`
- `TestTableClassificationGuard_MatchesZero`
- `TestTableClassificationGuard_RejectsDuplicateClass`
- `TestGuard_ProjectionWritesOnlyFromProjectors`
- `TestProjectionWriteGuard_FixtureDetected`
- `TestGuard_SentinelComparisons`
- `TestSentinelComparisonGuard_FixtureDetected`
- `TestGuard_WorkerDiscipline`
- `TestWorkerDisciplineGuard_FixtureDetected`
- `TestGuard_StaticSQLInventory`
- `TestStaticSQLGuard_FixtureDetected`
- `TestIsNotFound_RecognizesDriverSentinels`
- `TestGuard_GoldenEventCorpus`
- `TestGoldenEventCorpusGuard_RejectsMissingEntry`
- `TestGoldenEventCorpusGuard_RejectsChangedSerialization`
- `TestGuard_EventPayloadBodiesExcluded`
- `TestEventPayloadBodyGuard_RejectsNestedContainers`
- `TestInventorySnapshot_ReplacesAndRebuildsLatestState`
- `TestInventorySnapshot_OlderSnapshotLeavesNewerProjectionUntouched`
- `TestInventorySnapshot_OlderTombstoneLeavesNewerProjectionUntouched`
- `TestInventoryEvents_CanonicalizeAgentID`
- `TestExecutionOutput_OversizedChunkMarksTruncated`
- `TestExecutionOutput_ByteCapMarksTruncated`
- `TestExecutionOutput_ChunkCapMarksTruncated`
- `TestExecutionOutput_ConcurrentWritersRespectCaps`
- `TestExecutionOutput_LowercaseIDCanonicalized`
- `TestExecutionOutput_ReadIsLimitBounded`
- `TestExecutionOutput_SchemaRejectsOversizedChunk`
- `TestRecoveryCLI_RebuildsRegisteredInventoryTarget`
- `TestRecoveryCLI_RejectsUnsupportedTarget`
- `TestRecoveryCLI_DSNFileIsBounded`
- `TestRecoveryCLI_RejectsInsecureDSNFilePermissions`
- `TestConfigDocs`
- `TestSentinelComparisons_VersionedImportPathFixture`
- `TestSentinelComparisons_VersionLikePackageNames`
<!-- docref: end -->

Every behavioral storage test uses real Postgres. Each guard has a planted
fixture or explicit matches-zero case so a scanner that discovers nothing
cannot pass.

## Scope boundary

- Terminal-recording bodies remain an artifact-store responsibility
  (ART-4, SPEC-010); M5 enforces their exclusion from event payloads but does
  not implement the artifact store.
- Doctor check registration remains owned by (OPS-1, SPEC-016). The M4 work
  statistics seam stays available for that catalog.
- Execution lifecycle RPCs activate with the CRUD kernel and gateway specs;
  M5 implements only the bounded operational storage boundary they consume.
