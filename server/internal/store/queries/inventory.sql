-- name: UpsertInventorySnapshot :execrows
INSERT INTO inventory_snapshots (
    agent_id,
    projection_version,
    payload_version,
    snapshot,
    deleted,
    updated_at
) VALUES ($1, $2, $3, $4, false, $5)
ON CONFLICT (agent_id) DO UPDATE SET
    projection_version = EXCLUDED.projection_version,
    payload_version = EXCLUDED.payload_version,
    snapshot = EXCLUDED.snapshot,
    deleted = false,
    updated_at = EXCLUDED.updated_at
WHERE inventory_snapshots.projection_version < EXCLUDED.projection_version;

-- name: UpsertInventoryTombstone :execrows
INSERT INTO inventory_snapshots (
    agent_id,
    projection_version,
    payload_version,
    snapshot,
    deleted,
    updated_at
) VALUES ($1, $2, $3, NULL, true, $4)
ON CONFLICT (agent_id) DO UPDATE SET
    projection_version = EXCLUDED.projection_version,
    payload_version = EXCLUDED.payload_version,
    snapshot = NULL,
    deleted = true,
    updated_at = EXCLUDED.updated_at
WHERE inventory_snapshots.projection_version < EXCLUDED.projection_version;

-- name: ResetInventorySnapshots :exec
DELETE FROM inventory_snapshots;
