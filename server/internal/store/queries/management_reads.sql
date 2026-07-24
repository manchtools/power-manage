-- name: ListScopedAuditEvents :many
SELECT stream_type, stream_id, stream_version, event_type, payload_version,
       created_at, global_position
FROM events AS e
WHERE sqlc.arg(global_scope)::boolean
   OR e.stream_id = sqlc.arg(self_id)
   OR e.stream_id = ANY(sqlc.arg(device_group_ids)::text[])
   OR e.stream_id = ANY(sqlc.arg(user_group_ids)::text[])
   OR (
       e.stream_type IN ('agent', 'device', 'inventory')
       AND EXISTS (
           SELECT 1
           FROM device_groups AS g
           WHERE g.device_group_id = ANY(sqlc.arg(device_group_ids)::text[])
             AND e.stream_id = ANY(g.static_device_ids)
       )
   )
   OR (
       e.stream_type = 'user'
       AND EXISTS (
           SELECT 1
           FROM managed_user_group_members AS m
           WHERE m.group_id = ANY(sqlc.arg(user_group_ids)::text[])
             AND m.user_id = e.stream_id
       )
   )
ORDER BY e.global_position DESC
LIMIT sqlc.arg(page_limit);

-- name: GetScopedExecution :one
SELECT execution_id, device_id, output_bytes, output_chunks, truncated, updated_at
FROM execution_outputs AS x
WHERE x.execution_id = sqlc.arg(execution_id)
  AND (
      sqlc.arg(global_scope)::boolean
      OR EXISTS (
          SELECT 1
          FROM device_groups AS g
          WHERE g.device_group_id = ANY(sqlc.arg(device_group_ids)::text[])
            AND x.device_id = ANY(g.static_device_ids)
      )
  );

-- name: ListScopedExecutions :many
SELECT execution_id, device_id, output_bytes, output_chunks, truncated, updated_at
FROM execution_outputs AS x
WHERE sqlc.arg(global_scope)::boolean
   OR EXISTS (
       SELECT 1
       FROM device_groups AS g
       WHERE g.device_group_id = ANY(sqlc.arg(device_group_ids)::text[])
         AND x.device_id = ANY(g.static_device_ids)
   )
ORDER BY x.execution_id
LIMIT sqlc.arg(page_limit);

-- name: GetScopedInventorySnapshot :one
SELECT i.agent_id, i.projection_version, i.payload_version, i.snapshot,
       i.updated_at
FROM inventory_snapshots AS i
WHERE i.agent_id = sqlc.arg(agent_id)
  AND NOT i.deleted
  AND (
      sqlc.arg(global_scope)::boolean
      OR EXISTS (
          SELECT 1
          FROM device_groups AS g
          WHERE g.device_group_id = ANY(sqlc.arg(device_group_ids)::text[])
            AND i.agent_id = ANY(g.static_device_ids)
      )
  );

-- name: ListScopedInventorySnapshots :many
SELECT i.agent_id, i.projection_version, i.payload_version, i.snapshot,
       i.updated_at
FROM inventory_snapshots AS i
WHERE NOT i.deleted
  AND (
      sqlc.arg(global_scope)::boolean
      OR EXISTS (
          SELECT 1
          FROM device_groups AS g
          WHERE g.device_group_id = ANY(sqlc.arg(device_group_ids)::text[])
            AND i.agent_id = ANY(g.static_device_ids)
      )
  )
ORDER BY i.agent_id
LIMIT sqlc.arg(page_limit);

-- name: GetGlobalGateway :one
SELECT gateway_id, projection_version, certificate_fingerprint,
       registration_token_id, owner, dns_names, lifecycle_state, updated_at
FROM gateways
WHERE gateway_id = sqlc.arg(gateway_id)
  AND sqlc.arg(global_scope)::boolean;

-- name: ListGlobalGateways :many
SELECT gateway_id, projection_version, certificate_fingerprint,
       registration_token_id, owner, dns_names, lifecycle_state, updated_at
FROM gateways
WHERE sqlc.arg(global_scope)::boolean
ORDER BY gateway_id
LIMIT sqlc.arg(page_limit);
