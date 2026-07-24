-- name: InsertManagedAction :execrows
INSERT INTO managed_actions (
    action_id, name, params, projection_version, updated_at
) VALUES (
    sqlc.arg(action_id), sqlc.arg(name), sqlc.arg(params),
    sqlc.arg(projection_version), sqlc.arg(updated_at)
)
ON CONFLICT (action_id) DO NOTHING;

-- name: ReplaceManagedAction :execrows
UPDATE managed_actions
SET name = sqlc.arg(name),
    params = sqlc.arg(params),
    projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE action_id = sqlc.arg(action_id)
  AND NOT system_managed
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: DeleteManagedAction :execrows
DELETE FROM managed_actions
WHERE action_id = sqlc.arg(action_id)
  AND NOT system_managed
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: GetScopedManagedAction :one
SELECT action_id, name, params, projection_version
FROM managed_actions
WHERE action_id = sqlc.arg(action_id)
  AND NOT system_managed
  AND (
    sqlc.arg(global_scope)::boolean
    OR EXISTS (
      SELECT 1
      FROM assignments
      WHERE assignments.source_kind = 'action'
        AND assignments.source_id = managed_actions.action_id
        AND (
          assignments.target_kind = 'device_group'
            AND assignments.target_id = ANY(sqlc.arg(device_group_ids)::text[])
          OR assignments.target_kind = 'user_group'
            AND assignments.target_id = ANY(sqlc.arg(user_group_ids)::text[])
          OR assignments.target_kind = 'user'
            AND (
              assignments.target_id = sqlc.arg(self_id)
              OR EXISTS (
                SELECT 1 FROM managed_user_group_members
                WHERE managed_user_group_members.user_id = assignments.target_id
                  AND managed_user_group_members.group_id =
                      ANY(sqlc.arg(user_group_ids)::text[])
              )
            )
          OR assignments.target_kind = 'device'
            AND EXISTS (
              SELECT 1 FROM device_groups
              WHERE device_groups.device_group_id = ANY(sqlc.arg(device_group_ids)::text[])
                AND assignments.target_id = ANY(device_groups.static_device_ids)
            )
        )
    )
  );

-- name: ListScopedManagedActions :many
SELECT action_id, name, params, projection_version
FROM managed_actions
WHERE NOT system_managed
  AND (
    sqlc.arg(global_scope)::boolean
    OR EXISTS (
      SELECT 1
      FROM assignments
      WHERE assignments.source_kind = 'action'
        AND assignments.source_id = managed_actions.action_id
        AND (
          assignments.target_kind = 'device_group'
            AND assignments.target_id = ANY(sqlc.arg(device_group_ids)::text[])
          OR assignments.target_kind = 'user_group'
            AND assignments.target_id = ANY(sqlc.arg(user_group_ids)::text[])
          OR assignments.target_kind = 'user'
            AND (
              assignments.target_id = sqlc.arg(self_id)
              OR EXISTS (
                SELECT 1 FROM managed_user_group_members
                WHERE managed_user_group_members.user_id = assignments.target_id
                  AND managed_user_group_members.group_id =
                      ANY(sqlc.arg(user_group_ids)::text[])
              )
            )
          OR assignments.target_kind = 'device'
            AND EXISTS (
              SELECT 1 FROM device_groups
              WHERE device_groups.device_group_id = ANY(sqlc.arg(device_group_ids)::text[])
                AND assignments.target_id = ANY(device_groups.static_device_ids)
            )
        )
    )
  )
ORDER BY action_id
LIMIT sqlc.arg(page_limit);

-- name: ResetManagedActions :exec
DELETE FROM managed_actions
WHERE NOT system_managed;

-- name: InsertManagedActionSet :execrows
INSERT INTO managed_action_sets (
    action_set_id, name, projection_version, updated_at
) VALUES (
    sqlc.arg(action_set_id), sqlc.arg(name),
    sqlc.arg(projection_version), sqlc.arg(updated_at)
)
ON CONFLICT (action_set_id) DO NOTHING;

-- name: ReplaceManagedActionSet :execrows
UPDATE managed_action_sets
SET name = sqlc.arg(name),
    projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE action_set_id = sqlc.arg(action_set_id)
  AND NOT system_managed
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: DeleteManagedActionSet :execrows
DELETE FROM managed_action_sets
WHERE action_set_id = sqlc.arg(action_set_id)
  AND NOT system_managed
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: GetScopedManagedActionSet :one
SELECT action_set_id, name, projection_version
FROM managed_action_sets
WHERE action_set_id = sqlc.arg(action_set_id)
  AND NOT system_managed
  AND (
    sqlc.arg(global_scope)::boolean
    OR EXISTS (
      SELECT 1
      FROM assignments
      WHERE assignments.source_kind = 'action_set'
        AND assignments.source_id = managed_action_sets.action_set_id
        AND (
          assignments.target_kind = 'device_group'
            AND assignments.target_id = ANY(sqlc.arg(device_group_ids)::text[])
          OR assignments.target_kind = 'user_group'
            AND assignments.target_id = ANY(sqlc.arg(user_group_ids)::text[])
          OR assignments.target_kind = 'user'
            AND (
              assignments.target_id = sqlc.arg(self_id)
              OR EXISTS (
                SELECT 1 FROM managed_user_group_members
                WHERE managed_user_group_members.user_id = assignments.target_id
                  AND managed_user_group_members.group_id =
                      ANY(sqlc.arg(user_group_ids)::text[])
              )
            )
          OR assignments.target_kind = 'device'
            AND EXISTS (
              SELECT 1 FROM device_groups
              WHERE device_groups.device_group_id =
                    ANY(sqlc.arg(device_group_ids)::text[])
                AND assignments.target_id = ANY(device_groups.static_device_ids)
            )
        )
    )
  );

-- name: ListScopedManagedActionSets :many
SELECT action_set_id, name, projection_version
FROM managed_action_sets
WHERE NOT system_managed
  AND (
    sqlc.arg(global_scope)::boolean
    OR EXISTS (
      SELECT 1
      FROM assignments
      WHERE assignments.source_kind = 'action_set'
        AND assignments.source_id = managed_action_sets.action_set_id
        AND (
          assignments.target_kind = 'device_group'
            AND assignments.target_id = ANY(sqlc.arg(device_group_ids)::text[])
          OR assignments.target_kind = 'user_group'
            AND assignments.target_id = ANY(sqlc.arg(user_group_ids)::text[])
          OR assignments.target_kind = 'user'
            AND (
              assignments.target_id = sqlc.arg(self_id)
              OR EXISTS (
                SELECT 1 FROM managed_user_group_members
                WHERE managed_user_group_members.user_id = assignments.target_id
                  AND managed_user_group_members.group_id =
                      ANY(sqlc.arg(user_group_ids)::text[])
              )
            )
          OR assignments.target_kind = 'device'
            AND EXISTS (
              SELECT 1 FROM device_groups
              WHERE device_groups.device_group_id =
                    ANY(sqlc.arg(device_group_ids)::text[])
                AND assignments.target_id = ANY(device_groups.static_device_ids)
            )
        )
    )
  )
ORDER BY action_set_id
LIMIT sqlc.arg(page_limit);

-- name: ResetManagedActionSets :exec
DELETE FROM managed_action_sets
WHERE NOT system_managed;

-- name: InsertAssignment :execrows
INSERT INTO assignments (
    assignment_id, source_kind, source_id, target_kind, target_id, mode,
    projection_version, updated_at
) VALUES (
    sqlc.arg(assignment_id), sqlc.arg(source_kind), sqlc.arg(source_id),
    sqlc.arg(target_kind), sqlc.arg(target_id), sqlc.arg(mode),
    sqlc.arg(projection_version), sqlc.arg(updated_at)
)
ON CONFLICT (assignment_id) DO NOTHING;

-- name: DeleteAssignment :execrows
DELETE FROM assignments
WHERE assignment_id = sqlc.arg(assignment_id)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: GetScopedAssignment :one
SELECT assignment_id, source_kind, source_id, target_kind, target_id, mode,
       projection_version
FROM assignments
WHERE assignment_id = sqlc.arg(assignment_id)
  AND (
    sqlc.arg(global_scope)::boolean
    OR target_kind = 'device_group'
      AND target_id = ANY(sqlc.arg(device_group_ids)::text[])
    OR target_kind = 'user_group'
      AND target_id = ANY(sqlc.arg(user_group_ids)::text[])
    OR target_kind = 'user'
      AND target_id = sqlc.arg(self_id)
  );

-- name: ListScopedAssignments :many
SELECT assignment_id, source_kind, source_id, target_kind, target_id, mode,
       projection_version
FROM assignments
WHERE sqlc.arg(global_scope)::boolean
   OR target_kind = 'device_group'
     AND target_id = ANY(sqlc.arg(device_group_ids)::text[])
   OR target_kind = 'user_group'
     AND target_id = ANY(sqlc.arg(user_group_ids)::text[])
   OR target_kind = 'user'
     AND target_id = sqlc.arg(self_id)
ORDER BY assignment_id
LIMIT sqlc.arg(page_limit);

-- name: ResetAssignments :exec
DELETE FROM assignments;

-- name: InsertCompliancePolicy :execrows
INSERT INTO compliance_policies (
    policy_id, name, rule_action_ids, grace_hours, projection_version, updated_at
) VALUES (
    sqlc.arg(policy_id), sqlc.arg(name), sqlc.arg(rule_action_ids),
    sqlc.arg(grace_hours), sqlc.arg(projection_version), sqlc.arg(updated_at)
)
ON CONFLICT (policy_id) DO NOTHING;

-- name: ReplaceCompliancePolicy :execrows
UPDATE compliance_policies
SET name = sqlc.arg(name),
    rule_action_ids = sqlc.arg(rule_action_ids),
    grace_hours = sqlc.arg(grace_hours),
    projection_version = sqlc.arg(projection_version),
    updated_at = sqlc.arg(updated_at)
WHERE policy_id = sqlc.arg(policy_id)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: DeleteCompliancePolicy :execrows
DELETE FROM compliance_policies
WHERE policy_id = sqlc.arg(policy_id)
  AND projection_version = sqlc.arg(previous_projection_version);

-- name: GetCompliancePolicy :one
SELECT policy_id, name, rule_action_ids, grace_hours, projection_version
FROM compliance_policies
WHERE policy_id = sqlc.arg(policy_id)
  AND sqlc.arg(global_scope)::boolean;

-- name: ListCompliancePolicies :many
SELECT policy_id, name, rule_action_ids, grace_hours, projection_version
FROM compliance_policies
WHERE sqlc.arg(global_scope)::boolean
ORDER BY policy_id
LIMIT sqlc.arg(page_limit);

-- name: ResetCompliancePolicies :exec
DELETE FROM compliance_policies;
