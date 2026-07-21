-- name: ListPublicTables :many
SELECT class.relname::text AS table_name
FROM pg_catalog.pg_class AS class
JOIN pg_catalog.pg_namespace AS namespace
  ON namespace.oid = class.relnamespace
WHERE namespace.nspname = 'public'
  AND class.relkind IN ('r', 'p')
ORDER BY class.relname;
