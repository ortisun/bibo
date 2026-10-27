-- One SHA-256 over every definition the migrations create in the public schema.
-- Two databases with the same fingerprint have the same tables, columns, constraints, indexes,
-- triggers, functions, views and grants. The migrations suite compares the fingerprint after
-- a first run, after revert then run, and after redo.
WITH defs AS (
  SELECT 'column ' || c.table_name || '.' || c.column_name || ' ' || c.data_type || ' ' || c.is_nullable || ' ' ||
         coalesce(c.column_default, '') || ' ' || coalesce(c.identity_generation, '') AS d
    FROM information_schema.columns c
   WHERE c.table_schema = 'public' AND c.table_name <> '__diesel_schema_migrations'
  UNION ALL
  SELECT 'constraint ' || cl.relname || ' ' || co.conname || ' ' || pg_get_constraintdef(co.oid)
    FROM pg_constraint co JOIN pg_class cl ON cl.oid = co.conrelid
   WHERE cl.relnamespace = 'public'::regnamespace AND cl.relname <> '__diesel_schema_migrations'
  UNION ALL
  SELECT 'index ' || indexdef FROM pg_indexes
   WHERE schemaname = 'public' AND tablename <> '__diesel_schema_migrations'
  UNION ALL
  SELECT 'trigger ' || pg_get_triggerdef(t.oid) FROM pg_trigger t JOIN pg_class cl ON cl.oid = t.tgrelid
   WHERE cl.relnamespace = 'public'::regnamespace AND NOT t.tgisinternal
  UNION ALL
  SELECT 'function ' || pg_get_functiondef(p.oid) FROM pg_proc p
   WHERE p.pronamespace = 'public'::regnamespace
  UNION ALL
  SELECT 'view ' || viewname || ' ' || definition FROM pg_views WHERE schemaname = 'public'
  UNION ALL
  SELECT 'grant ' || grantee || ' ' || table_name || ' ' || privilege_type
    FROM information_schema.role_table_grants
   WHERE table_schema = 'public' AND grantee = 'factory_app' AND table_name <> '__diesel_schema_migrations'
  UNION ALL
  SELECT 'columngrant ' || grantee || ' ' || table_name || '.' || column_name || ' ' || privilege_type
    FROM information_schema.column_privileges
   WHERE table_schema = 'public' AND grantee = 'factory_app' AND table_name <> '__diesel_schema_migrations'
)
SELECT encode(sha256(convert_to(string_agg(d, E'\n' ORDER BY d), 'UTF8')), 'hex') FROM defs;
