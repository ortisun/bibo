-- Everything the migrations create in the public schema. After every migration is reverted the
-- list must be empty. Roles are cluster wide, so they are not listed and are not dropped.
SELECT 'table ' || c.relname
  FROM pg_class c
 WHERE c.relnamespace = 'public'::regnamespace
   AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
   AND c.relname <> '__diesel_schema_migrations'
   AND c.relname NOT LIKE '\_\_diesel%'
UNION ALL
SELECT 'function ' || p.proname FROM pg_proc p
 WHERE p.pronamespace = 'public'::regnamespace
UNION ALL
SELECT 'type ' || t.typname FROM pg_type t
 WHERE t.typnamespace = 'public'::regnamespace
   AND t.typtype NOT IN ('c')
   AND t.typname NOT LIKE '\_%'
   AND t.typname NOT LIKE '\_\_diesel%'
ORDER BY 1;
