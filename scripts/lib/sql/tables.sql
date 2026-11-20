-- Row count and content hash of every table in the public schema (work package s1-local-deployment).
--
-- Run as the database superuser. Prints one JSON object on one line:
--   { "<table>": { "rows": N, "sha256": "<hex>" }, ... }
-- The hash covers every column of every row: the rows are turned into text, sorted, joined with a
-- newline, and hashed. The time zone is fixed so that timestamps print the same on both sides.
-- A table with more than about 1 GB of text would hit the string size limit; the local stack is far
-- below that, and the failure would be an error, not a wrong answer.

SET TimeZone = 'UTC';

SELECT 'SELECT coalesce(jsonb_object_agg(t, jsonb_build_object(''rows'', n, ''sha256'', h)), ''{}''::jsonb)::text FROM (' ||
       coalesce(string_agg(
         format('SELECT %L AS t, count(*) AS n, encode(sha256(convert_to(coalesce(string_agg(x::text, E''\n'' ORDER BY x::text), ''''), ''UTF8'')), ''hex'') AS h FROM %I.%I x',
                c.relname, n.nspname, c.relname),
         ' UNION ALL ' ORDER BY c.relname),
         'SELECT NULL::text AS t, NULL::bigint AS n, NULL::text AS h WHERE false') ||
       ') s' AS q
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relkind = 'r' \gset

:q;
