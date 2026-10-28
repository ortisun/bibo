-- One line per tenant-owned table: its name, how many rows it holds, and a hash of those rows over the columns the table
-- had BEFORE the upgrade. The columns are recorded the first time this file runs (in dbtest.old_columns) and used
-- every time after, so a column added by a later migration is not part of the comparison, and a column that
-- changed value is. Run as a superuser, so row-level security does not hide anything.

SET client_min_messages = warning;
CREATE SCHEMA IF NOT EXISTS dbtest;
DO $$
BEGIN
  IF to_regclass('dbtest.old_columns') IS NULL THEN
    CREATE TABLE dbtest.old_columns AS
      SELECT c.table_name::text AS tbl, c.column_name::text AS col, c.ordinal_position AS pos
        FROM information_schema.columns c
       WHERE c.table_schema = 'public'
         AND c.table_name IN (SELECT t.table_name FROM information_schema.columns t
                                JOIN information_schema.tables b ON b.table_schema = t.table_schema AND b.table_name = t.table_name AND b.table_type = 'BASE TABLE'
                               WHERE t.table_schema = 'public' AND t.column_name = 'tenant_id');
  END IF;
END
$$;

CREATE OR REPLACE FUNCTION dbtest.fingerprint() RETURNS TABLE (tbl text, row_count bigint, row_hash text) LANGUAGE plpgsql AS $$
DECLARE
  t text;
  cols text;
BEGIN
  FOR t IN SELECT DISTINCT o.tbl FROM dbtest.old_columns o ORDER BY 1 LOOP
    SELECT string_agg(format('%I', o.col), ', ' ORDER BY o.pos) INTO cols FROM dbtest.old_columns o WHERE o.tbl = t;
    tbl := t;
    EXECUTE format('SELECT count(*), md5(coalesce(string_agg(r::text, E''\n'' ORDER BY r::text), '''')) FROM (SELECT %s FROM public.%I) r', cols, t) INTO row_count, row_hash;
    RETURN NEXT;
  END LOOP;
END
$$;

SELECT tbl || '|' || row_count || '|' || row_hash FROM dbtest.fingerprint();
