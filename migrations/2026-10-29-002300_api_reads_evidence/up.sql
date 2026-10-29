-- The API serves the evidence a person reads before a decision: the specification draft they approve, the
-- gate reports of a job and the stored documents behind both (GET /v1/jobs/{id}/specification-draft,
-- /gate-reports and /artifacts/{sha256}). That needs three more tables to be readable by the login of the API.
--
-- Migration 2026-10-28-002000 made the API's group narrow on purpose (finding API-3): it read a few tables
-- and wrote four, and the suite api_privileges said in so many words that it could not read the ledger, the
-- artifact index or the links from a stage run to its documents. The reason was the write side: with
-- factory_app the login could INSERT into 17 tables, among them the ledger, and mint a token for another
-- tenant's approver. Reading is another thing. These three grants are SELECT and nothing else, so the login
-- still updates nothing, deletes nothing and writes only the four tables it wrote before. Row-level security
-- applies to the group exactly as it does to factory_app: a row belongs to the tenant the transaction named.
--
--   artifacts            the index of the stored documents of the tenant: the hash, the size and the type. The
--                        artifact store answers a read only for a hash the tenant's own row names.
--   stage_run_artifacts  which stage run produced or consumed which document. The API serves a document only
--                        for a job whose stage runs are linked to it.
--   ledger_entries       the entries of the hash chain of a job, which cite each gate report by its hash.
--
-- The bytes of a document are not in the database. The API reads them from the artifact store it is
-- configured with (`artifacts` in its configuration), and without one the three endpoints answer 503.
--
-- The suite api_privileges lists the grants both ways, so this change is a line in that file as well.

GRANT SELECT ON artifacts, stage_run_artifacts, ledger_entries TO factory_api_app;

DO $$
DECLARE
  evidence_table text;
BEGIN
  FOREACH evidence_table IN ARRAY ARRAY['artifacts', 'stage_run_artifacts', 'ledger_entries'] LOOP
    EXECUTE format('ALTER POLICY tenant_isolation ON public.%I TO factory_app, factory_api_app', evidence_table);
  END LOOP;
END
$$;
