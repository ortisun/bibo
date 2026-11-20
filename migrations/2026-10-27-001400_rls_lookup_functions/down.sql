-- The functions belong to factory_lookup, so dropping them needs the same temporary membership.
GRANT factory_lookup TO CURRENT_USER;
DROP FUNCTION IF EXISTS resolve_installation(bigint, bigint);
DROP FUNCTION IF EXISTS resolve_token(bytea, text);
REVOKE factory_lookup FROM CURRENT_USER;

-- The view as the earlier migration made it (no tenant check).
CREATE OR REPLACE VIEW active_api_tokens WITH (security_invoker = true) AS
SELECT t.tenant_id, t.id, t.principal_id, t.token_hash, t.audience, t.expires_at
  FROM api_tokens t
  JOIN principals p ON p.tenant_id = t.tenant_id AND p.id = t.principal_id
 WHERE t.revoked_at IS NULL
   AND t.expires_at > now()
   AND p.disabled_at IS NULL;

DROP POLICY IF EXISTS lookup_read ON repositories;
DROP POLICY IF EXISTS lookup_read ON api_tokens;
DROP POLICY IF EXISTS lookup_read ON principals;
DROP POLICY IF EXISTS lookup_read ON tenants;

REVOKE ALL ON active_api_tokens FROM factory_lookup;
REVOKE ALL ON tenants, principals, api_tokens, repositories FROM factory_lookup;
