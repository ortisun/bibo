-- Tenancy and identity: tenants, registered repositories, principals and API tokens.
--
-- Tenancy rules (ADR 0007, rule 4), applied to every table in these migrations:
--   * every tenant-owned table has tenant_id uuid NOT NULL, first in its primary key;
--   * a foreign key between tenant-owned tables names tenant_id on both sides, so a row cannot
--     point at another tenant's parent;
--   * a unique constraint includes tenant_id. The few that do not are listed, with the reason, in
--     docs/database/constraints-and-indexes.md and in the tenancy test.
-- Row-level security is not in this baseline (ADR 0007). See docs/database/tenancy.md.

CREATE TABLE tenants (
  id           uuid PRIMARY KEY,
  slug         text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  kind         text NOT NULL DEFAULT 'customer' CHECK (kind IN ('customer', 'platform')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  disabled_at  timestamptz
);

-- Audit events that belong to no tenant (a webhook with a bad signature, an unknown installation)
-- are recorded under this one platform tenant, so every audit row still has a tenant and a chain.
CREATE UNIQUE INDEX tenants_one_platform ON tenants (kind) WHERE kind = 'platform';
INSERT INTO tenants (id, slug, display_name, kind)
VALUES ('00000000-0000-0000-0000-000000000001', 'platform', 'Platform events that belong to no tenant', 'platform');

CREATE TABLE repositories (
  tenant_id                   uuid    NOT NULL REFERENCES tenants (id),
  id                          uuid    NOT NULL,
  github_installation_id      bigint  NOT NULL CHECK (github_installation_id > 0),
  github_repository_id        bigint  NOT NULL CHECK (github_repository_id > 0),
  full_name                   text    NOT NULL CHECK (full_name ~ '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'),
  default_branch              text    NOT NULL CHECK (length(default_branch) BETWEEN 1 AND 255),
  enabled                     boolean NOT NULL DEFAULT true,
  -- Repositories without branch protection run at level L0 only (ADR 0009, default 3).
  protection_preflight_passed boolean NOT NULL DEFAULT false,
  autonomy_ceiling            text    NOT NULL DEFAULT 'L0' CHECK (autonomy_ceiling IN ('L0', 'L1', 'L2', 'L3')),
  version                     bigint  NOT NULL DEFAULT 1 CHECK (version >= 1),
  created_at                  timestamptz NOT NULL DEFAULT now(),
  updated_at                  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id),
  -- Not tenant scoped, on purpose. The webhook receiver finds the tenant FROM the repository, so
  -- the lookup cannot start with a tenant. One GitHub repository can belong to one tenant only;
  -- a second claim on it would make the tenant binding of a webhook ambiguous (threat T-24, C-04).
  UNIQUE (github_repository_id)
);
CREATE INDEX repositories_installation_idx ON repositories (github_installation_id);
CREATE TRIGGER repositories_bump BEFORE UPDATE ON repositories FOR EACH ROW EXECUTE FUNCTION bump_guard();

-- Identity only. Authority (requester, operator, approver and so on) comes from the named allowlist
-- in protected configuration and is deliberately NOT stored here (policies/approval.yaml, authority).
CREATE TABLE principals (
  tenant_id      uuid   NOT NULL REFERENCES tenants (id),
  id             uuid   NOT NULL,
  kind           text   NOT NULL CHECK (kind IN ('human', 'service')),
  github_user_id bigint CHECK (github_user_id > 0),
  -- Display only. A login can be renamed or re-registered by someone else; the numeric id is the key.
  login          text   CHECK (login IS NULL OR length(login) BETWEEN 1 AND 100),
  created_at     timestamptz NOT NULL DEFAULT now(),
  disabled_at    timestamptz,
  PRIMARY KEY (tenant_id, id),
  -- Lets approvals point at (tenant, principal, 'human', GitHub user id): the approver is a human of
  -- this tenant, and the GitHub id recorded with the approval is the one this principal has.
  UNIQUE (tenant_id, id, kind, github_user_id),
  UNIQUE (tenant_id, github_user_id),
  CHECK ((kind = 'human') = (github_user_id IS NOT NULL))
);

-- API tokens are stored as a SHA-256 hash of a 256-bit random secret. The secret is shown once
-- and never stored. Lookups hash the presented token and search token_hash.
CREATE TABLE api_tokens (
  tenant_id    uuid  NOT NULL REFERENCES tenants (id),
  id           uuid  NOT NULL,
  principal_id uuid  NOT NULL,
  token_hash   bytea NOT NULL CHECK (octet_length(token_hash) = 32),
  audience     text  NOT NULL CHECK (audience ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$'),
  label        text  CHECK (label IS NULL OR length(label) BETWEEN 1 AND 100),
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz,
  last_used_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, principal_id) REFERENCES principals (tenant_id, id),
  -- Not tenant scoped, on purpose: the API authenticates a request by this hash BEFORE it knows
  -- the tenant. 256 bits of entropy make a collision between tenants negligible, and the constraint
  -- turns the negligible case into an insert error instead of an ambiguous lookup.
  UNIQUE (token_hash),
  CHECK (expires_at > created_at),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);
CREATE INDEX api_tokens_principal_idx ON api_tokens (tenant_id, principal_id);

-- Once revoked, a token stays revoked: revoked_at can be set from NULL and nothing else. The
-- application role may update only revoked_at and last_used_at (column grants in the last migration).
CREATE FUNCTION api_tokens_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'a revoked API token cannot be changed or un-revoked'
      USING ERRCODE = '23514', CONSTRAINT = 'api_tokens_revocation_is_final', TABLE = 'api_tokens';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER api_tokens_guard BEFORE UPDATE ON api_tokens FOR EACH ROW EXECUTE FUNCTION api_tokens_guard();

-- The one place that says what a usable token is: not revoked, not expired, and its principal is
-- not disabled. Authentication reads this view with the token hash and the audience it serves.
-- security_invoker makes the view use the caller's rights, so a later row-level security policy
-- on the base tables applies through it.
CREATE VIEW active_api_tokens WITH (security_invoker = true) AS
SELECT t.tenant_id, t.id, t.principal_id, t.token_hash, t.audience, t.expires_at
  FROM api_tokens t
  JOIN principals p ON p.tenant_id = t.tenant_id AND p.id = t.principal_id
 WHERE t.revoked_at IS NULL
   AND t.expires_at > now()
   AND p.disabled_at IS NULL;
