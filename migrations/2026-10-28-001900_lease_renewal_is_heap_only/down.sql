CREATE INDEX attempts_lease_expiry_idx ON attempts (lease_expires_at) WHERE status IN ('STARTING', 'RUNNING');
