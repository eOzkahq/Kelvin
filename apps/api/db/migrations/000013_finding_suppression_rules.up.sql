-- ==============================================================================
-- Migration 000013: Finding Suppression Rules with Expiry (P3-18)
-- ==============================================================================

-- 1. Create finding_suppression_rules table
CREATE TABLE IF NOT EXISTS finding_suppression_rules (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  finding_id        uuid NOT NULL,
  actor_id          uuid REFERENCES users(id) ON DELETE SET NULL,
  reason            text NOT NULL,
  status            text NOT NULL CHECK (status IN ('ACTIVE', 'EXPIRED', 'REVOKED')),
  expires_at        timestamptz NOT NULL,
  revoked_at        timestamptz,
  revoked_by        uuid REFERENCES users(id) ON DELETE SET NULL,
  revocation_reason text,
  metadata          jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_suppression_rules_id_tenant UNIQUE (id, tenant_id),
  CONSTRAINT fk_suppression_rules_finding FOREIGN KEY (finding_id, tenant_id)
    REFERENCES findings(id, tenant_id) ON DELETE CASCADE
);

-- 2. Lookup indexes
CREATE INDEX IF NOT EXISTS idx_suppression_rules_finding
  ON finding_suppression_rules (tenant_id, finding_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_suppression_rules_active_expiry
  ON finding_suppression_rules (tenant_id, status, expires_at)
  WHERE status = 'ACTIVE';
