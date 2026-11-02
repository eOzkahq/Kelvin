-- ==============================================================================
-- Migration 000011: Finding Triage Decisions and Dispositions (P3-16)
-- ==============================================================================

-- 1. Create finding_triage_decisions table
CREATE TABLE IF NOT EXISTS finding_triage_decisions (
  id                   uuid PRIMARY KEY,
  tenant_id            uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  finding_id           uuid NOT NULL,
  disposition          text NOT NULL CHECK (disposition IN (
                         'CONFIRMED',
                         'INVESTIGATING',
                         'FALSE_POSITIVE',
                         'ACCEPTED_RISK',
                         'DUPLICATE'
                       )),
  scope                text NOT NULL CHECK (scope IN (
                         'PERSISTENT_FINDING',
                         'OBSERVATION',
                         'CORRELATION_GROUP'
                       )),
  actor_id             uuid REFERENCES users(id) ON DELETE SET NULL,
  justification        text NOT NULL,
  approver_id          uuid REFERENCES users(id) ON DELETE SET NULL,
  expires_at           timestamptz,
  canonical_finding_id uuid REFERENCES findings(id) ON DELETE SET NULL,
  metadata             jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_triage_decisions_id_tenant UNIQUE (id, tenant_id),
  CONSTRAINT fk_triage_decisions_finding FOREIGN KEY (finding_id, tenant_id)
    REFERENCES findings(id, tenant_id) ON DELETE CASCADE
);

-- 2. Lookup indexes
CREATE INDEX IF NOT EXISTS idx_triage_decisions_finding
  ON finding_triage_decisions (tenant_id, finding_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_triage_decisions_expiry
  ON finding_triage_decisions (tenant_id, expires_at)
  WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_triage_decisions_disposition
  ON finding_triage_decisions (tenant_id, disposition, created_at DESC);
