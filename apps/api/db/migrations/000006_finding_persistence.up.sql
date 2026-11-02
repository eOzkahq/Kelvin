-- ==============================================================================
-- Migration 000006: Finding and Observation Persistence Hardening (P3-05)
-- ==============================================================================

-- 1. Enforce ON DELETE RESTRICT on finding_observations -> findings relationship
-- to guarantee observation retention and prevent accidental cascade deletions
ALTER TABLE finding_observations
  DROP CONSTRAINT IF EXISTS finding_observations_finding_id_fkey;

ALTER TABLE finding_observations
  ADD CONSTRAINT finding_observations_finding_id_fkey
  FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE RESTRICT;

-- 2. Performance and lookup indexes for tenant, project, fingerprint, and timestamps
CREATE INDEX IF NOT EXISTS idx_findings_project_fingerprint_lookup
  ON findings (tenant_id, project_id, fingerprint);

CREATE INDEX IF NOT EXISTS idx_findings_project_last_seen
  ON findings (tenant_id, project_id, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_finding_observations_scanner_history
  ON finding_observations (tenant_id, scanner_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_finding_observations_history_lookup
  ON finding_observations (tenant_id, finding_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_finding_events_tenant_history
  ON finding_events (tenant_id, finding_id, created_at DESC);
