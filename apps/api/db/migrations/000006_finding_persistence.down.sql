-- ==============================================================================
-- Revert Migration 000006: Finding and Observation Persistence Hardening (P3-05)
-- ==============================================================================

DROP INDEX IF EXISTS idx_finding_events_tenant_history;
DROP INDEX IF EXISTS idx_finding_observations_history_lookup;
DROP INDEX IF EXISTS idx_finding_observations_scanner_history;
DROP INDEX IF EXISTS idx_findings_project_last_seen;
DROP INDEX IF EXISTS idx_findings_project_fingerprint_lookup;

ALTER TABLE finding_observations
  DROP CONSTRAINT IF EXISTS finding_observations_finding_id_fkey;

ALTER TABLE finding_observations
  ADD CONSTRAINT finding_observations_finding_id_fkey
  FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE CASCADE;
