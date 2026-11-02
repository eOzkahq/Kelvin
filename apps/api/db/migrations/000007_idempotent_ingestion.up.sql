-- ==============================================================================
-- Migration 000007: Idempotent Finding Ingestion & Assessment Dedup (P3-06)
-- ==============================================================================

-- 1. Ensure exactly one observation per finding per assessment run
ALTER TABLE finding_observations
  ADD CONSTRAINT uq_finding_observations_assessment_finding
  UNIQUE (assessment_id, finding_id);

-- 2. Index for rapid idempotency probes
CREATE INDEX IF NOT EXISTS idx_finding_observations_assessment_finding
  ON finding_observations (tenant_id, assessment_id, finding_id);
