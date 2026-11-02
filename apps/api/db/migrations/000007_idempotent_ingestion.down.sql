-- ==============================================================================
-- Revert Migration 000007: Idempotent Finding Ingestion & Assessment Dedup (P3-06)
-- ==============================================================================

DROP INDEX IF EXISTS idx_finding_observations_assessment_finding;

ALTER TABLE finding_observations
  DROP CONSTRAINT IF EXISTS uq_finding_observations_assessment_finding;
