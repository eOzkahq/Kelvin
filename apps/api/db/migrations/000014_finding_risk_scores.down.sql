DROP INDEX IF EXISTS idx_findings_tenant_risk_priority;

ALTER TABLE findings
  DROP COLUMN IF EXISTS risk_factors,
  DROP COLUMN IF EXISTS risk_priority_band,
  DROP COLUMN IF EXISTS risk_score;
