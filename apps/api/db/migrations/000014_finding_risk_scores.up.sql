-- ==============================================================================
-- Migration 000014: KELVIN Risk Assessment Model (P3-20)
-- ==============================================================================

-- 1. Add risk scoring fields to findings table
ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS risk_score numeric(3,1) CHECK (risk_score >= 0.0 AND risk_score <= 10.0),
  ADD COLUMN IF NOT EXISTS risk_priority_band text CHECK (risk_priority_band IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
  ADD COLUMN IF NOT EXISTS risk_factors jsonb NOT NULL DEFAULT '{}'::jsonb;

-- 2. Performance index for risk-prioritized dashboards and queries
CREATE INDEX IF NOT EXISTS idx_findings_tenant_risk_priority
  ON findings (tenant_id, risk_priority_band, risk_score DESC NULLS LAST);
