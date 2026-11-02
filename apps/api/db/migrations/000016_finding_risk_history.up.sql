-- ==============================================================================
-- Migration: 000016_finding_risk_history.up.sql
-- Purpose: Create finding_risk_history table for immutable versioned risk audit trail
-- Workstream: Workstream C (Risk Intelligence & Prioritization) - P3-25
-- ==============================================================================

CREATE TABLE IF NOT EXISTS finding_risk_history (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL,
  finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  model_version   TEXT NOT NULL,
  risk_score      NUMERIC(3,1) NOT NULL,
  priority_band   TEXT NOT NULL,
  risk_factors    JSONB NOT NULL DEFAULT '{}'::jsonb,
  trigger_reason  TEXT NOT NULL,
  actor_id        UUID,
  calculated_at   TIMESTAMPTZ NOT NULL,
  superseded_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- 1. Enable Row-Level Security (RLS)
ALTER TABLE finding_risk_history ENABLE ROW LEVEL SECURITY;

-- 2. Tenant isolation policy (ADR-0002)
CREATE POLICY finding_risk_history_tenant_isolation ON finding_risk_history
  AS RESTRICTIVE
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 3. Composite performance index for history queries
CREATE INDEX IF NOT EXISTS idx_finding_risk_history_lookup
  ON finding_risk_history (tenant_id, finding_id, calculated_at DESC);
