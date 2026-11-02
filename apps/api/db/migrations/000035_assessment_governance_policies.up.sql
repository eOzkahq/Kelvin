-- ==============================================================================
-- Migration: 000035_assessment_governance_policies.up.sql
-- Purpose: Organization Assessment Governance Policies (P4-20)
-- Workstream: Workstream C (Policy & Workflow Governance)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS assessment_governance_policies (
  id                           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id              UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  allowed_scanners             JSONB NOT NULL DEFAULT '["zap", "nuclei", "http", "tls"]'::jsonb,
  allowed_assessment_types     JSONB NOT NULL DEFAULT '["DAST", "NETWORK", "CONFIG"]'::jsonb,
  max_concurrency              INTEGER NOT NULL DEFAULT 5,
  max_target_pacing_ms         INTEGER NOT NULL DEFAULT 1000,
  prohibit_intrusive_on_prod   BOOLEAN NOT NULL DEFAULT true,
  enforce_maintenance_windows  BOOLEAN NOT NULL DEFAULT false,
  maintenance_window_start     VARCHAR(5) NOT NULL DEFAULT '00:00',
  maintenance_window_end       VARCHAR(5) NOT NULL DEFAULT '06:00',
  version                      INTEGER NOT NULL DEFAULT 1,
  status                       VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, DISABLED
  created_at                   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at                   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_assessment_gov_org UNIQUE (organization_id)
);

CREATE INDEX IF NOT EXISTS idx_assessment_gov_org
  ON assessment_governance_policies (organization_id);
