-- ==============================================================================
-- Migration 000015: Target Contextual Risk Factors (P3-22)
-- ==============================================================================

-- 1. Create target_risk_contexts table
CREATE TABLE IF NOT EXISTS target_risk_contexts (
  id                   uuid PRIMARY KEY,
  tenant_id            uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id           uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  target_asset         text NOT NULL,
  environment          text NOT NULL CHECK (environment IN ('PRODUCTION', 'STAGING', 'DEVELOPMENT', 'UNKNOWN')),
  internet_facing      boolean NOT NULL DEFAULT false,
  contains_pii         boolean NOT NULL DEFAULT false,
  business_criticality text NOT NULL CHECK (business_criticality IN ('MISSION_CRITICAL', 'BUSINESS_OPERATIONAL', 'NON_CRITICAL', 'UNKNOWN')),
  source               text NOT NULL DEFAULT 'MANUAL_ANALYST',
  updated_by           uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_target_risk_context UNIQUE (tenant_id, project_id, target_asset)
);

-- 2. Lookup index
CREATE INDEX IF NOT EXISTS idx_target_risk_contexts_lookup
  ON target_risk_contexts (tenant_id, project_id, target_asset);
