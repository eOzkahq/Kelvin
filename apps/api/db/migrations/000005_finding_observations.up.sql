-- ==============================================================================
-- Migration 000005: Finding Observations and Correlation Groups (P3-01)
-- ==============================================================================

-- 1. Correlation Groups: groups of related findings across scanners / surfaces
CREATE TABLE IF NOT EXISTS correlation_groups (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  name        text NOT NULL,
  rule_type   text NOT NULL DEFAULT 'MANUAL',
  description text,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_correlation_groups_id_tenant UNIQUE (id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_correlation_groups_tenant
  ON correlation_groups (tenant_id, created_at DESC);

ALTER TABLE correlation_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE correlation_groups FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS correlation_groups_tenant_isolation ON correlation_groups;
CREATE POLICY correlation_groups_tenant_isolation ON correlation_groups
  FOR ALL
  USING (tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());

-- Add correlation_group_id foreign key to findings if absent
ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS correlation_group_id uuid REFERENCES correlation_groups(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_findings_correlation_group
  ON findings (tenant_id, correlation_group_id)
  WHERE correlation_group_id IS NOT NULL;

-- 2. Finding Observations: immutable, assessment-specific occurrences of a finding
CREATE TABLE IF NOT EXISTS finding_observations (
  id             uuid PRIMARY KEY,
  tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  finding_id     uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  assessment_id  uuid NOT NULL REFERENCES assessments(id) ON DELETE RESTRICT,
  job_id         uuid NOT NULL REFERENCES jobs(id) ON DELETE RESTRICT,
  scanner_id     text NOT NULL,
  observed_at    timestamptz NOT NULL,
  evidence_refs  jsonb NOT NULL DEFAULT '[]'::jsonb,
  raw_metadata   jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_finding_observations_id_tenant UNIQUE (id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_finding_observations_finding
  ON finding_observations (tenant_id, finding_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_finding_observations_assessment
  ON finding_observations (tenant_id, assessment_id);

ALTER TABLE finding_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_observations FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS finding_observations_tenant_isolation ON finding_observations;
CREATE POLICY finding_observations_tenant_isolation ON finding_observations
  FOR ALL
  USING (tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());

-- Prevent in-place modifications to historical observations (immutability rule)
CREATE OR REPLACE FUNCTION prevent_observation_update()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'finding_observations are immutable historical audit records and cannot be updated';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_observation_update ON finding_observations;
CREATE TRIGGER trg_prevent_observation_update
  BEFORE UPDATE ON finding_observations
  FOR EACH ROW
  EXECUTE FUNCTION prevent_observation_update();
