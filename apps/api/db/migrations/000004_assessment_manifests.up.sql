-- Assessment execution manifests: immutable audit records of exact runtime configuration
CREATE TABLE IF NOT EXISTS assessment_manifests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  assessment_id uuid NOT NULL,
  run_id text NOT NULL,
  profile_id text NOT NULL,
  profile_version text NOT NULL DEFAULT '1.0',
  target_url text NOT NULL,
  scanners jsonb NOT NULL,
  resource_limits jsonb NOT NULL,
  effective_config jsonb NOT NULL,
  manifest_digest text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT fk_manifests_assessment_tenant
    FOREIGN KEY (assessment_id, tenant_id) REFERENCES assessments (id, tenant_id) ON DELETE CASCADE,
  CONSTRAINT uq_assessment_manifests_run
    UNIQUE (tenant_id, assessment_id, run_id)
);

CREATE INDEX IF NOT EXISTS idx_assessment_manifests_tenant_assessment
  ON assessment_manifests (tenant_id, assessment_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_assessment_manifests_digest
  ON assessment_manifests (manifest_digest);

-- Prevent silent mutation: manifests are strictly append-only and immutable
CREATE OR REPLACE FUNCTION enforce_assessment_manifest_immutability() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'assessment_manifests records are strictly immutable and cannot be updated';
END;
$$;

DROP TRIGGER IF EXISTS trg_prevent_manifest_update ON assessment_manifests;
CREATE TRIGGER trg_prevent_manifest_update
  BEFORE UPDATE ON assessment_manifests
  FOR EACH ROW EXECUTE FUNCTION enforce_assessment_manifest_immutability();

-- Tenant isolation via Row-Level Security
ALTER TABLE assessment_manifests ENABLE ROW LEVEL SECURITY;
ALTER TABLE assessment_manifests FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_assessment_manifests ON assessment_manifests;
CREATE POLICY tenant_isolation_assessment_manifests ON assessment_manifests
  TO kelvin_app
  USING (tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());
