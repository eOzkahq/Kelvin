-- Kelvin Security Platform — Schema Migration 00061
-- PRE-01: Standardize tenant context setting and enforce FORCE ROW LEVEL SECURITY across all tenant tables

-- 1. Canonical current_tenant_id() SQL helper accepting app.current_tenant_id and fallback to app.tenant_id
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT COALESCE(
    NULLIF(current_setting('app.current_tenant_id', true), ''),
    NULLIF(current_setting('app.tenant_id', true), '')
  )::uuid
$$;

-- 2. Standardize tenant isolation policies on tables that had RESTRICTIVE or non-canonical policies
DROP POLICY IF EXISTS finding_risk_history_tenant_isolation ON finding_risk_history;
CREATE POLICY finding_risk_history_tenant_isolation ON finding_risk_history
  FOR ALL
  USING (tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS finding_evidence_links_tenant_isolation ON finding_evidence_links;
CREATE POLICY finding_evidence_links_tenant_isolation ON finding_evidence_links
  FOR ALL
  USING (tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS remediation_tasks_tenant_isolation ON remediation_tasks;
CREATE POLICY remediation_tasks_tenant_isolation ON remediation_tasks
  FOR ALL
  USING (tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS remediation_updates_tenant_isolation ON remediation_updates;
CREATE POLICY remediation_updates_tenant_isolation ON remediation_updates
  FOR ALL
  USING (tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS report_snapshots_tenant_isolation ON report_snapshots;
CREATE POLICY report_snapshots_tenant_isolation ON report_snapshots
  FOR ALL
  USING (tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS report_artifacts_tenant_isolation ON report_artifacts;
CREATE POLICY report_artifacts_tenant_isolation ON report_artifacts
  FOR ALL
  USING (tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());

DROP POLICY IF EXISTS evidence_tenant_isolation ON evidence;
CREATE POLICY evidence_tenant_isolation ON evidence
  FOR ALL
  USING (tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());

-- 3. Enforce FORCE ROW LEVEL SECURITY on all tenant tables (prevents bypass even for table owners)
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE scan_profiles FORCE ROW LEVEL SECURITY;
ALTER TABLE assets FORCE ROW LEVEL SECURITY;
ALTER TABLE assessments FORCE ROW LEVEL SECURITY;
ALTER TABLE jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
ALTER TABLE finding_events FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE reports FORCE ROW LEVEL SECURITY;
ALTER TABLE finding_observations FORCE ROW LEVEL SECURITY;
ALTER TABLE finding_risk_history FORCE ROW LEVEL SECURITY;
ALTER TABLE finding_evidence_links FORCE ROW LEVEL SECURITY;
ALTER TABLE remediation_tasks FORCE ROW LEVEL SECURITY;
ALTER TABLE remediation_updates FORCE ROW LEVEL SECURITY;
ALTER TABLE report_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE report_artifacts FORCE ROW LEVEL SECURITY;
