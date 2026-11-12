-- Migration 000061 (Down): Revert tenant RLS standardization and restore previous RLS force settings

BEGIN;

-- 1. Revert current_tenant_id() to single setting
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
$$;

-- 2. Restore previous RLS force settings for tables newly forced in migration 000061
-- (Original tables from 000001, 000003, and 000005 retain their original FORCE ROW LEVEL SECURITY)
ALTER TABLE finding_risk_history NO FORCE ROW LEVEL SECURITY;
ALTER TABLE finding_evidence_links NO FORCE ROW LEVEL SECURITY;
ALTER TABLE remediation_tasks NO FORCE ROW LEVEL SECURITY;
ALTER TABLE remediation_updates NO FORCE ROW LEVEL SECURITY;
ALTER TABLE report_snapshots NO FORCE ROW LEVEL SECURITY;
ALTER TABLE report_artifacts NO FORCE ROW LEVEL SECURITY;

-- 3. Restore previous restrictive policies
DROP POLICY IF EXISTS remediation_tasks_tenant_isolation ON remediation_tasks;
CREATE POLICY remediation_tasks_tenant_isolation ON remediation_tasks
  AS RESTRICTIVE
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP POLICY IF EXISTS remediation_updates_tenant_isolation ON remediation_updates;
CREATE POLICY remediation_updates_tenant_isolation ON remediation_updates
  AS RESTRICTIVE
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP POLICY IF EXISTS finding_risk_history_tenant_isolation ON finding_risk_history;
CREATE POLICY finding_risk_history_tenant_isolation ON finding_risk_history
  AS RESTRICTIVE
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP POLICY IF EXISTS finding_evidence_links_tenant_isolation ON finding_evidence_links;
CREATE POLICY finding_evidence_links_tenant_isolation ON finding_evidence_links
  AS RESTRICTIVE
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP POLICY IF EXISTS report_snapshots_tenant_isolation ON report_snapshots;
CREATE POLICY report_snapshots_tenant_isolation ON report_snapshots
  AS RESTRICTIVE
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP POLICY IF EXISTS report_artifacts_tenant_isolation ON report_artifacts;
CREATE POLICY report_artifacts_tenant_isolation ON report_artifacts
  AS RESTRICTIVE
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

COMMIT;
