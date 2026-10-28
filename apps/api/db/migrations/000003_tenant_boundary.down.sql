ALTER TABLE reports DROP CONSTRAINT IF EXISTS fk_reports_assessment_tenant;
ALTER TABLE reports DROP CONSTRAINT IF EXISTS fk_reports_generator_tenant;
ALTER TABLE evidence
  DROP CONSTRAINT IF EXISTS fk_evidence_job_tenant,
  DROP CONSTRAINT IF EXISTS fk_evidence_finding_tenant;
ALTER TABLE finding_events DROP CONSTRAINT IF EXISTS fk_finding_events_finding_tenant;
ALTER TABLE finding_events DROP CONSTRAINT IF EXISTS fk_finding_events_actor_tenant;
ALTER TABLE findings
  DROP CONSTRAINT IF EXISTS fk_findings_last_job_tenant,
  DROP CONSTRAINT IF EXISTS fk_findings_first_job_tenant,
  DROP CONSTRAINT IF EXISTS fk_findings_job_tenant,
  DROP CONSTRAINT IF EXISTS fk_findings_assessment_tenant;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS fk_findings_asset_tenant;
ALTER TABLE assessments DROP CONSTRAINT IF EXISTS fk_assessments_requester_tenant;
ALTER TABLE scan_profiles DROP CONSTRAINT IF EXISTS fk_scan_profiles_creator_tenant;
ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS fk_audit_log_actor_tenant;
DROP POLICY IF EXISTS audit_writer_insert_tenant ON audit_log;
ALTER TABLE jobs DROP CONSTRAINT IF EXISTS fk_jobs_assessment_tenant;
ALTER TABLE auth_sessions DROP CONSTRAINT IF EXISTS fk_auth_sessions_user_tenant;
DROP POLICY IF EXISTS tenant_isolation_tenants ON tenants;
ALTER TABLE tenants NO FORCE ROW LEVEL SECURITY;
ALTER TABLE tenants DISABLE ROW LEVEL SECURITY;
DROP TRIGGER IF EXISTS enforce_assessment_profile_tenant ON assessments;
DROP FUNCTION IF EXISTS enforce_assessment_profile_tenant();
