-- Enforce the tenant root boundary and close cross-tenant parent/child links.
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_tenants ON tenants
  TO kelvin_app
  USING (id = current_tenant_id())
  WITH CHECK (id = current_tenant_id());

CREATE POLICY audit_writer_insert_tenant ON audit_log
  FOR INSERT TO kelvin_audit_writer
  WITH CHECK (tenant_id IS NULL OR tenant_id = current_tenant_id());

ALTER TABLE audit_log
  ADD CONSTRAINT fk_audit_log_actor_tenant
  FOREIGN KEY (actor_user_id, tenant_id) REFERENCES users (id, tenant_id);

ALTER TABLE auth_sessions
  ADD CONSTRAINT fk_auth_sessions_user_tenant
  FOREIGN KEY (user_id, tenant_id) REFERENCES users (id, tenant_id) ON DELETE CASCADE;

ALTER TABLE assessments
  ADD CONSTRAINT fk_assessments_requester_tenant
  FOREIGN KEY (requested_by, tenant_id) REFERENCES users (id, tenant_id) ON DELETE RESTRICT;

ALTER TABLE scan_profiles
  ADD CONSTRAINT fk_scan_profiles_creator_tenant
  FOREIGN KEY (created_by, tenant_id) REFERENCES users (id, tenant_id) ON DELETE SET NULL (created_by);

ALTER TABLE jobs
  ADD CONSTRAINT fk_jobs_assessment_tenant
  FOREIGN KEY (assessment_id, tenant_id) REFERENCES assessments (id, tenant_id) ON DELETE CASCADE;

ALTER TABLE findings
  ADD CONSTRAINT fk_findings_assessment_tenant
  FOREIGN KEY (assessment_id, tenant_id) REFERENCES assessments (id, tenant_id) ON DELETE RESTRICT,
  ADD CONSTRAINT fk_findings_job_tenant
  FOREIGN KEY (job_id, tenant_id) REFERENCES jobs (id, tenant_id) ON DELETE RESTRICT,
  ADD CONSTRAINT fk_findings_first_job_tenant
  FOREIGN KEY (first_job_id, tenant_id) REFERENCES jobs (id, tenant_id) ON DELETE RESTRICT,
  ADD CONSTRAINT fk_findings_last_job_tenant
  FOREIGN KEY (last_job_id, tenant_id) REFERENCES jobs (id, tenant_id) ON DELETE SET NULL (last_job_id),
  ADD CONSTRAINT fk_findings_asset_tenant
  FOREIGN KEY (asset_id, tenant_id) REFERENCES assets (id, tenant_id) ON DELETE SET NULL (asset_id);

ALTER TABLE finding_events
  ADD CONSTRAINT fk_finding_events_finding_tenant
  FOREIGN KEY (finding_id, tenant_id) REFERENCES findings (id, tenant_id) ON DELETE CASCADE,
  ADD CONSTRAINT fk_finding_events_actor_tenant
  FOREIGN KEY (actor_user_id, tenant_id) REFERENCES users (id, tenant_id) ON DELETE SET NULL (actor_user_id);

ALTER TABLE evidence
  ADD CONSTRAINT fk_evidence_finding_tenant
  FOREIGN KEY (finding_id, tenant_id) REFERENCES findings (id, tenant_id) ON DELETE CASCADE,
  ADD CONSTRAINT fk_evidence_job_tenant
  FOREIGN KEY (job_id, tenant_id) REFERENCES jobs (id, tenant_id) ON DELETE RESTRICT;

ALTER TABLE reports
  ADD CONSTRAINT fk_reports_assessment_tenant
  FOREIGN KEY (assessment_id, tenant_id) REFERENCES assessments (id, tenant_id) ON DELETE CASCADE,
  ADD CONSTRAINT fk_reports_generator_tenant
  FOREIGN KEY (generated_by, tenant_id) REFERENCES users (id, tenant_id) ON DELETE SET NULL (generated_by);

CREATE OR REPLACE FUNCTION enforce_assessment_profile_tenant() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE profile_tenant uuid;
BEGIN
  SELECT tenant_id INTO profile_tenant FROM scan_profiles WHERE id = NEW.profile_id;
  IF NOT FOUND OR (profile_tenant IS NOT NULL AND profile_tenant <> NEW.tenant_id) THEN
    RAISE EXCEPTION 'assessment profile is not owned by tenant %', NEW.tenant_id
      USING ERRCODE = 'foreign_key_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enforce_assessment_profile_tenant
  BEFORE INSERT OR UPDATE OF profile_id, tenant_id ON assessments
  FOR EACH ROW EXECUTE FUNCTION enforce_assessment_profile_tenant();

