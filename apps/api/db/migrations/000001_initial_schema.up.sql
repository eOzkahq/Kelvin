-- Kelvin Security Platform — Schema Migration 0001
-- Initial schema: tenants, users, auth_sessions, projects, scan_profiles, assets, assessments, jobs, findings, finding_events, evidence, reports, audit_log
-- Per ADR-0002, ADR-0003, and docs/architecture/DATA_MODEL.md

-- ==============================================================================
-- 1. Helper Functions & Roles
-- ==============================================================================

CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE AS $$
  SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
$$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'kelvin_app') THEN
    CREATE ROLE kelvin_app NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'kelvin_purger') THEN
    CREATE ROLE kelvin_purger NOLOGIN BYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'kelvin_audit_writer') THEN
    CREATE ROLE kelvin_audit_writer NOLOGIN;
  END IF;
END $$;

-- ==============================================================================
-- 2. Tenants (Root Entity)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS tenants (
  id         uuid PRIMARY KEY,
  name       text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
  slug       text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  status     text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED','OFFBOARDING')),
  settings   jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_tenants_slug ON tenants (slug);

DROP TRIGGER IF EXISTS set_updated_tenants ON tenants;
CREATE TRIGGER set_updated_tenants BEFORE UPDATE ON tenants
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ==============================================================================
-- 3. Users
-- ==============================================================================

CREATE TABLE IF NOT EXISTS users (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  email         text NOT NULL,
  display_name  text NOT NULL,
  password_hash text,
  oidc_subject  text,
  role          text NOT NULL CHECK (role IN ('PLATFORM_ADMIN','TENANT_ADMIN','SECURITY_ANALYST','READ_ONLY_AUDITOR')),
  is_active     boolean NOT NULL DEFAULT true,
  last_login_at timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  deleted_at    timestamptz,
  CONSTRAINT uq_users_id_tenant UNIQUE (id, tenant_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_users_tenant_email
  ON users (tenant_id, lower(email))
  WHERE deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_users_tenant_oidc
  ON users (tenant_id, oidc_subject)
  WHERE oidc_subject IS NOT NULL AND deleted_at IS NULL;

DROP TRIGGER IF EXISTS set_updated_users ON users;
CREATE TRIGGER set_updated_users BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ==============================================================================
-- 4. Auth Sessions
-- ==============================================================================

CREATE TABLE IF NOT EXISTS auth_sessions (
  id           uuid PRIMARY KEY,
  tenant_id    uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_family uuid NOT NULL,
  token_hash   text NOT NULL,
  issued_at    timestamptz NOT NULL,
  last_used_at timestamptz NOT NULL,
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz,
  user_agent   text,
  ip_address   inet,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_auth_sessions_id_tenant UNIQUE (id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_active
  ON auth_sessions (user_id, expires_at)
  WHERE revoked_at IS NULL;

DROP TRIGGER IF EXISTS set_updated_auth_sessions ON auth_sessions;
CREATE TRIGGER set_updated_auth_sessions BEFORE UPDATE ON auth_sessions
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ==============================================================================
-- 5. Projects
-- ==============================================================================

CREATE TABLE IF NOT EXISTS projects (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  name             text NOT NULL,
  description      text,
  scope_boundaries jsonb NOT NULL DEFAULT '{"allow":[],"deny":[]}'::jsonb,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  deleted_at       timestamptz,
  CONSTRAINT uq_projects_id_tenant UNIQUE (id, tenant_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_projects_tenant_name
  ON projects (tenant_id, lower(name))
  WHERE deleted_at IS NULL;

DROP TRIGGER IF EXISTS set_updated_projects ON projects;
CREATE TRIGGER set_updated_projects BEFORE UPDATE ON projects
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ==============================================================================
-- 6. Scan Profiles
-- ==============================================================================

CREATE TABLE IF NOT EXISTS scan_profiles (
  id          uuid PRIMARY KEY,
  tenant_id   uuid REFERENCES tenants(id) ON DELETE RESTRICT,
  profile_id  text NOT NULL,
  version     text NOT NULL,
  definition  jsonb NOT NULL,
  status      text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DEPRECATED')),
  created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now(),
  deleted_at  timestamptz,
  CONSTRAINT uq_scan_profiles_id_tenant UNIQUE (id, tenant_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_scan_profiles_tenant_ver
  ON scan_profiles (COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid), profile_id, version);

DROP TRIGGER IF EXISTS set_updated_scan_profiles ON scan_profiles;
CREATE TRIGGER set_updated_scan_profiles BEFORE UPDATE ON scan_profiles
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ==============================================================================
-- 7. Assets
-- ==============================================================================

CREATE TABLE IF NOT EXISTS assets (
  id                  uuid PRIMARY KEY,
  tenant_id           uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id          uuid NOT NULL,
  target_type         text NOT NULL CHECK (target_type IN ('DOMAIN','IPV4','IPV6','URL','CIDR')),
  value               text NOT NULL,
  is_verified         boolean NOT NULL DEFAULT false,
  verification_method text CHECK (verification_method IS NULL OR verification_method IN ('DNS_TXT','HTTP_WELL_KNOWN','LOA')),
  verified_at         timestamptz,
  first_seen_at       timestamptz NOT NULL DEFAULT now(),
  last_seen_at        timestamptz NOT NULL DEFAULT now(),
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  deleted_at          timestamptz,
  CONSTRAINT uq_assets_id_tenant UNIQUE (id, tenant_id),
  CONSTRAINT fk_assets_project_tenant FOREIGN KEY (project_id, tenant_id) REFERENCES projects (id, tenant_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_assets_project_target
  ON assets (project_id, target_type, value)
  WHERE deleted_at IS NULL;

DROP TRIGGER IF EXISTS set_updated_assets ON assets;
CREATE TRIGGER set_updated_assets BEFORE UPDATE ON assets
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ==============================================================================
-- 8. Assessments
-- ==============================================================================

CREATE TABLE IF NOT EXISTS assessments (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id       uuid NOT NULL,
  name             text NOT NULL,
  profile_id       uuid NOT NULL REFERENCES scan_profiles(id) ON DELETE RESTRICT,
  profile_snapshot jsonb NOT NULL,
  status           text NOT NULL DEFAULT 'QUEUED'
                   CHECK (status IN ('QUEUED','VALIDATING_SCOPE','RUNNING','COMPLETED','FAILED','TIMED_OUT','CANCELLED')),
  trigger_type     text NOT NULL DEFAULT 'MANUAL' CHECK (trigger_type IN ('MANUAL','SCHEDULE','API','WEBHOOK')),
  requested_by     uuid REFERENCES users(id) ON DELETE RESTRICT,
  idempotency_key  uuid,
  correlation_id   uuid NOT NULL,
  scheduled_at     timestamptz,
  queued_at        timestamptz NOT NULL DEFAULT now(),
  started_at       timestamptz,
  completed_at     timestamptz,
  error_detail     text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  deleted_at       timestamptz,
  CONSTRAINT uq_assessments_id_tenant UNIQUE (id, tenant_id),
  CONSTRAINT fk_assessments_project_tenant FOREIGN KEY (project_id, tenant_id) REFERENCES projects (id, tenant_id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_assessments_tenant_idem
  ON assessments (tenant_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_assessments_tenant_project_created
  ON assessments (tenant_id, project_id, created_at DESC, id DESC)
  WHERE deleted_at IS NULL;

DROP TRIGGER IF EXISTS set_updated_assessments ON assessments;
CREATE TRIGGER set_updated_assessments BEFORE UPDATE ON assessments
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ==============================================================================
-- 9. Jobs
-- ==============================================================================

CREATE TABLE IF NOT EXISTS jobs (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  assessment_id    uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  attempt          integer NOT NULL DEFAULT 1 CHECK (attempt >= 1),
  status           text NOT NULL DEFAULT 'QUEUED'
                   CHECK (status IN ('QUEUED','RUNNING','COMPLETED','FAILED','TIMED_OUT','CANCELLED')),
  worker_id        text,
  queue_job_id     text,
  priority         smallint NOT NULL DEFAULT 100,
  correlation_id   uuid NOT NULL,
  enqueued_at      timestamptz NOT NULL DEFAULT now(),
  started_at       timestamptz,
  finished_at      timestamptz,
  heartbeat_at     timestamptz,
  lease_expires_at timestamptz,
  exit_code        integer,
  error_ref        text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  deleted_at       timestamptz,
  CONSTRAINT uq_jobs_id_tenant UNIQUE (id, tenant_id),
  CONSTRAINT uq_jobs_assessment_attempt UNIQUE (assessment_id, attempt)
);

CREATE INDEX IF NOT EXISTS idx_jobs_active
  ON jobs (status, enqueued_at)
  WHERE status IN ('QUEUED','RUNNING');

CREATE INDEX IF NOT EXISTS idx_jobs_heartbeat
  ON jobs (heartbeat_at)
  WHERE status = 'RUNNING';

CREATE INDEX IF NOT EXISTS idx_jobs_queue_ref
  ON jobs (queue_job_id)
  WHERE queue_job_id IS NOT NULL;

DROP TRIGGER IF EXISTS set_updated_jobs ON jobs;
CREATE TRIGGER set_updated_jobs BEFORE UPDATE ON jobs
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ==============================================================================
-- 10. Findings (Hot-path entity)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS findings (
  id                uuid PRIMARY KEY,
  tenant_id         uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  project_id        uuid NOT NULL,
  assessment_id     uuid NOT NULL REFERENCES assessments(id) ON DELETE RESTRICT,
  job_id            uuid NOT NULL REFERENCES jobs(id) ON DELETE RESTRICT,
  asset_id          uuid REFERENCES assets(id) ON DELETE SET NULL,
  fingerprint       text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
  title             text NOT NULL,
  severity          text NOT NULL CHECK (severity IN ('INFORMATIONAL','LOW','MEDIUM','HIGH','CRITICAL')),
  confidence        numeric(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
  cvss_score        numeric(3,1) CHECK (cvss_score BETWEEN 0 AND 10),
  cwe_id            text,
  cve_ids           text[] NOT NULL DEFAULT '{}',
  status            text NOT NULL DEFAULT 'OPEN'
                    CHECK (status IN ('OPEN','CONFIRMED','FALSE_POSITIVE','RISK_ACCEPTED','RESOLVED')),
  affected_endpoint text,
  scanner_data      jsonb NOT NULL DEFAULT '{}'::jsonb,
  tags              text[] NOT NULL DEFAULT '{}',
  first_seen_at     timestamptz NOT NULL,
  last_seen_at      timestamptz NOT NULL,
  first_job_id      uuid NOT NULL REFERENCES jobs(id) ON DELETE RESTRICT,
  last_job_id       uuid REFERENCES jobs(id) ON DELETE SET NULL,
  occurrence_count  bigint NOT NULL DEFAULT 1,
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  deleted_at        timestamptz,
  CONSTRAINT uq_findings_id_tenant UNIQUE (id, tenant_id),
  CONSTRAINT uq_findings_project_fingerprint UNIQUE (project_id, fingerprint),
  CONSTRAINT fk_findings_project_tenant FOREIGN KEY (project_id, tenant_id) REFERENCES projects (id, tenant_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_findings_tenant_project_created_id_desc
  ON findings (tenant_id, project_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_findings_tenant_status_severity
  ON findings (tenant_id, status, severity)
  WHERE status IN ('OPEN','CONFIRMED');

CREATE INDEX IF NOT EXISTS idx_findings_tenant_last_seen
  ON findings (tenant_id, last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_findings_created_brin
  ON findings USING BRIN (created_at);

DROP TRIGGER IF EXISTS set_updated_findings ON findings;
CREATE TRIGGER set_updated_findings BEFORE UPDATE ON findings
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ==============================================================================
-- 11. Finding Events
-- ==============================================================================

CREATE TABLE IF NOT EXISTS finding_events (
  id            uuid PRIMARY KEY,
  tenant_id     uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  finding_id    uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  from_status   text CHECK (from_status IS NULL OR from_status IN ('OPEN','CONFIRMED','FALSE_POSITIVE','RISK_ACCEPTED','RESOLVED')),
  to_status     text NOT NULL CHECK (to_status IN ('OPEN','CONFIRMED','FALSE_POSITIVE','RISK_ACCEPTED','RESOLVED')),
  event_type    text NOT NULL CHECK (event_type IN ('CREATED','TRIAGE','REDETECTED','AUTO_REOPENED','MERGED')),
  actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  note          text,
  correlation_id uuid NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_finding_events_id_tenant UNIQUE (id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_finding_events_finding
  ON finding_events (finding_id, created_at);

-- ==============================================================================
-- 12. Evidence
-- ==============================================================================

CREATE TABLE IF NOT EXISTS evidence (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  finding_id       uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  job_id           uuid NOT NULL REFERENCES jobs(id) ON DELETE RESTRICT,
  evidence_type    text NOT NULL CHECK (evidence_type IN ('HTTP_EXCHANGE','HEADER_DUMP','SCREENSHOT','FILE','LOG')),
  object_key       text NOT NULL,
  content_type     text NOT NULL,
  size_bytes       bigint NOT NULL,
  checksum_sha256  text NOT NULL,
  redaction_status text NOT NULL DEFAULT 'PENDING' CHECK (redaction_status IN ('PENDING','COMPLETED','QUARANTINED')),
  redacted_preview text,
  deleted_object_at timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  deleted_at       timestamptz,
  CONSTRAINT uq_evidence_id_tenant UNIQUE (id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence (finding_id);
CREATE INDEX IF NOT EXISTS idx_evidence_pending
  ON evidence (created_at)
  WHERE redaction_status IN ('PENDING','QUARANTINED');

DROP TRIGGER IF EXISTS set_updated_evidence ON evidence;
CREATE TRIGGER set_updated_evidence BEFORE UPDATE ON evidence
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ==============================================================================
-- 13. Reports
-- ==============================================================================

CREATE TABLE IF NOT EXISTS reports (
  id              uuid PRIMARY KEY,
  tenant_id       uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  assessment_id   uuid NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  format          text NOT NULL CHECK (format IN ('PDF','JSON','CSV')),
  status          text NOT NULL DEFAULT 'GENERATING' CHECK (status IN ('GENERATING','READY','FAILED','EXPIRED')),
  object_key      text,
  size_bytes      bigint,
  checksum_sha256 text,
  generated_by    uuid REFERENCES users(id) ON DELETE SET NULL,
  expires_at      timestamptz NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  deleted_at      timestamptz,
  CONSTRAINT uq_reports_id_tenant UNIQUE (id, tenant_id)
);

DROP TRIGGER IF EXISTS set_updated_reports ON reports;
CREATE TRIGGER set_updated_reports BEFORE UPDATE ON reports
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ==============================================================================
-- 14. Audit Log
-- ==============================================================================

CREATE TABLE IF NOT EXISTS audit_log (
  id             uuid PRIMARY KEY,
  tenant_id      uuid REFERENCES tenants(id) ON DELETE RESTRICT,
  actor_user_id  uuid,
  actor_type     text NOT NULL CHECK (actor_type IN ('USER','SERVICE','WORKER','SYSTEM')),
  action         text NOT NULL,
  entity_type    text NOT NULL,
  entity_id      uuid,
  payload        jsonb NOT NULL DEFAULT '{}'::jsonb,
  correlation_id uuid NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_created_brin
  ON audit_log USING BRIN (created_at);

-- ==============================================================================
-- 15. Row Level Security Policies
-- ==============================================================================

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_users ON users;
CREATE POLICY tenant_isolation_users ON users
  TO kelvin_app
  USING (tenant_id = current_tenant_id() AND deleted_at IS NULL)
  WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE auth_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_auth_sessions ON auth_sessions;
CREATE POLICY tenant_isolation_auth_sessions ON auth_sessions
  TO kelvin_app
  USING (tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_projects ON projects;
CREATE POLICY tenant_isolation_projects ON projects
  TO kelvin_app
  USING (tenant_id = current_tenant_id() AND deleted_at IS NULL)
  WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE scan_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_profiles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_scan_profiles ON scan_profiles;
CREATE POLICY tenant_isolation_scan_profiles ON scan_profiles
  TO kelvin_app
  USING (tenant_id IS NULL OR tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_assets ON assets;
CREATE POLICY tenant_isolation_assets ON assets
  TO kelvin_app
  USING (tenant_id = current_tenant_id() AND deleted_at IS NULL)
  WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE assessments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_assessments ON assessments;
CREATE POLICY tenant_isolation_assessments ON assessments
  TO kelvin_app
  USING (tenant_id = current_tenant_id() AND deleted_at IS NULL)
  WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_jobs ON jobs;
CREATE POLICY tenant_isolation_jobs ON jobs
  TO kelvin_app
  USING (tenant_id = current_tenant_id() AND deleted_at IS NULL)
  WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_findings ON findings;
CREATE POLICY tenant_isolation_findings ON findings
  TO kelvin_app
  USING (tenant_id = current_tenant_id() AND deleted_at IS NULL)
  WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE finding_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_finding_events ON finding_events;
CREATE POLICY tenant_isolation_finding_events ON finding_events
  TO kelvin_app
  USING (tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_evidence ON evidence;
CREATE POLICY tenant_isolation_evidence ON evidence
  TO kelvin_app
  USING (tenant_id = current_tenant_id() AND deleted_at IS NULL)
  WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_reports ON reports;
CREATE POLICY tenant_isolation_reports ON reports
  TO kelvin_app
  USING (tenant_id = current_tenant_id() AND deleted_at IS NULL)
  WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_audit_log ON audit_log;
CREATE POLICY tenant_isolation_audit_log ON audit_log
  TO kelvin_app
  USING (tenant_id = current_tenant_id())
  WITH CHECK (tenant_id = current_tenant_id());

-- Grant privileges for app role
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO kelvin_app;
-- Revoke UPDATE/DELETE on audit_log per ADR-0002
REVOKE UPDATE, DELETE ON audit_log FROM kelvin_app;
GRANT INSERT ON audit_log TO kelvin_audit_writer;

