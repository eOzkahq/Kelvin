-- ==============================================================================
-- Migration: 000021_remediation_tracking.up.sql
-- Purpose: Remediation tracking domain data model (tasks and update history)
-- Workstream: Workstream E (Assessment History & Remediation) - P3-36
-- ==============================================================================

CREATE TABLE IF NOT EXISTS remediation_tasks (
  id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id                   UUID NOT NULL,
  finding_id                  UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  title                       VARCHAR(255) NOT NULL,
  description                 TEXT NOT NULL DEFAULT '',
  recommended_action          TEXT NOT NULL DEFAULT '',
  state                       VARCHAR(50) NOT NULL DEFAULT 'OPEN',
  assigned_user_id            VARCHAR(255) NOT NULL DEFAULT '',
  target_completion_date      TIMESTAMPTZ,
  verification_assessment_id  UUID REFERENCES assessments(id) ON DELETE SET NULL,
  created_at                  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at                  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- 1. Enable Row-Level Security
ALTER TABLE remediation_tasks ENABLE ROW LEVEL SECURITY;

-- 2. Restrictive Tenant Isolation Policy (ADR-0002)
CREATE POLICY remediation_tasks_tenant_isolation ON remediation_tasks
  AS RESTRICTIVE
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 3. Query indexes
CREATE INDEX IF NOT EXISTS idx_remediation_tasks_tenant_finding
  ON remediation_tasks (tenant_id, finding_id);

CREATE INDEX IF NOT EXISTS idx_remediation_tasks_tenant_state
  ON remediation_tasks (tenant_id, state);

CREATE TABLE IF NOT EXISTS remediation_updates (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL,
  task_id         UUID NOT NULL REFERENCES remediation_tasks(id) ON DELETE CASCADE,
  author_id       VARCHAR(255) NOT NULL,
  comment         TEXT NOT NULL DEFAULT '',
  previous_state  VARCHAR(50) NOT NULL,
  new_state       VARCHAR(50) NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- 1. Enable Row-Level Security
ALTER TABLE remediation_updates ENABLE ROW LEVEL SECURITY;

-- 2. Restrictive Tenant Isolation Policy (ADR-0002)
CREATE POLICY remediation_updates_tenant_isolation ON remediation_updates
  AS RESTRICTIVE
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 3. Query index
CREATE INDEX IF NOT EXISTS idx_remediation_updates_task
  ON remediation_updates (tenant_id, task_id, created_at ASC);
