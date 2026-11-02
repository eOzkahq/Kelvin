-- ==============================================================================
-- Migration: 000024_enterprise_hierarchy.up.sql
-- Purpose: Enterprise Organization, Workspace, and Team Hierarchy (P4-01)
-- Workstream: Workstream A (Organization & Team Administration)
-- ==============================================================================

-- 1. Organizations table (Enterprise Root Entity)
CREATE TABLE IF NOT EXISTS organizations (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name         VARCHAR(255) NOT NULL,
  slug         VARCHAR(100) NOT NULL UNIQUE,
  billing_tier VARCHAR(50) NOT NULL DEFAULT 'ENTERPRISE',
  status       VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
  settings     JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- 2. Workspaces table (Operational Environment Boundary -> maps 1:1 to Tenant)
CREATE TABLE IF NOT EXISTS workspaces (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  tenant_id       UUID NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
  name            VARCHAR(255) NOT NULL,
  slug            VARCHAR(100) NOT NULL,
  environment     VARCHAR(50) NOT NULL DEFAULT 'production',
  status          VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_workspaces_org_slug UNIQUE (organization_id, slug)
);

-- 3. Teams table (User groups within Organization)
CREATE TABLE IF NOT EXISTS teams (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name            VARCHAR(255) NOT NULL,
  slug            VARCHAR(100) NOT NULL,
  description     TEXT NOT NULL DEFAULT '',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_teams_org_slug UNIQUE (organization_id, slug)
);

-- 4. Organization Memberships (Global Org-Level Roles)
CREATE TABLE IF NOT EXISTS organization_memberships (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id         VARCHAR(255) NOT NULL,
  role            VARCHAR(50) NOT NULL DEFAULT 'MEMBER',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_org_membership_user UNIQUE (organization_id, user_id)
);

-- 5. Workspace Memberships (Workspace-Scoped Access Roles)
CREATE TABLE IF NOT EXISTS workspace_memberships (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id    UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id         VARCHAR(255) NOT NULL,
  role            VARCHAR(50) NOT NULL DEFAULT 'VIEWER',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_workspace_membership_user UNIQUE (workspace_id, user_id)
);

-- 6. Team Memberships
CREATE TABLE IF NOT EXISTS team_memberships (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id    UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id    VARCHAR(255) NOT NULL,
  role       VARCHAR(50) NOT NULL DEFAULT 'MEMBER',
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_team_membership_user UNIQUE (team_id, user_id)
);

-- 7. Team-to-Workspace Role Bindings (Team Access Grants)
CREATE TABLE IF NOT EXISTS workspace_team_grants (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  team_id      UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  role         VARCHAR(50) NOT NULL DEFAULT 'VIEWER',
  created_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_workspace_team_grant UNIQUE (workspace_id, team_id)
);

-- 8. Enable Row-Level Security on Workspaces and Workspace-scoped memberships
ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspaces_tenant_isolation ON workspaces
  AS RESTRICTIVE
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

ALTER TABLE workspace_memberships ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_memberships_isolation ON workspace_memberships
  AS RESTRICTIVE
  FOR ALL
  USING (workspace_id IN (
    SELECT w.id FROM workspaces w WHERE w.tenant_id = current_setting('app.current_tenant_id', true)::uuid
  ));

ALTER TABLE workspace_team_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY workspace_team_grants_isolation ON workspace_team_grants
  AS RESTRICTIVE
  FOR ALL
  USING (workspace_id IN (
    SELECT w.id FROM workspaces w WHERE w.tenant_id = current_setting('app.current_tenant_id', true)::uuid
  ));

-- 9. Backfill existing tenants into default organizations and workspaces
INSERT INTO organizations (id, name, slug, billing_tier, status)
SELECT 
  id, 
  name || ' Organization', 
  slug || '-org', 
  'ENTERPRISE', 
  status
FROM tenants
ON CONFLICT (slug) DO NOTHING;

INSERT INTO workspaces (id, organization_id, tenant_id, name, slug, environment, status)
SELECT 
  gen_random_uuid(), 
  id, 
  id, 
  name || ' Default Workspace', 
  slug || '-default', 
  'production', 
  status
FROM tenants
ON CONFLICT (tenant_id) DO NOTHING;
