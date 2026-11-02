-- ==============================================================================
-- Migration: 000026_resource_sharing_grants.up.sql
-- Purpose: Controlled Resource Sharing Across Teams (P4-06)
-- Workstream: Workstream A (Organization & Team Administration)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS resource_sharing_grants (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  resource_type       VARCHAR(50) NOT NULL, -- SCAN_PROFILE, REPORT, FINDING
  resource_id         UUID NOT NULL,
  source_workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  target_type         VARCHAR(50) NOT NULL, -- TEAM, WORKSPACE
  target_id           UUID NOT NULL,
  access_level        VARCHAR(50) NOT NULL DEFAULT 'READ', -- READ, EXECUTE
  granted_by_user_id  VARCHAR(255) NOT NULL,
  status              VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, REVOKED, EXPIRED
  expires_at          TIMESTAMPTZ,
  revoked_at          TIMESTAMPTZ,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_sharing_grants_lookup
  ON resource_sharing_grants (organization_id, resource_type, resource_id, status);

CREATE INDEX IF NOT EXISTS idx_sharing_grants_target
  ON resource_sharing_grants (target_type, target_id, status);
