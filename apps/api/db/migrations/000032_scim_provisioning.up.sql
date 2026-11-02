-- ==============================================================================
-- Migration: 000032_scim_provisioning.up.sql
-- Purpose: SCIM 2.0 User and Group Provisioning (P4-16)
-- Workstream: Workstream B (Enterprise Identity & Access Control)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS scim_tokens (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  token_hash      VARCHAR(64) NOT NULL,
  description     VARCHAR(255) NOT NULL DEFAULT 'SCIM Bearer Token',
  expires_at      TIMESTAMPTZ,
  revoked_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_scim_token_hash UNIQUE (token_hash)
);

CREATE INDEX IF NOT EXISTS idx_scim_tokens_org
  ON scim_tokens (organization_id);

CREATE TABLE IF NOT EXISTS scim_users (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  external_id     VARCHAR(255) NOT NULL,
  user_name       VARCHAR(255) NOT NULL,
  formatted_name  VARCHAR(255) NOT NULL DEFAULT '',
  given_name      VARCHAR(255) NOT NULL DEFAULT '',
  family_name     VARCHAR(255) NOT NULL DEFAULT '',
  active          BOOLEAN NOT NULL DEFAULT true,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_scim_user_org_external UNIQUE (organization_id, external_id),
  CONSTRAINT uq_scim_user_org_username UNIQUE (organization_id, user_name)
);

CREATE INDEX IF NOT EXISTS idx_scim_users_org_active
  ON scim_users (organization_id, active);

CREATE TABLE IF NOT EXISTS scim_groups (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  display_name    VARCHAR(255) NOT NULL,
  external_id     VARCHAR(255) NOT NULL DEFAULT '',
  members         JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_scim_group_org_name UNIQUE (organization_id, display_name)
);

CREATE INDEX IF NOT EXISTS idx_scim_groups_org
  ON scim_groups (organization_id);
