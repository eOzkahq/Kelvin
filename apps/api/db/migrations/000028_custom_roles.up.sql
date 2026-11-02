-- ==============================================================================
-- Migration: 000028_custom_roles.up.sql
-- Purpose: Custom Role Creation and Management (P4-11)
-- Workstream: Workstream B (Enterprise Identity & Access Control)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS custom_roles (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name            VARCHAR(255) NOT NULL,
  slug            VARCHAR(100) NOT NULL,
  description     TEXT NOT NULL DEFAULT '',
  scope           VARCHAR(50) NOT NULL DEFAULT 'WORKSPACE', -- ORGANIZATION, WORKSPACE
  permissions     JSONB NOT NULL DEFAULT '[]'::jsonb,
  version         INTEGER NOT NULL DEFAULT 1,
  status          VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, ARCHIVED
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_custom_roles_org_slug UNIQUE (organization_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_custom_roles_org
  ON custom_roles (organization_id, status);
