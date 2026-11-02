-- ==============================================================================
-- Migration: 000027_organization_settings_history.up.sql
-- Purpose: Organization-Level Settings and Versioned Configuration History (P4-07)
-- Workstream: Workstream A (Organization & Team Administration)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS organization_settings_history (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  version            INTEGER NOT NULL,
  settings           JSONB NOT NULL,
  changed_by_user_id VARCHAR(255) NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_org_settings_version UNIQUE (organization_id, version)
);

CREATE INDEX IF NOT EXISTS idx_org_settings_history_lookup
  ON organization_settings_history (organization_id, version DESC);
