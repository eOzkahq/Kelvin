-- ==============================================================================
-- Migration: 000036_scan_profile_governance.up.sql
-- Purpose: Scan Profile Approval and Governance (P4-21)
-- Workstream: Workstream C (Policy & Workflow Governance)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS scan_profiles (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name                VARCHAR(255) NOT NULL,
  slug                VARCHAR(100) NOT NULL,
  description         TEXT NOT NULL DEFAULT '',
  scanners            JSONB NOT NULL DEFAULT '[]'::jsonb,
  intensity           VARCHAR(50) NOT NULL DEFAULT 'NORMAL', -- PASSIVE, NORMAL, AGGRESSIVE, INVASIVE
  config              JSONB NOT NULL DEFAULT '{}'::jsonb,
  state               VARCHAR(50) NOT NULL DEFAULT 'DRAFT', -- DRAFT, PENDING_APPROVAL, APPROVED, ACTIVE, REJECTED, RETIRED
  version             INTEGER NOT NULL DEFAULT 1,
  requires_approval   BOOLEAN NOT NULL DEFAULT false,
  created_by_user_id  VARCHAR(255) NOT NULL,
  approved_by_user_id VARCHAR(255),
  approved_at         TIMESTAMPTZ,
  rejection_reason    TEXT NOT NULL DEFAULT '',
  created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_scan_profile_org_slug_version UNIQUE (organization_id, slug, version)
);

CREATE INDEX IF NOT EXISTS idx_scan_profiles_lookup
  ON scan_profiles (organization_id, state);

CREATE TABLE IF NOT EXISTS scan_profile_snapshots (
  id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  profile_id UUID NOT NULL REFERENCES scan_profiles(id) ON DELETE CASCADE,
  version    INTEGER NOT NULL,
  spec       JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_profile_version_snapshot UNIQUE (profile_id, version)
);
