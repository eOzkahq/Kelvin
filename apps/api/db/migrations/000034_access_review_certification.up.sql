-- ==============================================================================
-- Migration: 000034_access_review_certification.up.sql
-- Purpose: Enterprise Access Review and Certification (P4-18)
-- Workstream: Workstream B (Enterprise Identity & Access Control)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS access_review_campaigns (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name               VARCHAR(255) NOT NULL,
  description        TEXT NOT NULL DEFAULT '',
  cadence            VARCHAR(50) NOT NULL DEFAULT 'QUARTERLY', -- QUARTERLY, ANNUAL, AD_HOC
  scope              VARCHAR(50) NOT NULL DEFAULT 'ORGANIZATION', -- ORGANIZATION, WORKSPACE, PRIVILEGED_ONLY
  status             VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, COMPLETED, CANCELLED
  created_by_user_id VARCHAR(255) NOT NULL,
  due_date           TIMESTAMPTZ NOT NULL,
  completed_at       TIMESTAMPTZ,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_access_review_campaigns_org
  ON access_review_campaigns (organization_id, status);

CREATE TABLE IF NOT EXISTS access_review_items (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  campaign_id            UUID NOT NULL REFERENCES access_review_campaigns(id) ON DELETE CASCADE,
  organization_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  target_user_id         VARCHAR(255) NOT NULL,
  target_user_email      VARCHAR(255) NOT NULL DEFAULT '',
  resource_type          VARCHAR(50) NOT NULL, -- ORG_ROLE, WORKSPACE_ROLE, TEAM_MEMBERSHIP, CUSTOM_ROLE, SERVICE_ACCOUNT
  resource_id            VARCHAR(255) NOT NULL,
  assigned_role          VARCHAR(100) NOT NULL,
  is_privileged          BOOLEAN NOT NULL DEFAULT false,
  decision               VARCHAR(50) NOT NULL DEFAULT 'PENDING', -- PENDING, RETAIN, REVOKE, INVESTIGATE
  decision_justification TEXT NOT NULL DEFAULT '',
  reviewed_by_user_id    VARCHAR(255),
  reviewed_at            TIMESTAMPTZ,
  action_taken           BOOLEAN NOT NULL DEFAULT false,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_access_review_items_campaign
  ON access_review_items (campaign_id, decision);
