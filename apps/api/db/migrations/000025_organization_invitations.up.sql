-- ==============================================================================
-- Migration: 000025_organization_invitations.up.sql
-- Purpose: Organization Membership and Invitation Management (P4-04)
-- Workstream: Workstream A (Organization & Team Administration)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS organization_invitations (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  inviter_user_id VARCHAR(255) NOT NULL,
  invitee_email   VARCHAR(255) NOT NULL,
  role            VARCHAR(50) NOT NULL DEFAULT 'MEMBER',
  team_id         UUID REFERENCES teams(id) ON DELETE SET NULL,
  token_hash      VARCHAR(64) NOT NULL UNIQUE,
  status          VARCHAR(50) NOT NULL DEFAULT 'PENDING',
  expires_at      TIMESTAMPTZ NOT NULL,
  accepted_at     TIMESTAMPTZ,
  revoked_at      TIMESTAMPTZ,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_org_invitations_org 
  ON organization_invitations(organization_id, status);

CREATE INDEX IF NOT EXISTS idx_org_invitations_email 
  ON organization_invitations(invitee_email);
