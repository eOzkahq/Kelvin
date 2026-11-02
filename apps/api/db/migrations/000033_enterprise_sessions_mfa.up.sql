-- ==============================================================================
-- Migration: 000033_enterprise_sessions_mfa.up.sql
-- Purpose: Enterprise Session and MFA Security Policies (P4-17)
-- Workstream: Workstream B (Enterprise Identity & Access Control)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS session_policies (
  id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id             UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  max_idle_minutes            INTEGER NOT NULL DEFAULT 15,
  max_lifetime_hours          INTEGER NOT NULL DEFAULT 12,
  max_concurrent_sessions      INTEGER NOT NULL DEFAULT 5,
  require_mfa                 BOOLEAN NOT NULL DEFAULT true,
  require_step_up_reauth      BOOLEAN NOT NULL DEFAULT true,
  reauth_grace_period_seconds INTEGER NOT NULL DEFAULT 300,
  created_at                  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at                  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_session_policy_org UNIQUE (organization_id)
);

CREATE TABLE IF NOT EXISTS user_sessions (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id         VARCHAR(64) NOT NULL,
  organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id            VARCHAR(255) NOT NULL,
  ip_address         VARCHAR(45) NOT NULL DEFAULT '',
  user_agent         TEXT NOT NULL DEFAULT '',
  mfa_verified       BOOLEAN NOT NULL DEFAULT false,
  last_activity_at   TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  last_reauth_at     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  status             VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, REVOKED, EXPIRED
  revocation_reason  VARCHAR(255) NOT NULL DEFAULT '',
  created_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  expires_at         TIMESTAMPTZ NOT NULL,
  CONSTRAINT uq_user_session_id UNIQUE (session_id)
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_lookup
  ON user_sessions (organization_id, user_id, status);
