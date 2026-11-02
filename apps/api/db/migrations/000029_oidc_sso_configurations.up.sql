-- ==============================================================================
-- Migration: 000029_oidc_sso_configurations.up.sql
-- Purpose: OpenID Connect Enterprise SSO Configuration (P4-13)
-- Workstream: Workstream B (Enterprise Identity & Access Control)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS oidc_configurations (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  issuer_url              VARCHAR(512) NOT NULL,
  client_id               VARCHAR(255) NOT NULL,
  client_secret_encrypted TEXT NOT NULL,
  redirect_uri            VARCHAR(512) NOT NULL,
  scopes                  JSONB NOT NULL DEFAULT '["openid", "profile", "email"]'::jsonb,
  enabled                 BOOLEAN NOT NULL DEFAULT true,
  enforce_sso             BOOLEAN NOT NULL DEFAULT false,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_oidc_org UNIQUE (organization_id)
);

CREATE INDEX IF NOT EXISTS idx_oidc_configurations_org
  ON oidc_configurations (organization_id);
