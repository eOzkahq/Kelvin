-- ==============================================================================
-- Migration: 000030_saml_sso_configurations.up.sql
-- Purpose: SAML 2.0 Enterprise SSO Configuration (P4-14)
-- Workstream: Workstream B (Enterprise Identity & Access Control)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS saml_configurations (
  id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  idp_entity_id            VARCHAR(512) NOT NULL,
  sso_url                  VARCHAR(512) NOT NULL,
  sp_entity_id             VARCHAR(512) NOT NULL,
  acs_url                  VARCHAR(512) NOT NULL,
  idp_x509_cert            TEXT NOT NULL,
  idp_x509_cert_secondary  TEXT NOT NULL DEFAULT '',
  enabled                  BOOLEAN NOT NULL DEFAULT true,
  enforce_sso              BOOLEAN NOT NULL DEFAULT false,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_saml_org UNIQUE (organization_id)
);

CREATE INDEX IF NOT EXISTS idx_saml_configurations_org
  ON saml_configurations (organization_id);
