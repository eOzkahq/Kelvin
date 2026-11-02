-- ==============================================================================
-- Migration: 000031_enterprise_domains_jit.up.sql
-- Purpose: Enterprise Domain Verification and JIT Provisioning (P4-15)
-- Workstream: Workstream B (Enterprise Identity & Access Control)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS organization_domains (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  domain             VARCHAR(255) NOT NULL,
  verification_token VARCHAR(128) NOT NULL,
  status             VARCHAR(50) NOT NULL DEFAULT 'PENDING_VERIFICATION', -- PENDING_VERIFICATION, VERIFIED, EXPIRED, REVOKED
  jit_enabled        BOOLEAN NOT NULL DEFAULT true,
  default_role       VARCHAR(50) NOT NULL DEFAULT 'READ_ONLY_VIEWER',
  verified_at        TIMESTAMPTZ,
  expires_at         TIMESTAMPTZ,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_org_domain UNIQUE (organization_id, domain)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_active_verified_domain
  ON organization_domains (domain)
  WHERE status = 'VERIFIED';

CREATE INDEX IF NOT EXISTS idx_org_domains_lookup
  ON organization_domains (organization_id, status);
