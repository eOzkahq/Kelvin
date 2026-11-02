-- ==============================================================================
-- Migration: 000023_report_artifacts.up.sql
-- Purpose: Track rendered report artifacts with secure access, expiration and revocation
-- Workstream: Workstream F (Reporting, Search & User Experience) - P3-43
-- ==============================================================================

CREATE TABLE IF NOT EXISTS report_artifacts (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  report_id         UUID NOT NULL REFERENCES report_snapshots(report_id) ON DELETE CASCADE,
  assessment_id     UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  format            VARCHAR(20) NOT NULL, -- 'HTML', 'PDF'
  storage_path      VARCHAR(500) NOT NULL,
  sha256_checksum   VARCHAR(64) NOT NULL,
  size_bytes        BIGINT NOT NULL,
  expires_at        TIMESTAMPTZ,
  is_revoked        BOOLEAN NOT NULL DEFAULT false,
  revocation_reason TEXT,
  revoked_at        TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_report_format UNIQUE (tenant_id, report_id, format)
);

-- 1. Enable Row-Level Security
ALTER TABLE report_artifacts ENABLE ROW LEVEL SECURITY;

-- 2. Restrictive Tenant Isolation Policy (ADR-0002)
CREATE POLICY report_artifacts_tenant_isolation ON report_artifacts
  AS RESTRICTIVE
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 3. Composite performance indexes
CREATE INDEX IF NOT EXISTS idx_report_artifacts_tenant_report
  ON report_artifacts (tenant_id, report_id);

CREATE INDEX IF NOT EXISTS idx_report_artifacts_tenant_assessment
  ON report_artifacts (tenant_id, assessment_id);
