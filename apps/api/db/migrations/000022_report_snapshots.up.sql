-- ==============================================================================
-- Migration: 000022_report_snapshots.up.sql
-- Purpose: Create report_snapshots table for point-in-time frozen report documents
-- Workstream: Workstream F (Reporting, Search & User Experience) - P3-41
-- ==============================================================================

CREATE TABLE IF NOT EXISTS report_snapshots (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  assessment_id     UUID NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
  report_id         UUID NOT NULL UNIQUE,
  title             VARCHAR(255) NOT NULL,
  schema_version    VARCHAR(50) NOT NULL DEFAULT '1.0',
  template_version  VARCHAR(100) NOT NULL,
  snapshot_data     JSONB NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- 1. Enable Row-Level Security
ALTER TABLE report_snapshots ENABLE ROW LEVEL SECURITY;

-- 2. Restrictive Tenant Isolation Policy (ADR-0002)
CREATE POLICY report_snapshots_tenant_isolation ON report_snapshots
  AS RESTRICTIVE
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 3. Composite performance indexes
CREATE INDEX IF NOT EXISTS idx_report_snapshots_tenant_assessment
  ON report_snapshots (tenant_id, assessment_id);

CREATE INDEX IF NOT EXISTS idx_report_snapshots_tenant_created
  ON report_snapshots (tenant_id, created_at DESC);
