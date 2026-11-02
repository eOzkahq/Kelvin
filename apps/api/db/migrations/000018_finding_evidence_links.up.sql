-- ==============================================================================
-- Migration: 000018_finding_evidence_links.up.sql
-- Purpose: Create junction table linking persistent findings to evidence items
-- Workstream: Workstream D (Evidence Management & Auditability) - P3-27
-- ==============================================================================

CREATE TABLE IF NOT EXISTS finding_evidence_links (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL,
  finding_id      UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  evidence_id     UUID NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
  observation_id  UUID,
  is_primary      BOOLEAN NOT NULL DEFAULT false,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_finding_evidence UNIQUE (tenant_id, finding_id, evidence_id)
);

-- 1. Enable Row-Level Security
ALTER TABLE finding_evidence_links ENABLE ROW LEVEL SECURITY;

-- 2. Restrictive Tenant Isolation Policy (ADR-0002)
CREATE POLICY finding_evidence_links_tenant_isolation ON finding_evidence_links
  AS RESTRICTIVE
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 3. High performance composite indexes
CREATE INDEX IF NOT EXISTS idx_finding_evidence_links_finding
  ON finding_evidence_links (tenant_id, finding_id);

CREATE INDEX IF NOT EXISTS idx_finding_evidence_links_evidence
  ON finding_evidence_links (tenant_id, evidence_id);
