-- ==============================================================================
-- Migration: 000017_evidence_domain.up.sql
-- Purpose: Create evidence table for application-level evidence management domain
-- Workstream: Workstream D (Evidence Management & Auditability) - P3-26
-- ==============================================================================

CREATE TABLE IF NOT EXISTS evidence (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           UUID NOT NULL,
  project_id          UUID NOT NULL,
  assessment_id       UUID NOT NULL,
  job_id              UUID NOT NULL,
  finding_id          UUID REFERENCES findings(id) ON DELETE SET NULL,
  observation_id      UUID,
  evidence_type       TEXT NOT NULL,
  provenance          TEXT NOT NULL DEFAULT 'RAW_SCANNER',
  content_type        TEXT NOT NULL,
  storage_ref         TEXT,
  inline_content      TEXT,
  checksum_sha256     TEXT NOT NULL,
  size_bytes          BIGINT NOT NULL,
  redaction_status    TEXT NOT NULL DEFAULT 'UNREDACTED_INTERNAL',
  redacted_fields     JSONB NOT NULL DEFAULT '[]'::jsonb,
  sensitivity_level   TEXT NOT NULL DEFAULT 'INTERNAL',
  status              TEXT NOT NULL DEFAULT 'ACTIVE',
  retention_days      INT NOT NULL DEFAULT 90,
  expires_at          TIMESTAMPTZ NOT NULL,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- 1. Enable PostgreSQL Row-Level Security (RLS)
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;

-- 2. Restrictive tenant isolation policy (ADR-0002)
CREATE POLICY evidence_tenant_isolation ON evidence
  AS RESTRICTIVE
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 3. Composite indexes for high-frequency finding and assessment queries
CREATE INDEX IF NOT EXISTS idx_evidence_finding_lookup
  ON evidence (tenant_id, finding_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_evidence_assessment_lookup
  ON evidence (tenant_id, assessment_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_evidence_expiry
  ON evidence (tenant_id, status, expires_at);
