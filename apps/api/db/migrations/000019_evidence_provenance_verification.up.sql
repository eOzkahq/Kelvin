-- ==============================================================================
-- Migration: 000019_evidence_provenance_verification.up.sql
-- Purpose: Add integrity tracking columns and verification audit table
-- Workstream: Workstream D (Evidence Management & Auditability) - P3-30
-- ==============================================================================

ALTER TABLE evidence
  ADD COLUMN IF NOT EXISTS digest_algorithm TEXT NOT NULL DEFAULT 'SHA-256',
  ADD COLUMN IF NOT EXISTS integrity_status TEXT NOT NULL DEFAULT 'VERIFIED',
  ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS scanner_provenance JSONB NOT NULL DEFAULT '{}'::jsonb;

CREATE TABLE IF NOT EXISTS evidence_integrity_verifications (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  evidence_id       UUID NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
  status            TEXT NOT NULL,
  expected_digest   TEXT NOT NULL,
  calculated_digest TEXT,
  verified_by       TEXT NOT NULL,
  details           TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

-- Enable Row-Level Security
ALTER TABLE evidence_integrity_verifications ENABLE ROW LEVEL SECURITY;

CREATE POLICY evidence_integrity_verifications_tenant_isolation ON evidence_integrity_verifications
  AS RESTRICTIVE
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

CREATE INDEX IF NOT EXISTS idx_evidence_verifications_lookup
  ON evidence_integrity_verifications (tenant_id, evidence_id, created_at DESC);
