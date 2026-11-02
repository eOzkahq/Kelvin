-- ==============================================================================
-- Migration: 000020_evidence_retention_holds.up.sql
-- Purpose: Add legal hold flags and wiped timestamp for retention enforcement
-- Workstream: Workstream D (Evidence Management & Auditability) - P3-32
-- ==============================================================================

ALTER TABLE evidence
  ADD COLUMN IF NOT EXISTS is_legal_hold BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS legal_hold_reason TEXT,
  ADD COLUMN IF NOT EXISTS wiped_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS purge_retry_count INT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_evidence_retention_sweep
  ON evidence (status, is_legal_hold, expires_at);
