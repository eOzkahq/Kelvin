-- ==============================================================================
-- Migration: 000020_evidence_retention_holds.down.sql
-- Purpose: Revert legal hold and retention columns
-- Workstream: Workstream D (Evidence Management & Auditability) - P3-32
-- ==============================================================================

DROP INDEX IF EXISTS idx_evidence_retention_sweep;

ALTER TABLE evidence
  DROP COLUMN IF EXISTS is_legal_hold,
  DROP COLUMN IF EXISTS legal_hold_reason,
  DROP COLUMN IF EXISTS wiped_at,
  DROP COLUMN IF EXISTS purge_retry_count;
