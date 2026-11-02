-- ==============================================================================
-- Migration: 000019_evidence_provenance_verification.down.sql
-- Purpose: Revert integrity tracking columns and audit table
-- Workstream: Workstream D (Evidence Management & Auditability) - P3-30
-- ==============================================================================

DROP TABLE IF EXISTS evidence_integrity_verifications CASCADE;

ALTER TABLE evidence
  DROP COLUMN IF EXISTS digest_algorithm,
  DROP COLUMN IF EXISTS integrity_status,
  DROP COLUMN IF EXISTS last_verified_at,
  DROP COLUMN IF EXISTS scanner_provenance;
