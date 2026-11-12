-- ==============================================================================
-- Migration: 000017_evidence_domain.down.sql
-- Purpose: Revert evidence table
-- Workstream: Workstream D (Evidence Management & Auditability) - P3-26
-- ==============================================================================

DROP INDEX IF EXISTS idx_evidence_finding_lookup;
DROP INDEX IF EXISTS idx_evidence_assessment_lookup;
DROP INDEX IF EXISTS idx_evidence_expiry;
DROP POLICY IF EXISTS evidence_tenant_isolation ON evidence;
