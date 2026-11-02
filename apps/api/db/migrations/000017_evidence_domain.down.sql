-- ==============================================================================
-- Migration: 000017_evidence_domain.down.sql
-- Purpose: Revert evidence table
-- Workstream: Workstream D (Evidence Management & Auditability) - P3-26
-- ==============================================================================

DROP TABLE IF EXISTS evidence CASCADE;
