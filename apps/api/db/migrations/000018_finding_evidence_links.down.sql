-- ==============================================================================
-- Migration: 000018_finding_evidence_links.down.sql
-- Purpose: Revert finding_evidence_links table
-- Workstream: Workstream D (Evidence Management & Auditability) - P3-27
-- ==============================================================================

DROP TABLE IF EXISTS finding_evidence_links CASCADE;
