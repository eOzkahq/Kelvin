-- ==============================================================================
-- Migration: 000023_report_artifacts.down.sql
-- Purpose: Rollback report_artifacts table
-- Workstream: Workstream F (Reporting, Search & User Experience) - P3-43
-- ==============================================================================

DROP POLICY IF EXISTS report_artifacts_tenant_isolation ON report_artifacts;
DROP TABLE IF EXISTS report_artifacts;
