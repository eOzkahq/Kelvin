-- ==============================================================================
-- Migration: 000022_report_snapshots.down.sql
-- Purpose: Rollback report_snapshots table
-- Workstream: Workstream F (Reporting, Search & User Experience) - P3-41
-- ==============================================================================

DROP POLICY IF EXISTS report_snapshots_tenant_isolation ON report_snapshots;
DROP TABLE IF EXISTS report_snapshots;
