-- ==============================================================================
-- Migration: 000021_remediation_tracking.down.sql
-- Purpose: Rollback remediation tracking data model
-- Workstream: Workstream E (Assessment History & Remediation) - P3-36
-- ==============================================================================

DROP POLICY IF EXISTS remediation_updates_tenant_isolation ON remediation_updates;
DROP TABLE IF EXISTS remediation_updates;

DROP POLICY IF EXISTS remediation_tasks_tenant_isolation ON remediation_tasks;
DROP TABLE IF EXISTS remediation_tasks;
