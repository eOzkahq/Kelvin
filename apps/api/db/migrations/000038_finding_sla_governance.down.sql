-- ==============================================================================
-- Migration: 000038_finding_sla_governance.down.sql
-- Purpose: Revert Finding SLA and Priority Governance (P4-23)
-- ==============================================================================

DROP TABLE IF EXISTS finding_sla_trackers CASCADE;
DROP TABLE IF EXISTS sla_policies CASCADE;
