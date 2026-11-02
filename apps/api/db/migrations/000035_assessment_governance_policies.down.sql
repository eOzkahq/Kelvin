-- ==============================================================================
-- Migration: 000035_assessment_governance_policies.down.sql
-- Purpose: Revert Organization Assessment Governance Policies (P4-20)
-- ==============================================================================

DROP TABLE IF EXISTS assessment_governance_policies CASCADE;
