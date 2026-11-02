-- ==============================================================================
-- Migration 000011 Down: Revert Finding Triage Decisions
-- ==============================================================================

DROP TABLE IF EXISTS finding_triage_decisions CASCADE;
