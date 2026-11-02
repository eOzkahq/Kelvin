-- ==============================================================================
-- Migration 000010 Down: Revert Finding Correlation Groups
-- ==============================================================================

DROP TABLE IF EXISTS finding_correlation_group_members CASCADE;
DROP TABLE IF EXISTS finding_correlation_groups CASCADE;
