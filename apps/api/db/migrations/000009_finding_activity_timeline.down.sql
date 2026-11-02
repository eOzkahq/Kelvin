-- ==============================================================================
-- Migration 000009 Down: Revert Immutable Finding Activity Timeline
-- ==============================================================================

DROP RULE IF EXISTS no_delete_finding_activity_timeline ON finding_activity_timeline;
DROP RULE IF EXISTS no_update_finding_activity_timeline ON finding_activity_timeline;
DROP TABLE IF EXISTS finding_activity_timeline CASCADE;
