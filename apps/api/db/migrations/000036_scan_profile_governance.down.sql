-- ==============================================================================
-- Migration: 000036_scan_profile_governance.down.sql
-- Purpose: Revert Scan Profile Approval and Governance (P4-21)
-- ==============================================================================

DROP TABLE IF EXISTS scan_profile_snapshots CASCADE;
DROP INDEX IF EXISTS idx_scan_profiles_lookup;
