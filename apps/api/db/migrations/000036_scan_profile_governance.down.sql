-- ==============================================================================
-- Migration: 000036_scan_profile_governance.down.sql
-- Purpose: Revert Scan Profile Approval and Governance (P4-21)
-- ==============================================================================

DROP TABLE IF EXISTS scan_profile_snapshots CASCADE;
DROP TABLE IF EXISTS scan_profiles CASCADE;
