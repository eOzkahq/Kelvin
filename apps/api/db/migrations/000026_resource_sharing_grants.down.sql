-- ==============================================================================
-- Migration: 000026_resource_sharing_grants.down.sql
-- Purpose: Revert Controlled Resource Sharing Across Teams (P4-06)
-- ==============================================================================

DROP TABLE IF EXISTS resource_sharing_grants CASCADE;
