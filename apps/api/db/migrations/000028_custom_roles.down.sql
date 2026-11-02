-- ==============================================================================
-- Migration: 000028_custom_roles.down.sql
-- Purpose: Revert Custom Role Creation and Management (P4-11)
-- ==============================================================================

DROP TABLE IF EXISTS custom_roles CASCADE;
