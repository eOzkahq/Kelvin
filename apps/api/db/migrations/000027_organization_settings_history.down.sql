-- ==============================================================================
-- Migration: 000027_organization_settings_history.down.sql
-- Purpose: Revert Organization-Level Settings and Configuration History (P4-07)
-- ==============================================================================

DROP TABLE IF EXISTS organization_settings_history CASCADE;
