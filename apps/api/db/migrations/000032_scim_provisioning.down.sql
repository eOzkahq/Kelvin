-- ==============================================================================
-- Migration: 000032_scim_provisioning.down.sql
-- Purpose: Revert SCIM 2.0 User and Group Provisioning (P4-16)
-- ==============================================================================

DROP TABLE IF EXISTS scim_groups CASCADE;
DROP TABLE IF EXISTS scim_users CASCADE;
DROP TABLE IF EXISTS scim_tokens CASCADE;
