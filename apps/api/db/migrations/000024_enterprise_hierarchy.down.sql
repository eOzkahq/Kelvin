-- ==============================================================================
-- Migration: 000024_enterprise_hierarchy.down.sql
-- Purpose: Revert Enterprise Organization, Workspace, and Team Hierarchy (P4-01)
-- ==============================================================================

DROP TABLE IF EXISTS workspace_team_grants CASCADE;
DROP TABLE IF EXISTS team_memberships CASCADE;
DROP TABLE IF EXISTS workspace_memberships CASCADE;
DROP TABLE IF EXISTS organization_memberships CASCADE;
DROP TABLE IF EXISTS teams CASCADE;
DROP TABLE IF EXISTS workspaces CASCADE;
DROP TABLE IF EXISTS organizations CASCADE;
