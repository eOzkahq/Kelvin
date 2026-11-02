-- ==============================================================================
-- Migration: 000025_organization_invitations.down.sql
-- Purpose: Revert Organization Membership and Invitation Management (P4-04)
-- ==============================================================================

DROP TABLE IF EXISTS organization_invitations CASCADE;
