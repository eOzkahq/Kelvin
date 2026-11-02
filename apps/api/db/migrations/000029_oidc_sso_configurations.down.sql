-- ==============================================================================
-- Migration: 000029_oidc_sso_configurations.down.sql
-- Purpose: Revert OpenID Connect Enterprise SSO Configuration (P4-13)
-- ==============================================================================

DROP TABLE IF EXISTS oidc_configurations CASCADE;
