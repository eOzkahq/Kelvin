-- ==============================================================================
-- Migration: 000030_saml_sso_configurations.down.sql
-- Purpose: Revert SAML 2.0 Enterprise SSO Configuration (P4-14)
-- ==============================================================================

DROP TABLE IF EXISTS saml_configurations CASCADE;
