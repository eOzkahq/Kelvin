-- ==============================================================================
-- Migration: 000033_enterprise_sessions_mfa.down.sql
-- Purpose: Revert Enterprise Session and MFA Security Policies (P4-17)
-- ==============================================================================

DROP TABLE IF EXISTS user_sessions CASCADE;
DROP TABLE IF EXISTS session_policies CASCADE;
