-- ==============================================================================
-- Migration: 000031_enterprise_domains_jit.down.sql
-- Purpose: Revert Enterprise Domain Verification and JIT Provisioning (P4-15)
-- ==============================================================================

DROP TABLE IF EXISTS organization_domains CASCADE;
