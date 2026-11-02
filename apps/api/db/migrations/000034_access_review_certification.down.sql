-- ==============================================================================
-- Migration: 000034_access_review_certification.down.sql
-- Purpose: Revert Enterprise Access Review and Certification (P4-18)
-- ==============================================================================

DROP TABLE IF EXISTS access_review_items CASCADE;
DROP TABLE IF EXISTS access_review_campaigns CASCADE;
