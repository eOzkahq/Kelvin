-- ==============================================================================
-- Migration: 000037_scheduling_maintenance_windows.down.sql
-- Purpose: Revert Assessment Scheduling and Maintenance-Window Policies (P4-22)
-- ==============================================================================

DROP TABLE IF EXISTS scheduling_windows CASCADE;
