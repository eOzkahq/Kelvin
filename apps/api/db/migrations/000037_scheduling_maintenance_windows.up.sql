-- ==============================================================================
-- Migration: 000037_scheduling_maintenance_windows.up.sql
-- Purpose: Assessment Scheduling and Maintenance-Window Policies (P4-22)
-- Workstream: Workstream C (Policy & Workflow Governance)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS scheduling_windows (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name                 VARCHAR(255) NOT NULL,
  window_type          VARCHAR(50) NOT NULL, -- MAINTENANCE, BLACKOUT
  time_zone            VARCHAR(100) NOT NULL DEFAULT 'UTC',
  days_of_week         JSONB NOT NULL DEFAULT '[1,2,3,4,5]'::jsonb, -- 1=Monday ... 7=Sunday
  start_time           VARCHAR(5) NOT NULL, -- "HH:MM"
  end_time             VARCHAR(5) NOT NULL, -- "HH:MM"
  blackout_action      VARCHAR(50) NOT NULL DEFAULT 'HOLD', -- HOLD, CANCEL
  applies_to_manual    BOOLEAN NOT NULL DEFAULT true,
  applies_to_scheduled BOOLEAN NOT NULL DEFAULT true,
  status               VARCHAR(50) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, DISABLED
  created_at           TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_scheduling_windows_org
  ON scheduling_windows (organization_id, status);
