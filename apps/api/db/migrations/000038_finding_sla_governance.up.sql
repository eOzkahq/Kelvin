-- ==============================================================================
-- Migration: 000038_finding_sla_governance.up.sql
-- Purpose: Finding SLA and Priority Governance (P4-23)
-- Workstream: Workstream C (Policy & Workflow Governance)
-- ==============================================================================

CREATE TABLE IF NOT EXISTS sla_policies (
  id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id             UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name                        VARCHAR(255) NOT NULL DEFAULT 'Default SLA Policy',
  critical_remediation_days   INTEGER NOT NULL DEFAULT 7,
  high_remediation_days       INTEGER NOT NULL DEFAULT 30,
  medium_remediation_days     INTEGER NOT NULL DEFAULT 90,
  low_remediation_days        INTEGER NOT NULL DEFAULT 180,
  critical_triage_hours       INTEGER NOT NULL DEFAULT 24,
  high_triage_hours           INTEGER NOT NULL DEFAULT 72,
  pause_on_exception          BOOLEAN NOT NULL DEFAULT true,
  pause_on_verification       BOOLEAN NOT NULL DEFAULT true,
  version                     INTEGER NOT NULL DEFAULT 1,
  status                      VARCHAR(50) NOT NULL DEFAULT 'ACTIVE',
  created_at                  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at                  TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_sla_policy_org UNIQUE (organization_id)
);

CREATE TABLE IF NOT EXISTS finding_sla_trackers (
  id                             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id                     UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  organization_id                UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  policy_version                 INTEGER NOT NULL DEFAULT 1,
  clock_started_at               TIMESTAMPTZ NOT NULL,
  triage_due_at                  TIMESTAMPTZ NOT NULL,
  remediation_due_at             TIMESTAMPTZ NOT NULL,
  paused_at                      TIMESTAMPTZ,
  total_paused_duration_seconds  INTEGER NOT NULL DEFAULT 0,
  triage_status                  VARCHAR(50) NOT NULL DEFAULT 'ON_TRACK', -- ON_TRACK, MET, BREACHED
  remediation_status             VARCHAR(50) NOT NULL DEFAULT 'ON_TRACK', -- ON_TRACK, MET, BREACHED, PAUSED, EXEMPTED
  created_at                     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  updated_at                     TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT uq_finding_sla UNIQUE (finding_id)
);

CREATE INDEX IF NOT EXISTS idx_finding_sla_status
  ON finding_sla_trackers (organization_id, remediation_status);
