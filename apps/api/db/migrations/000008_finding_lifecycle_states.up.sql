-- ==============================================================================
-- Migration 000008: Extended Finding Lifecycle State Machine (P3-09)
-- ==============================================================================

-- 1. Extend findings.status check constraint with canonical lifecycle states
ALTER TABLE findings
  DROP CONSTRAINT IF EXISTS findings_status_check;

ALTER TABLE findings
  ADD CONSTRAINT findings_status_check
  CHECK (status IN (
    'NEW',
    'OPEN',
    'CONFIRMED',
    'IN_PROGRESS',
    'RESOLVED',
    'REOPENED',
    'FALSE_POSITIVE',
    'RISK_ACCEPTED',
    'ACCEPTED_RISK'
  ));

-- 2. Extend finding_events constraints
ALTER TABLE finding_events
  DROP CONSTRAINT IF EXISTS finding_events_from_status_check;

ALTER TABLE finding_events
  ADD CONSTRAINT finding_events_from_status_check
  CHECK (from_status IS NULL OR from_status IN (
    'NEW',
    'OPEN',
    'CONFIRMED',
    'IN_PROGRESS',
    'RESOLVED',
    'REOPENED',
    'FALSE_POSITIVE',
    'RISK_ACCEPTED',
    'ACCEPTED_RISK'
  ));

ALTER TABLE finding_events
  DROP CONSTRAINT IF EXISTS finding_events_to_status_check;

ALTER TABLE finding_events
  ADD CONSTRAINT finding_events_to_status_check
  CHECK (to_status IN (
    'NEW',
    'OPEN',
    'CONFIRMED',
    'IN_PROGRESS',
    'RESOLVED',
    'REOPENED',
    'FALSE_POSITIVE',
    'RISK_ACCEPTED',
    'ACCEPTED_RISK'
  ));
