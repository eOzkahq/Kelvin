-- ==============================================================================
-- Revert Migration 000008: Extended Finding Lifecycle State Machine (P3-09)
-- ==============================================================================

ALTER TABLE finding_events
  DROP CONSTRAINT IF EXISTS finding_events_to_status_check;

ALTER TABLE finding_events
  ADD CONSTRAINT finding_events_to_status_check
  CHECK (to_status IN ('OPEN','CONFIRMED','FALSE_POSITIVE','RISK_ACCEPTED','RESOLVED'));

ALTER TABLE finding_events
  DROP CONSTRAINT IF EXISTS finding_events_from_status_check;

ALTER TABLE finding_events
  ADD CONSTRAINT finding_events_from_status_check
  CHECK (from_status IS NULL OR from_status IN ('OPEN','CONFIRMED','FALSE_POSITIVE','RISK_ACCEPTED','RESOLVED'));

ALTER TABLE findings
  DROP CONSTRAINT IF EXISTS findings_status_check;

ALTER TABLE findings
  ADD CONSTRAINT findings_status_check
  CHECK (status IN ('OPEN','CONFIRMED','FALSE_POSITIVE','RISK_ACCEPTED','RESOLVED'));
