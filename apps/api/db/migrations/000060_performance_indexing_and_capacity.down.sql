-- Migration 000060 (Down): Remove performance indexing

BEGIN;

DROP INDEX IF EXISTS idx_findings_org_severity_status_created;
DROP INDEX IF EXISTS idx_assessment_findings_composite;
DROP INDEX IF EXISTS idx_evidence_finding_created;
DROP INDEX IF EXISTS idx_audit_events_org_timestamp;
DROP INDEX IF EXISTS idx_assessments_status_scheduled;

COMMIT;
