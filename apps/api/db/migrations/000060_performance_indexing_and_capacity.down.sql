-- Migration 000060 (Down): Remove performance indexing

BEGIN;

DROP INDEX IF EXISTS idx_findings_tenant_severity_status_created;
DROP INDEX IF EXISTS idx_findings_tenant_assessment;
DROP INDEX IF EXISTS idx_evidence_finding_created;
DROP INDEX IF EXISTS idx_audit_log_tenant_timestamp;
DROP INDEX IF EXISTS idx_assessments_status_scheduled;

COMMIT;
