-- Migration 000060: Production Performance Indexing and Capacity Optimization
-- Optimizes query execution plans identified during P5-16 load testing

BEGIN;

-- 1. High-speed multi-tenant triage filtering index
CREATE INDEX IF NOT EXISTS idx_findings_tenant_severity_status_created 
  ON findings (tenant_id, severity, status, created_at DESC);

-- 2. Assessment-to-finding join index for rapid report assembling & comparison
CREATE INDEX IF NOT EXISTS idx_findings_tenant_assessment 
  ON findings (tenant_id, assessment_id);

-- 3. Rapid evidence lookup index
CREATE INDEX IF NOT EXISTS idx_evidence_finding_created 
  ON evidence (tenant_id, finding_id, created_at DESC);

-- 4. Audit event timeline fast search index
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_timestamp 
  ON audit_log (tenant_id, created_at DESC);

-- 5. Active assessment queue scheduling index
CREATE INDEX IF NOT EXISTS idx_assessments_status_scheduled 
  ON assessments (status, scheduled_at ASC) 
  WHERE status = 'QUEUED';

COMMIT;
