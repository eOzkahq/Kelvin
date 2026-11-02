-- 000054_audit_integrity_chains_and_checkpoints.down.sql

DROP TABLE IF EXISTS audit_integrity_alerts;
DROP TABLE IF EXISTS audit_checkpoints;

DROP INDEX IF EXISTS idx_audit_log_tenant_seq;

ALTER TABLE audit_log 
    DROP COLUMN IF EXISTS current_hash,
    DROP COLUMN IF EXISTS previous_hash,
    DROP COLUMN IF EXISTS sequence_num;
