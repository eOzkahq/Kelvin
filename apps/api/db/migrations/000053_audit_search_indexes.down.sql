-- 000053_audit_search_indexes.down.sql

DROP INDEX IF EXISTS idx_audit_log_payload_gin;
DROP INDEX IF EXISTS idx_audit_log_tenant_correlation;
DROP INDEX IF EXISTS idx_audit_log_tenant_actor;
DROP INDEX IF EXISTS idx_audit_log_tenant_entity;
DROP INDEX IF EXISTS idx_audit_log_tenant_action;
DROP INDEX IF EXISTS idx_audit_log_tenant_created;
