-- 000053_audit_search_indexes.up.sql

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_created 
    ON audit_log (tenant_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_action 
    ON audit_log (tenant_id, action, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_entity 
    ON audit_log (tenant_id, entity_type, entity_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_actor 
    ON audit_log (tenant_id, actor_user_id, created_at DESC) 
    WHERE actor_user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_correlation 
    ON audit_log (tenant_id, correlation_id);

CREATE INDEX IF NOT EXISTS idx_audit_log_payload_gin 
    ON audit_log USING GIN (payload jsonb_path_ops);
