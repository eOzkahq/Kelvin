-- 000049_integration_adapter_executions.up.sql
-- External Integration Adapter Framework (P4-34)

CREATE TABLE IF NOT EXISTS integration_adapter_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL REFERENCES integration_connections(id) ON DELETE CASCADE,
    provider VARCHAR(64) NOT NULL,
    action VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL CHECK (status IN ('SUCCESS', 'FAILED', 'RATE_LIMITED')),
    duration_ms BIGINT NOT NULL DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_adapter_exec_org_conn 
    ON integration_adapter_executions (organization_id, connection_id, created_at DESC);
