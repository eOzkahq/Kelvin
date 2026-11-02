-- 000046_integration_connections_and_secrets.up.sql
-- Secure Integration Connection and Secret Management (P4-31)

CREATE TABLE IF NOT EXISTS integration_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    provider VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DISABLED', 'ERROR')),
    endpoint_url TEXT NOT NULL,
    encrypted_secret_payload BYTEA NOT NULL,
    encryption_nonce BYTEA NOT NULL,
    key_id VARCHAR(64) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    creator_id VARCHAR(255) NOT NULL,
    owner_id VARCHAR(255) NOT NULL,
    last_sync_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_integration_connections_org_status 
    ON integration_connections (organization_id, status);

CREATE TABLE IF NOT EXISTS integration_connection_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL REFERENCES integration_connections(id) ON DELETE CASCADE,
    actor_id VARCHAR(255) NOT NULL,
    action VARCHAR(64) NOT NULL CHECK (action IN ('CREATE', 'UPDATE', 'ROTATE_SECRET', 'DISABLE', 'ENABLE', 'DELETE', 'INVOKE_SUCCESS', 'INVOKE_BLOCKED_SSRF', 'INVOKE_FAILED')),
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_integration_audit_conn 
    ON integration_connection_audit_logs (connection_id, created_at DESC);
