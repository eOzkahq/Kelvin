-- 000044_api_credentials_lifecycle.up.sql
-- API Credential and Key Lifecycle Management (P4-29)

CREATE TABLE IF NOT EXISTS api_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    service_account_id UUID REFERENCES service_accounts(id) ON DELETE CASCADE,
    user_id VARCHAR(255),
    name VARCHAR(255) NOT NULL,
    key_prefix VARCHAR(32) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED', 'COMPROMISED')),
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,
    last_used_ip VARCHAR(64),
    usage_count BIGINT NOT NULL DEFAULT 0,
    revoked_at TIMESTAMPTZ,
    revoked_by VARCHAR(255),
    revocation_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_cred_org_status 
    ON api_credentials (organization_id, status);

CREATE INDEX IF NOT EXISTS idx_api_cred_prefix 
    ON api_credentials (key_prefix);

CREATE INDEX IF NOT EXISTS idx_api_cred_hash 
    ON api_credentials (key_hash);
