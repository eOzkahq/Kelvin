-- 000045_oauth_client_credentials.up.sql
-- OAuth 2.0 Client Credentials for Machine-to-Machine Access (P4-30)

CREATE TABLE IF NOT EXISTS oauth_issued_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_id VARCHAR(128) NOT NULL UNIQUE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    service_account_id UUID NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
    client_id VARCHAR(128) NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    is_revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_oauth_tokens_tid 
    ON oauth_issued_tokens (token_id);

CREATE INDEX IF NOT EXISTS idx_oauth_tokens_sa_revoked 
    ON oauth_issued_tokens (service_account_id, is_revoked);
