-- 000047_outbound_webhook_subscriptions.up.sql
-- Outbound Webhook Subscription Management (P4-32)

CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    endpoint_url TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DISABLED', 'SUSPENDED')),
    event_types JSONB NOT NULL DEFAULT '[]'::jsonb,
    encrypted_signing_secret BYTEA NOT NULL,
    encryption_nonce BYTEA NOT NULL,
    key_id VARCHAR(64) NOT NULL,
    creator_id VARCHAR(255) NOT NULL,
    consecutive_failures INT NOT NULL DEFAULT 0,
    last_dispatched_at TIMESTAMPTZ,
    last_delivery_status VARCHAR(32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_subs_org_status 
    ON webhook_subscriptions (organization_id, status);

CREATE TABLE IF NOT EXISTS webhook_subscription_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    subscription_id UUID NOT NULL REFERENCES webhook_subscriptions(id) ON DELETE CASCADE,
    actor_id VARCHAR(255) NOT NULL,
    action VARCHAR(64) NOT NULL CHECK (action IN ('CREATE', 'UPDATE', 'ROTATE_SECRET', 'DISABLE', 'ENABLE', 'DELETE', 'SUSPEND_FAILURE_THRESHOLD')),
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_sub_audit_sub 
    ON webhook_subscription_audit_logs (subscription_id, created_at DESC);
