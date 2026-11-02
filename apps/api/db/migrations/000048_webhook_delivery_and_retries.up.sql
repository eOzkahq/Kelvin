-- 000048_webhook_delivery_and_retries.up.sql
-- Signed Webhook Delivery, Retry and Replay Protection (P4-33)

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL,
    subscription_id UUID NOT NULL REFERENCES webhook_subscriptions(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    event_type VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'SUCCESS', 'PENDING_RETRY', 'DEAD_LETTER')),
    attempts INT NOT NULL DEFAULT 0,
    last_status_code INT,
    last_error TEXT,
    response_snippet TEXT,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMPTZ,
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliv_event 
    ON webhook_deliveries (event_id);

CREATE INDEX IF NOT EXISTS idx_webhook_deliv_sub_status 
    ON webhook_deliveries (subscription_id, status);

CREATE INDEX IF NOT EXISTS idx_webhook_deliv_retry 
    ON webhook_deliveries (status, next_retry_at) 
    WHERE status = 'PENDING_RETRY';
