-- 000051_collaboration_notifications.up.sql
CREATE TABLE IF NOT EXISTS collaboration_destinations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    platform VARCHAR(32) NOT NULL, -- 'slack', 'msteams'
    name VARCHAR(255) NOT NULL,
    webhook_url TEXT NOT NULL,
    channel_name VARCHAR(255) NOT NULL DEFAULT '',
    subscribed_events JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(32) NOT NULL DEFAULT 'active', -- 'active', 'disabled', 'revoked'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_collab_dest_org ON collaboration_destinations(organization_id, status);

CREATE TABLE IF NOT EXISTS collaboration_notification_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    destination_id UUID NOT NULL REFERENCES collaboration_destinations(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    event_type VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL, -- 'delivered', 'failed', 'retrying'
    attempts INT NOT NULL DEFAULT 1,
    http_status INT,
    error_message TEXT,
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_collab_deliveries_dest ON collaboration_notification_deliveries(destination_id, created_at DESC);
