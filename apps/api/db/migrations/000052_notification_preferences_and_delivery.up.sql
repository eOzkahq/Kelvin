-- 000052_notification_preferences_and_delivery.up.sql

CREATE TABLE IF NOT EXISTS notification_org_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
    allowed_channels JSONB NOT NULL DEFAULT '["in_app", "email", "webhook", "collaboration"]'::jsonb,
    mandatory_events JSONB NOT NULL DEFAULT '["findings.critical", "policy.violation"]'::jsonb,
    channel_defaults JSONB NOT NULL DEFAULT '{"in_app": true, "email": true, "webhook": true, "collaboration": true}'::jsonb,
    quiet_hours_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    quiet_hours_start_utc INT NOT NULL DEFAULT 22,
    quiet_hours_end_utc INT NOT NULL DEFAULT 7,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS notification_user_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL,
    channel_overrides JSONB NOT NULL DEFAULT '{}'::jsonb,
    event_overrides JSONB NOT NULL DEFAULT '{}'::jsonb,
    quiet_hours_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    quiet_hours_start_utc INT NOT NULL DEFAULT 22,
    quiet_hours_end_utc INT NOT NULL DEFAULT 7,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_user_pref_org_user UNIQUE (organization_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_notif_user_pref_org ON notification_user_preferences(organization_id, user_id);

CREATE TABLE IF NOT EXISTS notification_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id VARCHAR(255),
    event_type VARCHAR(64) NOT NULL,
    channel VARCHAR(32) NOT NULL, -- 'in_app', 'email', 'webhook', 'collaboration'
    deduplication_key VARCHAR(255) NOT NULL,
    title VARCHAR(255) NOT NULL,
    sanitized_content TEXT NOT NULL,
    status VARCHAR(32) NOT NULL, -- 'delivered', 'suppressed', 'failed', 'queued'
    suppression_reason VARCHAR(128),
    error_message TEXT,
    delivered_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notif_logs_dedup ON notification_logs(organization_id, deduplication_key, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notif_logs_org_status ON notification_logs(organization_id, status, created_at DESC);
