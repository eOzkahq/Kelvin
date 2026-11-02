-- 000047_outbound_webhook_subscriptions.down.sql
-- Outbound Webhook Subscription Management (P4-32)

DROP TABLE IF EXISTS webhook_subscription_audit_logs CASCADE;
DROP TABLE IF EXISTS webhook_subscriptions CASCADE;
