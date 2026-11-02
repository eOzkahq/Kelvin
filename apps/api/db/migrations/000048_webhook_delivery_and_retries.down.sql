-- 000048_webhook_delivery_and_retries.down.sql
-- Signed Webhook Delivery, Retry and Replay Protection (P4-33)

DROP TABLE IF EXISTS webhook_deliveries CASCADE;
