-- 000046_integration_connections_and_secrets.down.sql
-- Secure Integration Connection and Secret Management (P4-31)

DROP TABLE IF EXISTS integration_connection_audit_logs CASCADE;
DROP TABLE IF EXISTS integration_connections CASCADE;
