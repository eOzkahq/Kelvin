-- 000043_service_accounts_and_machine_identities.down.sql
-- Machine Identity and Service Account Model (P4-28)

DROP TABLE IF EXISTS service_account_audit_logs CASCADE;
DROP TABLE IF EXISTS service_account_credentials CASCADE;
DROP TABLE IF EXISTS service_accounts CASCADE;
