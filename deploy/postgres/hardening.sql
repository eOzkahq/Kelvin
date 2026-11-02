-- KELVIN Production Database Hardening & Role Segregation Script
-- Standard: CIS PostgreSQL 16 Benchmark & Phase 5 Hardening Specification

BEGIN;

-- 1. Restrict default PUBLIC schema creation privileges
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE kelvin FROM PUBLIC;

-- 2. Define Least-Privilege Roles
-- Role A: Migration Admin (Used strictly during CI/CD deployment migrations)
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kelvin_migrator') THEN
    CREATE ROLE kelvin_migrator WITH LOGIN INHERIT;
  END IF;
END $$;

-- Role B: Runtime Application (Used by Go API & Worker processes)
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kelvin_app') THEN
    CREATE ROLE kelvin_app WITH LOGIN NOINHERIT;
  END IF;
END $$;

-- Role C: Read-Only Compliance Auditor
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kelvin_auditor') THEN
    CREATE ROLE kelvin_auditor WITH LOGIN NOINHERIT;
  END IF;
END $$;

-- 3. Schema & Table Ownership
GRANT CONNECT ON DATABASE kelvin TO kelvin_migrator, kelvin_app, kelvin_auditor;
GRANT USAGE, CREATE ON SCHEMA public TO kelvin_migrator;
GRANT USAGE ON SCHEMA public TO kelvin_app, kelvin_auditor;

-- Set default search path
ALTER ROLE kelvin_migrator SET search_path TO public;
ALTER ROLE kelvin_app SET search_path TO public;
ALTER ROLE kelvin_auditor SET search_path TO public;

-- Set runtime resource and deadlock timeouts
ALTER ROLE kelvin_app SET statement_timeout = '30s';
ALTER ROLE kelvin_app SET idle_in_transaction_session_timeout = '60s';
ALTER ROLE kelvin_app SET lock_timeout = '10s';

-- 4. Granular DML Grants (kelvin_app has ZERO table creation/DDL rights)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO kelvin_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO kelvin_app;

ALTER DEFAULT PRIVILEGES FOR ROLE kelvin_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO kelvin_app;

ALTER DEFAULT PRIVILEGES FOR ROLE kelvin_migrator IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO kelvin_app;

-- 5. Read-Only Grants for Auditor
GRANT SELECT ON ALL TABLES IN SCHEMA public TO kelvin_auditor;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO kelvin_auditor;

ALTER DEFAULT PRIVILEGES FOR ROLE kelvin_migrator IN SCHEMA public
  GRANT SELECT ON TABLES TO kelvin_auditor;

COMMIT;
