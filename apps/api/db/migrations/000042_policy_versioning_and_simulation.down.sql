-- 000042_policy_versioning_and_simulation.down.sql
-- Policy Versioning, Simulation and Change Audit (P4-27)

DROP TABLE IF EXISTS policy_audit_logs CASCADE;
DROP TABLE IF EXISTS policy_simulation_runs CASCADE;
DROP TABLE IF EXISTS policy_definition_versions CASCADE;
