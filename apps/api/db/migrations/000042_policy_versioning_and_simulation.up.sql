-- 000042_policy_versioning_and_simulation.up.sql
-- Policy Versioning, Simulation and Change Audit (P4-27)

CREATE TABLE IF NOT EXISTS policy_definition_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    policy_type VARCHAR(64) NOT NULL,
    version INT NOT NULL DEFAULT 1,
    status VARCHAR(32) NOT NULL CHECK (status IN ('DRAFT', 'PUBLISHED', 'ARCHIVED')),
    definition JSONB NOT NULL,
    author_id VARCHAR(255) NOT NULL,
    published_by VARCHAR(255),
    published_at TIMESTAMPTZ,
    change_summary TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_policy_org_type_version UNIQUE (organization_id, policy_type, version)
);

CREATE INDEX IF NOT EXISTS idx_policy_versions_org_type_status 
    ON policy_definition_versions (organization_id, policy_type, status);

CREATE TABLE IF NOT EXISTS policy_simulation_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    policy_version_id UUID NOT NULL REFERENCES policy_definition_versions(id) ON DELETE CASCADE,
    executed_by VARCHAR(255) NOT NULL,
    total_evaluated INT NOT NULL DEFAULT 0,
    allowed_count INT NOT NULL DEFAULT 0,
    denied_count INT NOT NULL DEFAULT 0,
    approval_required_count INT NOT NULL DEFAULT 0,
    conflicts_detected INT NOT NULL DEFAULT 0,
    impact_report JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_simulations_version 
    ON policy_simulation_runs (policy_version_id, created_at DESC);

CREATE TABLE IF NOT EXISTS policy_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    policy_version_id UUID REFERENCES policy_definition_versions(id) ON DELETE SET NULL,
    actor_id VARCHAR(255) NOT NULL,
    action VARCHAR(64) NOT NULL CHECK (action IN ('CREATE_DRAFT', 'UPDATE_DRAFT', 'SIMULATE', 'PUBLISH', 'ROLLBACK', 'ARCHIVE')),
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_policy_audit_org_created 
    ON policy_audit_logs (organization_id, created_at DESC);
