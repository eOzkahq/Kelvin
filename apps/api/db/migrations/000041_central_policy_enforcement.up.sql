-- 000041_central_policy_enforcement.up.sql
-- Central Policy Enforcement Across Application Boundaries (P4-26)

CREATE TABLE IF NOT EXISTS policy_enforcement_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    enforcement_point VARCHAR(64) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    subject_id VARCHAR(255) NOT NULL,
    decision VARCHAR(32) NOT NULL CHECK (decision IN ('ALLOW', 'DENY', 'REQUIRE_APPROVAL', 'TERMINATE_JOB')),
    matched_rule_id VARCHAR(255),
    policy_version INT NOT NULL DEFAULT 1,
    reason TEXT,
    audit_trace JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_enforcement_records_org_point 
    ON policy_enforcement_records (organization_id, enforcement_point, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_enforcement_records_resource 
    ON policy_enforcement_records (resource_id);
