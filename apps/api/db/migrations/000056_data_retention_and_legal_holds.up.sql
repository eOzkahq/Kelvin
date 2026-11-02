-- 000056_data_retention_and_legal_holds.up.sql

CREATE TABLE IF NOT EXISTS data_retention_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL UNIQUE REFERENCES tenants(id) ON DELETE CASCADE,
    evidence_retention_days INT NOT NULL DEFAULT 90,
    assessment_retention_days INT NOT NULL DEFAULT 365,
    finding_retention_days INT NOT NULL DEFAULT 730,
    report_retention_days INT NOT NULL DEFAULT 365,
    audit_retention_days INT NOT NULL DEFAULT 365,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS legal_holds (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    reason TEXT NOT NULL,
    target_type VARCHAR(64) NOT NULL, -- 'TENANT', 'PROJECT', 'ASSESSMENT'
    target_id VARCHAR(255),
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE', -- 'ACTIVE', 'RELEASED'
    created_by VARCHAR(255) NOT NULL,
    released_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_legal_holds_tenant ON legal_holds(tenant_id, status);

CREATE TABLE IF NOT EXISTS data_retention_purge_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    records_scanned INT NOT NULL,
    records_purged INT NOT NULL,
    records_held INT NOT NULL DEFAULT 0,
    evidence_bytes_reclaimed BIGINT NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL, -- 'SUCCESS', 'PARTIAL', 'FAILED'
    details TEXT,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_retention_purges_tenant ON data_retention_purge_executions(tenant_id, executed_at DESC);
