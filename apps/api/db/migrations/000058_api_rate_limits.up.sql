-- 000058_api_rate_limits.up.sql

CREATE TABLE IF NOT EXISTS tenant_rate_limit_configs (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    standard_limit_per_minute INT NOT NULL DEFAULT 100,
    expensive_limit_per_minute INT NOT NULL DEFAULT 10,
    burst_capacity INT NOT NULL DEFAULT 20,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rate_limit_violations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_id VARCHAR(255) NOT NULL,
    operation_category VARCHAR(64) NOT NULL,
    client_ip VARCHAR(45) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_violations_tenant ON rate_limit_violations(tenant_id, occurred_at DESC);
