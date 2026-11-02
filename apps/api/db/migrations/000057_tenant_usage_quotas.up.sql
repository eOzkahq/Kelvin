-- 000057_tenant_usage_quotas.up.sql

CREATE TABLE IF NOT EXISTS tenant_quotas (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    max_concurrent_scans INT NOT NULL DEFAULT 5,
    max_monthly_scan_hours INT NOT NULL DEFAULT 100,
    max_storage_gb INT NOT NULL DEFAULT 50,
    max_service_identities INT NOT NULL DEFAULT 20,
    max_monthly_events INT NOT NULL DEFAULT 10000,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tenant_usage_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    billing_period VARCHAR(7) NOT NULL, -- 'YYYY-MM'
    dimension VARCHAR(64) NOT NULL,
    current_value NUMERIC(14, 2) NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_tenant_usage_period UNIQUE (tenant_id, billing_period, dimension)
);

CREATE INDEX IF NOT EXISTS idx_tenant_usage_period ON tenant_usage_snapshots(tenant_id, billing_period);
