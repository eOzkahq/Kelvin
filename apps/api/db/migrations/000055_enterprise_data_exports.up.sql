-- 000055_enterprise_data_exports.up.sql

CREATE TABLE IF NOT EXISTS data_exports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    requester_id VARCHAR(255) NOT NULL,
    classification VARCHAR(32) NOT NULL, -- PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
    scope VARCHAR(64) NOT NULL, -- FINDINGS, REPORTS, AUDIT_LOGS, REMEDIATIONS
    format VARCHAR(16) NOT NULL, -- JSON, CSV
    record_count INT NOT NULL DEFAULT 0,
    status VARCHAR(32) NOT NULL DEFAULT 'COMPLETED', -- COMPLETED, FAILED, EXPIRED
    checksum_sha256 VARCHAR(64) NOT NULL,
    download_token VARCHAR(128) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_data_exports_tenant ON data_exports(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_data_exports_token ON data_exports(download_token);
