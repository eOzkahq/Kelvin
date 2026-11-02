-- 000054_audit_integrity_chains_and_checkpoints.up.sql

ALTER TABLE audit_log 
    ADD COLUMN IF NOT EXISTS sequence_num BIGINT,
    ADD COLUMN IF NOT EXISTS previous_hash VARCHAR(64),
    ADD COLUMN IF NOT EXISTS current_hash VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_seq 
    ON audit_log (tenant_id, sequence_num ASC);

CREATE TABLE IF NOT EXISTS audit_checkpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    checkpoint_seq BIGINT NOT NULL,
    start_sequence_num BIGINT NOT NULL,
    end_sequence_num BIGINT NOT NULL,
    record_count INT NOT NULL,
    start_hash VARCHAR(64) NOT NULL,
    end_hash VARCHAR(64) NOT NULL,
    merkle_root VARCHAR(64) NOT NULL,
    signature VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'VALID', -- 'VALID', 'TAMPERED', 'PENDING'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_audit_checkpoint_seq UNIQUE (tenant_id, checkpoint_seq)
);

CREATE INDEX IF NOT EXISTS idx_audit_checkpoints_tenant ON audit_checkpoints(tenant_id, checkpoint_seq DESC);

CREATE TABLE IF NOT EXISTS audit_integrity_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    checkpoint_id UUID REFERENCES audit_checkpoints(id) ON DELETE SET NULL,
    failure_type VARCHAR(64) NOT NULL, -- 'HASH_MISMATCH', 'CHAIN_BROKEN', 'MERKLE_MISMATCH', 'SIGNATURE_INVALID'
    record_id UUID,
    sequence_num BIGINT,
    expected_hash VARCHAR(64),
    computed_hash VARCHAR(64),
    details TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'OPEN', -- 'OPEN', 'INVESTIGATING', 'RESOLVED'
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_integrity_alerts ON audit_integrity_alerts(tenant_id, detected_at DESC);
