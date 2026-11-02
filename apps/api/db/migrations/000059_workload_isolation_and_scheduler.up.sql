-- 000059_workload_isolation_and_scheduler.up.sql

CREATE TABLE IF NOT EXISTS workload_execution_queues (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    job_id UUID NOT NULL,
    job_type VARCHAR(64) NOT NULL, -- 'ASSESSMENT_SCAN', 'REPORT_COMPILE', 'INTEGRATION_SYNC'
    priority INT NOT NULL DEFAULT 5,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING', -- 'PENDING', 'RUNNING', 'COMPLETED', 'FAILED'
    worker_id VARCHAR(255),
    enqueued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_workload_queues_tenant_status 
    ON workload_execution_queues(tenant_id, status, priority ASC, enqueued_at ASC);

CREATE TABLE IF NOT EXISTS scheduler_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    active_workers INT NOT NULL,
    total_queued_jobs INT NOT NULL,
    saturated_tenants_count INT NOT NULL DEFAULT 0,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scheduler_metrics_time 
    ON scheduler_metrics(recorded_at DESC);
