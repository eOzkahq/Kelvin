-- 000040_risk_exception_governance.up.sql
-- Accepted-Risk Approval and Exception Governance (P4-25)

CREATE TABLE IF NOT EXISTS risk_exception_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL,
    category VARCHAR(64) NOT NULL CHECK (category IN ('BUSINESS_JUSTIFICATION', 'FALSE_POSITIVE_EXCEPTION', 'COMPENSATING_CONTROL', 'UPSTREAM_DEPENDENCY')),
    severity VARCHAR(32) NOT NULL,
    rationale TEXT NOT NULL,
    compensating_controls TEXT,
    requester_id VARCHAR(255) NOT NULL,
    requested_duration_days INT NOT NULL CHECK (requested_duration_days > 0 AND requested_duration_days <= 90),
    requires_dual_approval BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'REVOKED')),
    approved_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    review_date TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_exceptions_org_status 
    ON risk_exception_requests (organization_id, status);

CREATE INDEX IF NOT EXISTS idx_risk_exceptions_finding 
    ON risk_exception_requests (organization_id, finding_id);

CREATE TABLE IF NOT EXISTS risk_exception_approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    exception_request_id UUID NOT NULL REFERENCES risk_exception_requests(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    approver_id VARCHAR(255) NOT NULL,
    approver_role VARCHAR(64) NOT NULL,
    decision VARCHAR(32) NOT NULL CHECK (decision IN ('APPROVED', 'REJECTED')),
    comments TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_exception_approvals_req 
    ON risk_exception_approvals (exception_request_id, created_at ASC);
