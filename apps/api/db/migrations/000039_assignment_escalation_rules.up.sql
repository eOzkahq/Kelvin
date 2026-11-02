-- 000039_assignment_escalation_rules.up.sql
-- Enterprise Assignment and Escalation Rules (P4-24)

CREATE TABLE IF NOT EXISTS assignment_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    priority INT NOT NULL DEFAULT 100,
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    target_tag VARCHAR(100),
    vulnerability_class VARCHAR(100),
    min_severity VARCHAR(32),
    assignee_type VARCHAR(32) NOT NULL CHECK (assignee_type IN ('USER', 'TEAM')),
    assignee_id VARCHAR(255) NOT NULL,
    fallback_assignee_type VARCHAR(32) CHECK (fallback_assignee_type IN ('USER', 'TEAM')),
    fallback_assignee_id VARCHAR(255),
    version INT NOT NULL DEFAULT 1,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assignment_rules_org_active_priority 
    ON assignment_rules (organization_id, is_active, priority ASC);

CREATE TABLE IF NOT EXISTS escalation_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    assignment_rule_id UUID REFERENCES assignment_rules(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    trigger_condition VARCHAR(64) NOT NULL CHECK (trigger_condition IN ('SLA_WARNING', 'SLA_BREACHED', 'TIME_ELAPSED')),
    trigger_threshold_minutes INT NOT NULL DEFAULT 0,
    escalation_level INT NOT NULL DEFAULT 1,
    escalate_to_type VARCHAR(32) NOT NULL CHECK (escalate_to_type IN ('USER', 'TEAM')),
    escalate_to_id VARCHAR(255) NOT NULL,
    next_escalation_policy_id UUID REFERENCES escalation_policies(id) ON DELETE SET NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_escalation_policies_org_rule_level 
    ON escalation_policies (organization_id, assignment_rule_id, escalation_level ASC);

CREATE TABLE IF NOT EXISTS finding_assignment_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL,
    rule_id UUID REFERENCES assignment_rules(id) ON DELETE SET NULL,
    rule_version INT NOT NULL DEFAULT 1,
    assigned_to_type VARCHAR(32) NOT NULL CHECK (assigned_to_type IN ('USER', 'TEAM')),
    assigned_to_id VARCHAR(255) NOT NULL,
    assignment_source VARCHAR(64) NOT NULL CHECK (assignment_source IN ('RULE_MATCH', 'DEFAULT_FALLBACK', 'ESCALATION', 'MANUAL_OVERRIDE')),
    escalation_level INT NOT NULL DEFAULT 0,
    actor_id VARCHAR(255),
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_assignment_executions_finding 
    ON finding_assignment_executions (organization_id, finding_id, created_at DESC);
