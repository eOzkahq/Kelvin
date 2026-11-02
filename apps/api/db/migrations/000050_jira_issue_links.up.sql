-- 000050_jira_issue_links.up.sql
-- Jira Issue-Tracking Integration (P4-35)

CREATE TABLE IF NOT EXISTS jira_issue_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspaces(id) ON DELETE CASCADE,
    connection_id UUID NOT NULL REFERENCES integration_connections(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL,
    remediation_id UUID,
    jira_issue_id VARCHAR(64) NOT NULL,
    jira_issue_key VARCHAR(64) NOT NULL,
    jira_project_key VARCHAR(32) NOT NULL,
    jira_issue_url TEXT NOT NULL,
    sync_status VARCHAR(32) NOT NULL DEFAULT 'SYNCED' CHECK (sync_status IN ('SYNCED', 'PENDING_UPDATE', 'FAILED')),
    last_synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_jira_link_finding UNIQUE (organization_id, connection_id, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_jira_links_finding 
    ON jira_issue_links (organization_id, finding_id);

CREATE INDEX IF NOT EXISTS idx_jira_links_key 
    ON jira_issue_links (jira_issue_key);
