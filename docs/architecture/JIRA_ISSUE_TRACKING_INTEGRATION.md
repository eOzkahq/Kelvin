# Jira Issue-Tracking Integration Architecture

## 1. Overview
The Jira Issue-Tracking Integration connects Kelvin vulnerability findings and remediation records directly to Atlassian Jira Cloud and Data Center. It provides automatic finding-to-issue field translation, severity-to-priority mapping, evidence credential redaction, strict idempotency against duplicate issue creation, and error classification.

## 2. Jira Export & Idempotent Linking Lifecycle

```mermaid
sequenceDiagram
    participant Analyst as Security Analyst
    participant API as Kelvin Findings Export API
    participant JiraService as Kelvin JiraService
    participant JiraAdapter as Jira Adapter
    participant Jira as Atlassian Jira REST API

    Analyst->>API: POST /findings/{id}/export-jira (connID, project='SEC')
    API->>JiraService: ExportFindingToJira(req)
    JiraService->>JiraService: Check Idempotency Table (finding_id + conn_id)

    alt Already Linked
        JiraService-->>API: Return Existing JiraIssueLink (No duplicate issue created!)
    else Not Linked
        JiraService->>JiraAdapter: Execute(CREATE_ISSUE, payload)
        JiraAdapter->>JiraAdapter: Map Severity to Priority & Sanitize Secrets
        JiraAdapter->>Jira: POST /rest/api/2/issue (Bearer Token)
        Jira-->>JiraAdapter: 201 Created { id: '10001', key: 'SEC-402' }
        JiraAdapter-->>JiraService: ExecutionResult(ExternalID='SEC-402', ExternalURL)
        JiraService->>JiraService: Persist Record in jira_issue_links Table
        JiraService-->>API: JiraIssueLink Created
    end

    API-->>Analyst: 200 OK { issue_key: 'SEC-402', issue_url: 'https://jira.../browse/SEC-402' }
```

## 3. Severity to Jira Priority Mapping
Kelvin finding severities translate deterministically into standard Jira issue priorities:
- `CRITICAL` &rarr; `Highest`
- `HIGH` &rarr; `High`
- `MEDIUM` &rarr; `Medium`
- `LOW` &rarr; `Low`
- `INFO` &rarr; `Lowest`

## 4. Key Architectural Guarantees
1. **Idempotent Issue Creation Barrier**: `jira_issue_links` enforces a unique constraint on `(organization_id, connection_id, finding_id)`. Subsequent or retried export operations return the existing issue link without calling the Jira REST API twice.
2. **Leakage & Sanitization Defense**: Finding descriptions and summary fields undergo token sanitization before dispatch, stripping raw token signatures (e.g. `klv_live_`, `whsec_`) and replacing them with `[REDACTED_SECRET]`.
3. **Resilient Error Classification**: HTTP 429 yields `ErrProviderRateLimited`, 401/403 yields `ErrProviderAuthFailed`, and network drops yield `ErrProviderUnavailable`.
4. **Tenant-Scoped Access**: Connections and exported issues are strictly bounded by organization and workspace tenancies.
