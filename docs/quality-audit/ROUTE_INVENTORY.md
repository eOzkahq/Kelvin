# Route and Surface Inventory

## 1. Web Application Routes Catalog

| Route Path | View / Component | Min Required Role | Auth Required? | Purpose | Audit Status | Related Findings |
|---|---|---|:---:|---|:---:|---|
| `/` | `HomePage.tsx` | Anonymous | No | Public landing, API health checks, and platform connectivity | **PASS** | None |
| `/dashboard` | `DashboardPage.tsx` | Standard Member | Yes | Real-time posture dashboard, active assessment metrics, severity summary | **PASS** | None |
| `/findings` | `FindingsWorkspacePage.tsx` | Security Analyst | Yes | Findings triage, SLA indicators, search filters, detail drawer | **PASS** | `AUD-003` (Resolved) |
| `/compare` | `AssessmentComparePage.tsx` | Security Analyst | Yes | Assessment-to-assessment delta comparison, regression detection | **PASS** | `AUD-004` (Resolved) |
| `/reports` | `ReportCenterPage.tsx` | Standard Member | Yes | Report snapshot browser, HTML preview, signed PDF downloads | **PASS** | None |
| `/*` (Fallback) | `HomePage.tsx` | Anonymous | No | Graceful 404 recovery handling without stack traces | **PASS** | None |

---

## 2. Protected Enterprise API Endpoints

| Endpoint URL Path | HTTP Method | Minimum RBAC Scope | Classification | Description | Status |
|---|---|---|---|---|:---:|
| `/api/v1/auth/login` | POST | Anonymous | Public | Authenticates credentials, returns session JWT | **PASS** |
| `/api/v1/auth/sso/saml` | POST | Anonymous | Public | SAML 2.0 assertion consumer service | **PASS** |
| `/api/v1/auth/sso/oidc` | GET | Anonymous | Public | OpenID Connect callback and token exchange | **PASS** |
| `/api/v1/assessments` | GET, POST | `assessments:read`, `assessments:create` | Internal | Lists or queues security assessment scans | **PASS** |
| `/api/v1/assessments/{id}/compare` | GET | `assessments:read` | Confidential | Generates delta comparison between scans | **PASS** |
| `/api/v1/findings` | GET | `findings:read` | Confidential | Search and filter findings with pagination | **PASS** |
| `/api/v1/findings/{id}` | GET, PATCH | `findings:read`, `findings:write` | Confidential | Views details, triages status, updates SLA | **PASS** |
| `/api/v1/findings/{id}/evidence` | GET | `evidence:read` | Restricted | Retrieves sanitized, redacted evidence blobs | **PASS** |
| `/api/v1/reports` | GET, POST | `reports:read`, `reports:create` | Confidential | Creates snapshots and compiles reports | **PASS** |
| `/api/v1/reports/{id}/export` | GET | `reports:read` | Confidential | Generates signed ephemeral download token | **PASS** |
| `/api/v1/remediations` | GET, POST | `remediations:read`, `remediations:write` | Internal | Tracks assigned remediation lifecycle | **PASS** |
| `/api/v1/policies` | GET, POST, PUT | `policies:read`, `policies:write` | Confidential | Central governance policy management | **PASS** |
| `/api/v1/policies/simulate` | POST | `policies:write` | Confidential | Dry-run policy simulation engine | **PASS** |
| `/api/v1/audit-events` | GET | `audit:read` | Restricted | Multi-dimensional audit search & filtering | **PASS** |
| `/api/v1/audit/integrity-check` | POST | `audit:verify` | Restricted | Verifies cryptographic hash chain and Merkle root | **PASS** |
| `/api/v1/data-exports` | POST | `data:export` | Confidential / Restricted | Requests scoped checksummed data bundle | **PASS** |
| `/api/v1/integrations/jira` | POST | `integrations:write` | Confidential | Bi-directional Jira issue creation & sync | **PASS** |
| `/api/v1/integrations/collaboration` | POST | `integrations:write` | Confidential | Slack / Teams alert notification dispatch | **PASS** |
| `/api/v1/webhooks/subscriptions` | GET, POST | `integrations:write` | Confidential | Manages HMAC-SHA256 outbound webhooks | **PASS** |
| `/api/v1/quotas/summary` | GET | `quotas:read` | Internal | Returns tenant usage and percentage limits | **PASS** |

---

## 3. Direct Boundary & IDOR Verification

All parameterized routes (`/api/v1/findings/{id}`, `/api/v1/assessments/{id}`, `/api/v1/reports/{id}`) were subjected to direct cross-tenant request forging using automated test scripts:
- Tenant A attempting to access Tenant B objects via manipulated UUIDs received strict `404 Not Found` or `403 Forbidden` responses.
- Tenant context is strictly resolved from verified session tokens, never from unauthenticated client headers (`X-Tenant-ID`).
