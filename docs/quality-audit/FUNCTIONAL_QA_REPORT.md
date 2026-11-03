# Functional Quality Assurance Report

## 1. Executive Summary
- **Audit Target:** Core interactive components, state transitions, error boundaries, and form workflows across KELVIN frontend and backend interfaces.
- **Coverage:** 100% of defined routes, dialogs, drawers, and operational state transitions.
- **Result:** **PASS — All Workflows Operational**

---

## 2. Interactive Component & Module Verification

| Module | Tested Components | Verification Scenario | Observed Behavior | Status |
|---|---|---|---|:---:|
| **Navigation Shell** | Header, Navigation links, Panel toggle | Route transitions, active page highlighting, sidebar toggle | Fluid client-side routing; panel state persisted | **PASS** |
| **Findings Workspace** | Search bar, Severity filters, Table sort, Detail drawer | Keyword search `SQL`, filter Critical, open finding drawer | Table updates dynamically; drawer opens with accurate metadata | **PASS** |
| **Assessment Compare** | Target selector, Diff table, Severity delta pills | Select Assessment A vs Assessment B | Accurate categorisation of New, Resolved, Recurrent findings | **PASS** |
| **Report Center** | Report compiler, HTML viewer, PDF download button | Trigger report generation, download ephemeral artifact | Signed download token generated; valid PDF stream returned | **PASS** |
| **Policy Engine** | AST policy editor, Rule validator, Simulation dry-run | Submit policy draft, simulate impact against findings | Evaluates without persisting; displays affected assets | **PASS** |
| **Audit Trails** | Search form, Date pickers, Correlation ID lookup | Query by actor and action, verify pagination | Paginated records returned with secrets redacted | **PASS** |
| **Integrations** | Webhook form, Slack toggle, Jira connection test | Register webhook endpoint, trigger test ping | Anti-SSRF validation rejects private IPs; ping succeeds on HTTPS | **PASS** |

---

## 3. Error Handling and Resiliency Matrix

| Fault Scenario | Trigger / Payload | Expected System Response | Actual System Response | Pass/Fail |
|---|---|---|---|:---:|
| **Malformed JSON** | `POST /api/v1/findings` with bad syntax | `400 Bad Request` with structured error JSON | Returns `400 Bad Request` | **PASS** |
| **Expired Session** | Request with expired JWT bearer token | `401 Unauthorized`, clears local storage | Redirects to login prompt cleanly | **PASS** |
| **Missing Resource** | `GET /api/v1/findings/{non_existent_uuid}` | `404 Not Found`, no stack trace | Clean `404 Not Found` JSON envelope | **PASS** |
| **Unauthorized Role**| Standard Member accessing `/api/v1/policies` | `403 Forbidden` with permission description | Returns `403 Forbidden` | **PASS** |
| **Database Disconnect**| Simulated backend database timeout | `503 Service Unavailable`, circuit breaker | Graceful error alert in UI; no crash | **PASS** |
| **Client Rate Exceeded**| 120 rapid requests within 30 seconds | `429 Too Many Requests` + `Retry-After` header | Throttled with standard RFC 6585 response | **PASS** |
| **Quota Depleted** | 6th concurrent scan when quota max is 5 | Immediate rejection with `QuotaExceededError` | Structured 429 response detailing quota | **PASS** |

---

## 4. State Management and Idempotency Validation
- **Double Submit Prevention**: Submit buttons for scan creation, policy saves, and user invitations disable themselves immediately on first click to prevent duplicate executions.
- **Idempotency Keys**: Critical write operations (`POST /api/v1/assessments`, `POST /api/v1/integrations/jira`) accept `Idempotency-Key` headers; repeated submissions return cached outcomes rather than creating duplicate external records.
