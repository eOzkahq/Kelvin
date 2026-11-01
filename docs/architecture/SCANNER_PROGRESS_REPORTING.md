# Scanner Progress Reporting & Lifecycle Observability

## 1. Executive Summary

In accordance with ADR-0002 (Canonical Finding Schema), ADR-0005 (Worker Execution Isolation), and Issue P2-27, Kelvin exposes standardized, observable progress throughout every assessment execution without coupling control plane observability to scanner-specific output streams.

Progress reporting provides:
1. **Normalized Execution Stages**: Standardized lifecycle phases covering preflight, initialization, active execution, output collection, result normalization, and terminal completion.
2. **Honest Progress Representation**: Precise distinction between scanners providing authentic completion metrics and indeterminate executions where progress is unknown. Kelvin **never** fabricates progress percentages (e.g., arbitrary 50% approximations).
3. **Traceable Stage Transitions**: Timestamped transitions recording duration spent in each stage and execution details.
4. **Leak-Free Sanitization**: Automatic redaction of credentials, API tokens, passwords, cookies, authorization headers, and terminal escapes from progress messages.
5. **Multi-Channel Lifecycle Publishing**: Streaming over Redis Pub/Sub (`kelvin:events:progress:<assessment_id>`) for real-time frontend visibility alongside durable status caching.

---

## 2. Normalized Execution Stages

Every scanner and assessment pipeline executes across six discrete, sequential stages:

```mermaid
flowchart LR
    Preflight["1. PREFLIGHT"] --> Init["2. SCANNER_INITIALIZATION"]
    Init --> Exec["3. SCANNER_EXECUTION"]
    Exec --> Collect["4. OUTPUT_COLLECTION"]
    Collect --> Norm["5. RESULT_NORMALIZATION"]
    Norm --> Comp["6. COMPLETION"]

    Exec -.->|Operator Cancel| Cancelled["CANCELLED"]
    Exec -.->|Deadline Exceeded| TimedOut["TIMED_OUT"]
    Exec -.->|Process Crash| Failed["FAILED"]
```

### Stage Definitions:

| Stage | Responsibility | Artifacts / Actions |
| :--- | :--- | :--- |
| `PREFLIGHT` | Target authorization & readiness checks | Verifies tenant scope, target reachability, worker readiness, and provisions execution workspace. |
| `SCANNER_INITIALIZATION` | Environment & sandbox configuration | Generates scanner configuration, computes cgroups/resource limits, and sets up safe egress proxies. |
| `SCANNER_EXECUTION` | Active scanner process execution | Executes containerized or in-process scanner adapter; streams honest runtime progress. |
| `OUTPUT_COLLECTION` | Raw artifact ingestion | Captures exit codes, stdout/stderr, and raw output reports from the ephemeral container. |
| `RESULT_NORMALIZATION` | Canonical Schema transformation | Parses raw tool findings into Kelvin Canonical Finding Schema (`finding.v1.json`), stamping versions and digests. |
| `COMPLETION` | Workspace cleanup & finalization | Reclaims workspace directories, cgroups slices, and persists final execution status. |

---

## 3. Honest Progress Representation

External security scanners vary widely in their ability to report completion metrics:
- Tools like Nuclei or Nmap can count scheduled templates or scanned ports.
- Tools like passive baseline auditors or TLS checkers execute indeterminate sequences where total request volume is unknown in advance.

Kelvin models this distinction explicitly via `progress.ScannerProgress`:

```go
type ScannerProgress struct {
    // Percentage is nil if the scanner cannot provide reliable percentage completion.
    // Kelvin strictly forbids fabricating progress numbers.
    Percentage     *float64  `json:"percentage,omitempty"`
    ItemsCompleted int64     `json:"items_completed,omitempty"`
    ItemsTotal     int64     `json:"items_total,omitempty"`
    Units          string    `json:"units,omitempty"`
    Message        string    `json:"message,omitempty"`
    UpdatedAt      time.Time `json:"updated_at"`
}
```

### Rules for Progress Mapping:
1. **Determinate Progress**: When an adapter declares `SupportsProgress: true` and supplies discrete completed/total counts (`completed, total`), percentage is calculated as:
   $$\text{percentage} = \min\left(100.0, \max\left(0.0, \frac{\text{completed}}{\text{total}} \times 100.0\right)\right)$$
2. **Indeterminate Progress**: When an adapter does not support progress reporting, `Percentage` is strictly `nil` (`HasPercentage() == false`), and a descriptive status message is published (e.g. `"executing scanner 'http_headers'"`). The UI renders an indeterminate activity indicator rather than a misleading percentage bar.

---

## 4. Traceable Stage Transitions

To enable latency breakdown and bottleneck identification, every stage change is recorded in an immutable `StageTransition` history:

```json
{
  "from_stage": "SCANNER_INITIALIZATION",
  "to_stage": "SCANNER_EXECUTION",
  "timestamp": "2026-11-02T00:15:30.124Z",
  "duration_ms": 142,
  "details": "initializing scanner container and limits"
}
```

The `StageTracker` records:
- `FromStage` and `ToStage`
- Elapsed wall-clock time spent in the preceding stage
- UTC timestamp of transition
- Sanitized contextual message

On pipeline or scanner termination (including cancellations or timeouts), the full transition history is preserved in the emitted `ProgressEvent`.

---

## 5. Sensitive Data Sanitization

Progress messages must never expose sensitive client credentials, authentication cookies, or proprietary target data. The `progress.SanitizeMessage` pipeline enforces:

1. **Basic Auth Credentials**: `https://user:pass@target.com` $\rightarrow$ `https://user:[REDACTED]@target.com`.
2. **Query Parameter Secrets**: Replaces values for `token`, `password`, `secret`, `api_key`, `apikey`, `access_token`, `auth`, `key`, and `client_secret` with `[REDACTED]`.
3. **Bearer Tokens**: `Bearer <token>` $\rightarrow$ `Bearer [REDACTED]`.
4. **Authorization & Cookie Headers**: Strips header values for `Authorization`, `X-Api-Key`, `Cookie`, and `Set-Cookie`.
5. **Terminal Escapes**: Strips all ANSI color sequences (`\x1b[...]`).
6. **Message Length Ceiling**: Caps messages at 256 characters with `... [truncated]` to prevent raw HTML or binary dumps from flooding event streams.

---

## 6. Event Publishing Architecture

```mermaid
sequenceDiagram
    autonumber
    participant Orch as Assessment Orchestrator
    participant Tracker as Stage Tracker
    participant Pub as Redis Progress Publisher
    participant Redis as Redis Broker
    actor UI as Dashboard / SSE Client

    Orch->>Tracker: TransitionTo(SCANNER_EXECUTION)
    Tracker->>Pub: PublishProgress(ProgressEvent)
    Pub->>Redis: PUBLISH kelvin:events:progress:<assessment_id> (Event JSON)
    Pub->>Redis: HSET kelvin:job:<job_id>:progress (Latest State, 24h TTL)
    Redis-->>UI: Real-Time Event Stream (SSE / WebSocket)
```

1. **Redis Pub/Sub Channel**: `kelvin:events:progress:<assessment_id>` delivers sub-second progress updates to frontend clients without database polling.
2. **Redis Job Hash**: `kelvin:job:<job_id>:progress` stores the latest stage, percentage, and message with a 24-hour TTL for instant REST API lookups.
3. **In-Memory Publisher**: `progress.MemoryPublisher` enables self-contained, broker-free unit and integration testing.

---

## 7. Interrupted Execution Handling

When an execution is interrupted by cancellation, execution deadline expiry, or process crash, progress reporting transitions honestly:

| Interruption Cause | Final Stage Status | Stage Details Recorded |
| :--- | :--- | :--- |
| **Operator Cancellation** | `CANCELLED` | `[CANCELLED] execution cancelled by operator` |
| **Execution Deadline Exceeded** | `TIMED_OUT` | `[TIMED_OUT] hard execution deadline exceeded` |
| **Process Crash / OOM** | `FAILED` | `[FAILED] scanner process failed: <sanitized error>` |

In all interrupted cases:
- Further pipeline phases are aborted immediately.
- The stage transition history up to the failure point is completely preserved.
- The control plane receives the terminal state transition event immediately.
