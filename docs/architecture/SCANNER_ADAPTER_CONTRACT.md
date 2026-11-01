# Kelvin — Scanner Adapter Contract

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Phase 2 implementation contract (`P2-02`) |
| **Owner** | Platform Engineering |
| **Implementation** | `apps/worker/internal/adapters` |
| **Related** | `MVP_SCANNER_SELECTION.md`, `SCAN_PROFILES.md`, `TARGET_SCOPE_ENFORCEMENT.md`, `EXECUTION_ISOLATION.md`, `FINDING_SCHEMA.md` |

## Contract

`adapters.ScannerAdapter` is the worker's registered adapter interface. It includes the following lifecycle operations:

```go
type ScannerAdapter interface {
    Adapter
    Initialize(context.Context, *zap.Logger) error
    ValidateConfig(json.RawMessage) error
    Capabilities() Capabilities
    Execute(context.Context, Task) (Result, error)
    Cancel() error
    Health(context.Context) error
    Result() (Result, error)
}
```

The exact Go definition and reference implementation are in `internal/adapters/contract.go`; the snippet summarizes the public contract.

| Operation | Contract |
| :--- | :--- |
| `Name` | Stable registered name matching the job scanner type. Empty names and duplicates are rejected. |
| `Initialize` | Called once before the adapter accepts jobs. Receives a service logger; initialization errors prevent registration/use. |
| `ValidateConfig` | Reject malformed, unknown, or unsupported scanner options before work starts. Empty configuration may mean scanner defaults only where those defaults are safe and pinned. |
| `Capabilities` | Returns supported check categories, network need, cancellation support, and declared request bounds. Declarations inform policy; runtime enforcement remains in worker and sandbox layers. |
| `Execute` | Receives a daemon-validated `Task` and deadline-bearing context. It returns a structured `Result` or error. Implementations must honor cancellation and must not access the database. |
| `Cancel` | Best-effort cancellation of the active execution. It is idempotent when no execution is active. The context is the authoritative deadline/cancellation signal. |
| `Health` | Reports readiness/availability and honors its context. It must not generate target traffic. |
| `Result` | Returns a defensive copy of the most recent successful result, or `adapters.ErrNoResult` when no result exists. Results are untrusted until validated by the ingestion path. |

## Input and output

The worker constructs `Task` from a queue job only after tenant and scope context processing. `ValidateTask` verifies required IDs, scanner, target, profile, and hard deadline. The task carries job/assessment/tenant identifiers, correlation ID, scanner name, target, profile ID, deadline, and scanner-specific JSON payload. Adapter code must use the supplied target and approved scope-aware clients; it must not resolve or widen scope independently.

`Result` carries exit code, duration, capped stdout/stderr, raw findings bytes, OOM state, and deadline state. Every field from a scanner is untrusted. The worker rejects execution failures and validates findings before job completion; canonical normalization, redaction, and persistence remain outside scanner-specific code. Adapters have no database dependency.

## Worker and sandbox relationship

The registry accepts only `ScannerAdapter` implementations. The daemon validates task data and dispatches the registered adapter name to the configured sandbox executor. External scanner processes run in the controlled OCI image; adapter code must not spawn an unsandboxed scanner process. `Execute` receives the same deadline-bearing context used by the worker. Worker-level limits and egress remain authoritative even when scanner flags expose similar controls.

`ReferenceAdapter` in `internal/adapters/contract.go` demonstrates serialized execution, initialization/readiness, cancellation, defensive result access, and narrow runner injection. Its runner is the seam where a production adapter delegates to the worker's sandbox execution. It does not provide direct network or persistence access.

## Errors and status

Adapters return errors for invalid task/configuration, unavailable or uninitialized state, rejected concurrent use, scanner failure, and cancellation. The daemon maps any non-nil execution error to job failure; deadline and OOM status are preserved in `Result` and mapped to their corresponding worker termination causes. A zero exit code alone does not authorize completion: finding validation must also pass. Health errors affect readiness and must not be silently treated as successful execution.

## Security requirements

- External binaries run only under ADR-0005 isolation, including rootless OCI, UID `10001`, dropped capabilities, read-only root filesystem, resource bounds, and constrained egress.
- All target requests use the validated scope and revalidate redirects; adapters may not expose arbitrary target overrides.
- Do not put secrets in logs, task payload errors, stdout/stderr, or findings. Redact evidence before it leaves the worker boundary.
- Treat scanner output as hostile input and validate it against `finding.v1.json` before ingestion.
- Fail closed when config, capabilities, profile bounds, or scope cannot be enforced.
