# Kelvin — Scanner Registry and Capability Discovery

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Phase 2 implementation contract (`P2-06`) |
| **Implementation** | `apps/worker/internal/adapters/adapters.go` |
| **Related** | `SCANNER_ADAPTER_CONTRACT.md`, `SCANNER_CONFIGURATION.md`, `MVP_SCANNER_SELECTION.md`, `EXECUTION_ISOLATION.md` |

## Registry model

`adapters.Registry` is a worker-process singleton instance created at startup. It accepts a stable scanner identifier, immutable discovery metadata, and a factory. Duplicate identifiers are rejected with `ErrDuplicateAdapter`; malformed metadata and nil factories are rejected before storage. Factories are lazy and are invoked at most once per registered entry. The created adapter must report the registered ID, version, and capabilities exactly; disagreement marks it unavailable.

Registry metadata includes ID, display name, engine/adapter version, supported target types, check capabilities, configuration version, availability, and an unavailable reason. Metadata is registry state, not scan execution data. All returned metadata and capability slices are defensive copies.

Availability moves from `REGISTERED` to `AVAILABLE` only after factory construction, adapter initialization, and a successful health check. Factory panics, metadata mismatch, initialization errors, and failed health checks mark only that entry `UNAVAILABLE`. Other healthy adapters remain available. Unknown IDs return `ErrAdapterNotFound`; registered but unhealthy or not-yet-initialized IDs return `ErrAdapterUnavailable`. The worker fails jobs for either condition before invoking the scanner.

## Discovery API

| API | Behavior |
| :--- | :--- |
| `RegisterAdapter(metadata, factory)` | Registers a lazy adapter factory and metadata; duplicate IDs fail deterministically. |
| `GetAdapter(id)` | Returns only an initialized and healthy adapter. |
| `FindByCapability(flag)` | Finds available adapters by flag, check category, protocol, target type, or built-in capability names such as `passive_only`, `requires_network`, and `supports_cancellation`. |
| `ListAvailable()` | Returns healthy adapter metadata sorted by scanner ID. |
| `Metadata(id)` | Returns registered metadata, including registered/unavailable state and failure reason. |
| `Names()` | Lists all registered IDs, including those not currently available. |

Capabilities are descriptive and guide scanner selection. They do not authorize targets or replace scan profiles. Scope, profile budgets, worker resource limits, and OCI isolation remain enforced at the execution boundary.

## Registration guidance

Concrete adapters register from worker composition code using the immutable values from `MVP_SCANNER_SELECTION.md` and `SCANNER_CONFIGURATION.md`. Built-in checks declare their supported HTTP(S) target types and passive check categories. ZAP and Nuclei declare sandbox execution, network, cancellation, target types, and their exact configuration version. Do not register a placeholder factory as available: an engine with no executable implementation must be absent or report unavailable.

The registry currently provides the lifecycle and discovery mechanism. Scanner image wiring and concrete engine factories are added by the integration and controlled-image issues. The worker starts with no scanner adapters until composition registers real implementations; production queue startup therefore remains fail-closed when none are registered.

## Failure handling and concurrency

All map access is protected by a registry RW mutex. Each entry serializes construction and lifecycle initialization independently, so concurrent capability queries do not expose partially initialized instances. Initialization proceeds in sorted ID order for reproducible startup behavior. Unavailable reasons are diagnostic metadata; callers should return a safe generic scanner-unavailable response and keep the detailed reason in internal logs.
