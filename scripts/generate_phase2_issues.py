import os

phase2_issues = [
    # Workstream A
    {
        "id": "P2-01",
        "slug": "P2-01_DEFINE_MVP_SCANNER_SELECTION_AND_CAPABILITY_MATRIX",
        "title": "Define the MVP Scanner Selection and Capability Matrix",
        "workstream": "Workstream A — Scanner Architecture & Integration Foundation",
        "workstream_label": "workstream/a-foundation",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Select the initial scanner technologies that KELVIN will support in its MVP. Avoid integrating tools without a clear product requirement or creating unnecessary dependencies.",
        "requirements": [
            "Evaluate potential scanners based on their capabilities, maintenance status, licensing, integration complexity, resource requirements, and compatibility with containerized workers.",
            "Define the initial MVP scanner lineup: Built-in HTTP/HTTPS preflight checks, Built-in TLS configuration assessment, Built-in HTTP security header and cookie checks, OWASP ZAP Baseline, and Nuclei with a curated, vetted safe-template set.",
            "Define what each scanner is responsible for detecting.",
            "Identify overlapping capabilities between scanners.",
            "Define which checks are passive, which generate requests, and what operational impact they may have.",
            "Explicitly exclude unrestricted port scanning, arbitrary template execution, exploit execution, and denial-of-service testing from default MVP profiles.",
            "Document deferred scanners and the reasoning for excluding them."
        ],
        "acceptance_criteria": [
            "An approved scanner selection matrix exists.",
            "Each selected scanner has a documented purpose and capability boundary.",
            "Licensing and distribution considerations are documented.",
            "Default MVP scanning behavior is explicitly defined as non-intrusive and bounded.",
            "Deferred integrations are documented separately."
        ]
    },
    {
        "id": "P2-02",
        "slug": "P2-02_DEFINE_SCANNER_ADAPTER_INTERFACE",
        "title": "Define the Scanner Adapter Interface",
        "workstream": "Workstream A — Scanner Architecture & Integration Foundation",
        "workstream_label": "workstream/a-foundation",
        "area_label": "area/architecture",
        "kind_label": "kind/feature",
        "priority_label": "priority/critical",
        "purpose": "Establish a consistent Go interface through which KELVIN can integrate built-in checks and external scanner tools.",
        "requirements": [
            "Define a common scanner adapter interface (`ScannerAdapter`).",
            "Include operations for: Scanner initialization (`Initialize`), Configuration validation (`ValidateConfig`), Capability discovery (`Capabilities`), Execution (`Execute`), Cancellation (`Cancel`), Health or availability checks (`Health`), and Result retrieval (`Result`).",
            "Define how adapters receive validated assessment inputs.",
            "Define how adapters interact with the existing assessment worker.",
            "Ensure scanner-specific implementation details remain isolated from the domain and application layers.",
            "Avoid direct database access from scanner adapters.",
            "Define consistent error and execution-status semantics."
        ],
        "acceptance_criteria": [
            "A documented Go adapter interface exists in `apps/worker/internal/adapter/`.",
            "Adapter implementations follow the same lifecycle contract.",
            "Scanner-specific code does not leak into unrelated application modules.",
            "Unit tests verify the expected adapter behavior.",
            "A reference implementation demonstrates the contract."
        ]
    },
    {
        "id": "P2-03",
        "slug": "P2-03_DEFINE_SCANNER_INVOCATION_INPUT_CONTRACT",
        "title": "Define the Scanner Invocation Input Contract",
        "workstream": "Workstream A — Scanner Architecture & Integration Foundation",
        "workstream_label": "workstream/a-foundation",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Define exactly what information a scanner receives when KELVIN requests an assessment.",
        "requirements": [
            "Define the scanner execution input structure (`ExecutionInput`).",
            "Include: Assessment ID, Tenant and authorization context where required, Canonical target information, Approved scope, Selected scan profile, Scanner-specific configuration, Execution deadline, Resource policy reference, Correlation and tracing identifiers.",
            "Ensure scanners receive only the information required for their task.",
            "Do not pass unrestricted user-supplied command-line arguments to scanner processes.",
            "Define how sensitive configuration and credentials, if supported later, are referenced without exposing secret values.",
            "Ensure all target data originates from the validated assessment context established in Phase 1."
        ],
        "acceptance_criteria": [
            "A versioned execution input contract exists.",
            "Required and optional fields are documented.",
            "Invalid or incomplete inputs are rejected.",
            "Inputs cannot override Phase 1 authorization or scope restrictions.",
            "Contract tests cover valid and invalid payloads."
        ]
    },
    {
        "id": "P2-04",
        "slug": "P2-04_DEFINE_SCANNER_OUTPUT_ENVELOPE",
        "title": "Define the Scanner Output Envelope",
        "workstream": "Workstream A — Scanner Architecture & Integration Foundation",
        "workstream_label": "workstream/a-foundation",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Create a consistent output envelope for results and diagnostics returned by different scanner adapters.",
        "requirements": [
            "Define a common output structure containing: Assessment ID, Scanner identifier and version, Execution status, Start and completion timestamps, Findings collection, Execution diagnostics, Scanner-specific metadata, Partial-result indicator.",
            "Distinguish successful execution, completed-with-warnings, partial completion, and failure.",
            "Define how adapters represent scanner crashes and malformed output.",
            "Keep raw output separate from normalized findings.",
            "Include correlation identifiers for tracing.",
            "Ensure output structures are versioned."
        ],
        "acceptance_criteria": [
            "A documented, versioned output contract exists.",
            "All adapters use the common envelope.",
            "Failure and partial-result states are unambiguous.",
            "Raw scanner output cannot be mistaken for normalized findings.",
            "Contract tests validate serialization and deserialization."
        ]
    },
    {
        "id": "P2-05",
        "slug": "P2-05_DEFINE_SCANNER_CONFIGURATION_SCHEMA",
        "title": "Define the Scanner Configuration Schema",
        "workstream": "Workstream A — Scanner Architecture & Integration Foundation",
        "workstream_label": "workstream/a-foundation",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Establish a validated configuration model for controlling scanner behavior without exposing unsafe or unrestricted execution options.",
        "requirements": [
            "Define configuration schemas for each selected scanner.",
            "Include supported settings such as: Request timeout, Maximum request rate, Maximum scan duration, Approved scan mode, Template or ruleset reference, Scanner-specific safe options.",
            "Define defaults and upper/lower bounds.",
            "Reject unsupported and unknown configuration fields where appropriate.",
            "Prevent user-provided configuration from overriding security restrictions.",
            "Separate product-level scan profiles from scanner-specific implementation settings.",
            "Ensure schemas are versioned."
        ],
        "acceptance_criteria": [
            "Every selected scanner has a documented configuration schema.",
            "Invalid values are rejected before execution.",
            "Unsafe settings cannot be enabled through ordinary user input.",
            "Defaults are documented and tested.",
            "Configuration versions can be identified in assessment metadata."
        ]
    },
    {
        "id": "P2-06",
        "slug": "P2-06_IMPLEMENT_SCANNER_REGISTRY_AND_CAPABILITY_DISCOVERY",
        "title": "Implement the Scanner Registry and Capability Discovery",
        "workstream": "Workstream A — Scanner Architecture & Integration Foundation",
        "workstream_label": "workstream/a-foundation",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Provide a central registry through which KELVIN discovers and manages available scanner adapters.",
        "requirements": [
            "Implement a registry for scanner adapters.",
            "Register each scanner with: Unique identifier, Display name, Version, Supported target types, Supported assessment capabilities, Supported configuration version, Availability status.",
            "Allow the assessment engine to resolve a scanner by identifier.",
            "Prevent duplicate or conflicting scanner registration.",
            "Define behavior when a requested scanner is unavailable.",
            "Keep registry metadata separate from individual scan execution records."
        ],
        "acceptance_criteria": [
            "Scanner adapters can register with the registry.",
            "The engine can discover available capabilities.",
            "Unknown scanner identifiers are rejected safely.",
            "Duplicate registrations are handled deterministically.",
            "Registry behavior is covered by automated tests."
        ]
    },
    {
        "id": "P2-07",
        "slug": "P2-07_IMPLEMENT_SCANNER_VERSION_AND_COMPATIBILITY_MANAGEMENT",
        "title": "Implement Scanner Version and Compatibility Management",
        "workstream": "Workstream A — Scanner Architecture & Integration Foundation",
        "workstream_label": "workstream/a-foundation",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Ensure KELVIN runs known, compatible scanner versions and can identify exactly which version generated an assessment result.",
        "requirements": [
            "Define supported versions for every integrated scanner.",
            "Pin scanner dependencies to approved versions.",
            "Record the scanner version used for each assessment.",
            "Implement startup or readiness verification for scanner versions.",
            "Detect unexpected runtime version changes.",
            "Define a compatibility policy for adapter and scanner upgrades.",
            "Document how scanner updates are reviewed, tested, and promoted.",
            "Avoid silently upgrading scanner binaries in production."
        ],
        "acceptance_criteria": [
            "Every integrated scanner has an approved version policy.",
            "Runtime version verification is implemented.",
            "Version information is recorded per assessment.",
            "Unsupported versions prevent execution or produce a clear blocked state.",
            "Upgrade procedures are documented."
        ]
    },
    {
        "id": "P2-08",
        "slug": "P2-08_PACKAGE_SCANNERS_AS_CONTROLLED_RUNTIME_IMAGES",
        "title": "Package Scanners as Controlled Runtime Images",
        "workstream": "Workstream A — Scanner Architecture & Integration Foundation",
        "workstream_label": "workstream/a-foundation",
        "area_label": "area/infra",
        "kind_label": "kind/feature",
        "priority_label": "priority/critical",
        "purpose": "Create reproducible scanner runtime environments that can be deployed consistently across development, testing, and production.",
        "requirements": [
            "Package external scanner dependencies in controlled container images.",
            "Use pinned base images and dependency versions.",
            "Prefer minimal runtime images.",
            "Avoid including unnecessary compilers, shells, debugging utilities, or unrelated packages in production images.",
            "Run scanner containers as non-root wherever supported.",
            "Define image build and verification processes.",
            "Record image digests and scanner versions.",
            "Integrate image builds into CI.",
            "Document vulnerability scanning and update requirements for scanner images."
        ],
        "acceptance_criteria": [
            "Each external scanner has a reproducible runtime image.",
            "Image versions and digests are traceable.",
            "Images follow the Phase 1 worker security architecture.",
            "CI verifies image builds.",
            "Image update and rollback procedures are documented."
        ]
    },
    {
        "id": "P2-09",
        "slug": "P2-09_IMPLEMENT_SAFE_SCANNER_PROCESS_INVOCATION",
        "title": "Implement Safe Scanner Process Invocation",
        "workstream": "Workstream A — Scanner Architecture & Integration Foundation",
        "workstream_label": "workstream/a-foundation",
        "area_label": "area/security",
        "kind_label": "kind/feature",
        "priority_label": "priority/critical",
        "purpose": "Provide one controlled mechanism for invoking external scanner processes without creating command-injection vulnerabilities.",
        "requirements": [
            "Implement a shared Go process invocation abstraction.",
            "Use structured executable paths and argument arrays.",
            "Never construct scanner commands through shell string concatenation.",
            "Do not allow arbitrary executables or user-supplied shell commands.",
            "Validate arguments against each scanner's supported configuration.",
            "Support execution deadlines and cancellation.",
            "Capture standard output and standard error with bounded buffers.",
            "Record exit codes and execution metadata.",
            "Ensure processes inherit only the minimum required environment variables.",
            "Avoid leaking secrets through process arguments or logs."
        ],
        "acceptance_criteria": [
            "External scanners are invoked through the shared abstraction.",
            "Shell-based command construction is not used.",
            "Argument validation is enforced.",
            "Timeouts and cancellation are supported.",
            "Output capture is bounded.",
            "Tests cover malicious input, invalid arguments, and process failures."
        ]
    },
    {
        "id": "P2-10",
        "slug": "P2-10_BUILD_SCANNER_ADAPTER_CONFORMANCE_TEST_HARNESS",
        "title": "Build the Scanner Adapter Conformance Test Harness",
        "workstream": "Workstream A — Scanner Architecture & Integration Foundation",
        "workstream_label": "workstream/a-foundation",
        "area_label": "area/worker",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Create reusable tests that verify whether a scanner adapter follows KELVIN's integration contract.",
        "requirements": [
            "Build a reusable adapter test harness.",
            "Test initialization, configuration validation, execution, cancellation, and output handling.",
            "Support fake scanner processes for deterministic tests.",
            "Include fixtures for valid output, malformed output, empty output, partial output, and scanner failure.",
            "Verify that adapters preserve correlation identifiers.",
            "Verify that adapter errors use standard KELVIN error semantics.",
            "Make the harness usable by future scanner integrations."
        ],
        "acceptance_criteria": [
            "The harness can test any conforming adapter.",
            "At least one external scanner adapter and one built-in adapter pass the harness.",
            "Failure scenarios are covered.",
            "Tests run in CI without requiring unrestricted internet access.",
            "Usage documentation is available."
        ]
    },

    # Workstream B
    {
        "id": "P2-11",
        "slug": "P2-11_IMPLEMENT_HTTP_HTTPS_PREFLIGHT_ASSESSMENT_ADAPTER",
        "title": "Implement the HTTP/HTTPS Preflight Assessment Adapter",
        "workstream": "Workstream B — MVP Scanner Integrations",
        "workstream_label": "workstream/b-integrations",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Implement a built-in adapter that verifies whether an approved web target is reachable before more expensive scanner execution begins.",
        "requirements": [
            "Support approved HTTP and HTTPS targets.",
            "Perform bounded connection and response checks.",
            "Capture response status, protocol information, and relevant timing metadata.",
            "Handle connection failures, TLS failures, and timeout conditions.",
            "Respect the validated target and redirect restrictions from Phase 1.",
            "Avoid crawling or recursively discovering unrelated targets.",
            "Record clear preflight outcomes.",
            "Ensure preflight checks cannot bypass the approved target scope."
        ],
        "acceptance_criteria": [
            "The adapter supports approved HTTP/HTTPS targets.",
            "Reachability and failure states are represented consistently.",
            "Redirects are subject to scope validation.",
            "Requests have bounded timeouts.",
            "Unit and integration tests cover common network conditions."
        ]
    },
    {
        "id": "P2-12",
        "slug": "P2-12_IMPLEMENT_SAFE_REDIRECT_CHAIN_EVALUATION",
        "title": "Implement Safe Redirect Chain Evaluation",
        "workstream": "Workstream B — MVP Scanner Integrations",
        "workstream_label": "workstream/b-integrations",
        "area_label": "area/security",
        "kind_label": "kind/feature",
        "priority_label": "priority/critical",
        "purpose": "Ensure scanners handle redirects without escaping the authorized assessment scope.",
        "requirements": [
            "Define how redirect responses are evaluated.",
            "Validate every redirect destination against the approved scope.",
            "Reject redirects to unapproved hosts, addresses, schemes, and ports.",
            "Enforce a maximum redirect count.",
            "Detect redirect loops.",
            "Avoid trusting scanner-reported final URLs without independent validation.",
            "Ensure DNS resolution and network destination checks remain consistent with Phase 1 protections.",
            "Record blocked redirects as structured diagnostics."
        ],
        "acceptance_criteria": [
            "Each redirect destination is validated before being followed.",
            "Out-of-scope redirects are blocked.",
            "Redirect loops and excessive chains are handled safely.",
            "Redirect behavior is covered by automated tests.",
            "Blocked redirects are observable in assessment diagnostics."
        ]
    },
    {
        "id": "P2-13",
        "slug": "P2-13_IMPLEMENT_TLS_CONFIGURATION_ASSESSMENT_ADAPTER",
        "title": "Implement the TLS Configuration Assessment Adapter",
        "workstream": "Workstream B — MVP Scanner Integrations",
        "workstream_label": "workstream/b-integrations",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Provide a built-in or controlled-tool adapter for evaluating the TLS configuration of approved HTTPS targets.",
        "requirements": [
            "Define the TLS assessment implementation and its dependency strategy.",
            "Evaluate certificate validity and expiration.",
            "Capture certificate chain information where available.",
            "Evaluate supported TLS protocol versions.",
            "Identify weak or deprecated configuration according to the approved rule set.",
            "Record handshake and connection failures separately from security findings.",
            "Avoid intrusive TLS testing that could disrupt the target.",
            "Version the TLS assessment rules."
        ],
        "acceptance_criteria": [
            "The adapter evaluates approved HTTPS targets.",
            "Certificate and protocol information is captured.",
            "Findings are returned through the common output envelope.",
            "Rule versions are traceable.",
            "Tests cover valid certificates, expired certificates, protocol issues, and connection failures."
        ]
    },
    {
        "id": "P2-14",
        "slug": "P2-14_IMPLEMENT_HTTP_SECURITY_HEADER_AND_COOKIE_CHECKS",
        "title": "Implement HTTP Security Header and Cookie Checks",
        "workstream": "Workstream B — MVP Scanner Integrations",
        "workstream_label": "workstream/b-integrations",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Implement KELVIN-native checks for common HTTP security configuration weaknesses.",
        "requirements": [
            "Inspect relevant response headers.",
            "Evaluate the presence and configuration of applicable security headers.",
            "Inspect cookie attributes such as Secure, HttpOnly, and SameSite where applicable.",
            "Avoid making assumptions where the response context is insufficient.",
            "Define detection rules and expected behavior for each check.",
            "Assign preliminary severity and confidence according to documented rules.",
            "Record the response context required to explain each result.",
            "Version the rules independently from scanner releases."
        ],
        "acceptance_criteria": [
            "Header and cookie checks execute through a built-in adapter.",
            "Each rule has documented detection logic.",
            "Findings include evidence sufficient for later review.",
            "False-positive-sensitive checks have explicit confidence handling.",
            "Automated fixtures verify expected outcomes."
        ]
    },
    {
        "id": "P2-15",
        "slug": "P2-15_INTEGRATE_OWASP_ZAP_BASELINE_SCANNER",
        "title": "Integrate OWASP ZAP Baseline Scanner",
        "workstream": "Workstream B — MVP Scanner Integrations",
        "workstream_label": "workstream/b-integrations",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/scanner-integration",
        "priority_label": "priority/critical",
        "purpose": "Integrate OWASP ZAP Baseline as the first external web application security scanner.",
        "requirements": [
            "Implement a Go adapter for the approved ZAP runtime.",
            "Pass only validated targets and approved scanner configuration.",
            "Collect scanner output through the defined output contract.",
            "Capture scanner version and execution metadata.",
            "Support bounded execution time and cancellation.",
            "Handle non-zero exit codes and malformed output.",
            "Ensure the integration uses the approved baseline mode.",
            "Prevent direct user access to arbitrary ZAP command-line options."
        ],
        "acceptance_criteria": [
            "ZAP Baseline can execute through KELVIN's worker architecture.",
            "Results are captured and returned through the common output envelope.",
            "Execution limits and cancellation work.",
            "Scanner version is recorded.",
            "Automated adapter tests pass."
        ]
    },
    {
        "id": "P2-16",
        "slug": "P2-16_DEFINE_AND_ENFORCE_ZAP_BASELINE_SAFETY_PROFILE",
        "title": "Define and Enforce the ZAP Baseline Safety Profile",
        "workstream": "Workstream B — MVP Scanner Integrations",
        "workstream_label": "workstream/b-integrations",
        "area_label": "area/security",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Ensure that the ZAP integration uses an approved, predictable scanning configuration suitable for the KELVIN MVP.",
        "requirements": [
            "Define the permitted ZAP Baseline execution options.",
            "Explicitly prohibit switching to unrestricted active scanning through ordinary assessment configuration.",
            "Define request and duration limits.",
            "Restrict crawling behavior to approved targets.",
            "Ensure redirects and discovered URLs remain inside the authorized scope.",
            "Review default rules for operational impact.",
            "Document expected target traffic and potential service impact.",
            "Version the approved ZAP configuration."
        ],
        "acceptance_criteria": [
            "A versioned ZAP Baseline profile exists.",
            "The adapter cannot enable unrestricted active scanning.",
            "Request and duration limits are enforced.",
            "Scope restrictions apply to discovered URLs.",
            "Safety behavior is tested and documented."
        ]
    },
    {
        "id": "P2-17",
        "slug": "P2-17_INTEGRATE_NUCLEI_THROUGH_A_CONTROLLED_ADAPTER",
        "title": "Integrate Nuclei Through a Controlled Adapter",
        "workstream": "Workstream B — MVP Scanner Integrations",
        "workstream_label": "workstream/b-integrations",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/scanner-integration",
        "priority_label": "priority/critical",
        "purpose": "Integrate Nuclei as an additional scanner while preventing arbitrary or unsafe template execution.",
        "requirements": [
            "Implement a Go adapter for the approved Nuclei runtime.",
            "Pass only validated targets.",
            "Use an approved template catalog.",
            "Restrict template selection to catalog identifiers.",
            "Record Nuclei version and template catalog version.",
            "Capture structured output.",
            "Support bounded execution time and cancellation.",
            "Ensure user configuration cannot inject arbitrary templates, code, or executable options.",
            "Handle scanner errors and partial output consistently."
        ],
        "acceptance_criteria": [
            "Nuclei executes through the KELVIN worker architecture.",
            "Only approved templates can be selected.",
            "Scanner metadata is captured.",
            "Output follows the common envelope.",
            "Cancellation, timeouts, and malformed output are tested."
        ]
    },
    {
        "id": "P2-18",
        "slug": "P2-18_ESTABLISH_CURATED_NUCLEI_TEMPLATE_CATALOG",
        "title": "Establish a Curated Nuclei Template Catalog",
        "workstream": "Workstream B — MVP Scanner Integrations",
        "workstream_label": "workstream/b-integrations",
        "area_label": "area/security",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Define a controlled collection of Nuclei templates that KELVIN permits in its MVP assessments.",
        "requirements": [
            "Establish a template review and approval process.",
            "Include only templates that satisfy the MVP's safety requirements.",
            "Review template request behavior, external interactions, and potential impact.",
            "Exclude intrusive, destructive, denial-of-service, and exploit-oriented templates from the default catalog.",
            "Record template identifiers, sources, versions, and review status.",
            "Define an update and rollback process.",
            "Ensure template changes are reviewed and tested before release.",
            "Prevent unreviewed upstream changes from being loaded automatically."
        ],
        "acceptance_criteria": [
            "A versioned, curated catalog exists.",
            "Each included template has review metadata.",
            "Disallowed templates cannot be selected.",
            "Template catalog changes are traceable.",
            "CI or an equivalent validation process verifies catalog integrity."
        ]
    },
    {
        "id": "P2-19",
        "slug": "P2-19_IMPLEMENT_MVP_ASSESSMENT_PROFILE_DEFINITIONS",
        "title": "Implement MVP Assessment Profile Definitions",
        "workstream": "Workstream B — MVP Scanner Integrations",
        "workstream_label": "workstream/b-integrations",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Connect Phase 1's scan profile model to the actual scanner integrations delivered in Phase 2.",
        "requirements": [
            "Implement the initial assessment profiles approved for the MVP.",
            "Map each profile to its permitted scanner adapters and configurations.",
            "Define scanner order and execution dependencies.",
            "Define which checks can run independently.",
            "Ensure profiles cannot exceed the platform's safety and resource policies.",
            "Version profile definitions.",
            "Validate the profile before creating scanner executions.",
            "Keep profile configuration independent of scanner-specific implementation details."
        ],
        "acceptance_criteria": [
            "Approved profiles can be selected for assessments.",
            "Each profile maps to supported scanner capabilities.",
            "Invalid or unsupported combinations are rejected.",
            "Profile versions are traceable.",
            "Profile execution is covered by tests."
        ]
    },
    {
        "id": "P2-20",
        "slug": "P2-20_IMPLEMENT_SCANNER_AVAILABILITY_AND_RUNTIME_READINESS_CHECKS",
        "title": "Implement Scanner Availability and Runtime Readiness Checks",
        "workstream": "Workstream B — MVP Scanner Integrations",
        "workstream_label": "workstream/b-integrations",
        "area_label": "area/worker",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Ensure that KELVIN can determine whether each scanner is ready before attempting execution.",
        "requirements": [
            "Verify required scanner binaries or runtime images are available.",
            "Verify scanner version compatibility.",
            "Verify required configuration and template catalogs exist.",
            "Detect missing or corrupted runtime dependencies.",
            "Expose scanner-specific readiness information through the appropriate internal health interfaces.",
            "Distinguish application health from individual scanner availability.",
            "Prevent unavailable scanners from being selected for new executions.",
            "Avoid exposing internal runtime details through public health endpoints."
        ],
        "acceptance_criteria": [
            "Scanner readiness can be evaluated independently.",
            "Missing dependencies are detected before execution.",
            "Unavailable scanners are reported accurately.",
            "Readiness failures are logged with correlation information.",
            "Tests cover missing, incompatible, and ready scanner states."
        ]
    },

    # Workstream C
    {
        "id": "P2-21",
        "slug": "P2-21_INTEGRATE_SCANNER_ADAPTERS_WITH_THE_ASSESSMENT_WORKER",
        "title": "Integrate Scanner Adapters with the Assessment Worker",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/worker",
        "kind_label": "kind/feature",
        "priority_label": "priority/critical",
        "purpose": "Connect the Phase 1 assessment worker and queue foundations to the scanner adapter system.",
        "requirements": [
            "Resolve scanner adapters from the registry.",
            "Load the validated assessment execution context.",
            "Execute the scanners selected by the assessment profile.",
            "Use existing Phase 1 job lifecycle and queue contracts.",
            "Keep worker orchestration separate from scanner-specific logic.",
            "Ensure failures are reported through the established lifecycle.",
            "Preserve assessment and tenant context throughout execution.",
            "Prevent workers from accepting unvalidated execution requests."
        ],
        "acceptance_criteria": [
            "Assessment jobs can trigger registered scanner adapters.",
            "Existing Phase 1 lifecycle semantics are preserved.",
            "Worker execution is independent of scanner implementation details.",
            "Failures are reflected in the established job state model.",
            "Integration tests cover complete worker execution."
        ]
    },
    {
        "id": "P2-22",
        "slug": "P2-22_IMPLEMENT_PER_ASSESSMENT_WORKSPACE_MANAGEMENT",
        "title": "Implement Per-Assessment Workspace Management",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/worker",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Provide isolated temporary storage for scanner configuration, intermediate data, and execution output.",
        "requirements": [
            "Create a dedicated workspace for each assessment execution.",
            "Ensure workspaces cannot be accessed by unrelated assessments or tenants.",
            "Define safe locations for configuration, temporary files, and output.",
            "Use unique execution identifiers for workspace paths.",
            "Prevent path traversal through user-controlled filenames.",
            "Define workspace ownership and permission rules.",
            "Ensure interrupted executions do not leave uncontrolled temporary data.",
            "Integrate cleanup with the existing job recovery and evidence lifecycle design."
        ],
        "acceptance_criteria": [
            "Each execution receives an isolated workspace.",
            "Cross-assessment access is prevented.",
            "Temporary files use controlled paths and permissions.",
            "Workspaces are cleaned up according to policy.",
            "Cleanup behavior is tested under success, failure, and cancellation."
        ]
    },
    {
        "id": "P2-23",
        "slug": "P2-23_APPLY_SCANNER_SPECIFIC_NETWORK_EGRESS_POLICIES",
        "title": "Apply Scanner-Specific Network Egress Policies",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/security",
        "kind_label": "kind/security",
        "priority_label": "priority/critical",
        "purpose": "Apply the Phase 1 network isolation architecture to each scanner runtime.",
        "requirements": [
            "Define network egress requirements for each scanner.",
            "Allow only the minimum network communication needed for an approved assessment.",
            "Ensure scanners cannot use unrestricted network access.",
            "Apply target scope restrictions consistently across built-in and external scanners.",
            "Restrict unexpected outbound callbacks and unrelated network destinations.",
            "Ensure scanner configuration cannot weaken network policy.",
            "Document how DNS resolution, redirects, and resolved network destinations are handled.",
            "Test policy enforcement at the execution boundary."
        ],
        "acceptance_criteria": [
            "Each scanner has a documented egress policy.",
            "Scanner execution cannot bypass Phase 1 network restrictions.",
            "Unauthorized outbound destinations are blocked.",
            "Network policy failures are observable.",
            "Integration tests verify permitted and prohibited network behavior."
        ]
    },
    {
        "id": "P2-24",
        "slug": "P2-24_APPLY_SCANNER_SPECIFIC_RESOURCE_LIMITS",
        "title": "Apply Scanner-Specific Resource Limits",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/worker",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Configure and enforce resource constraints for the different scanner runtimes.",
        "requirements": [
            "Define CPU, memory, process, and temporary-storage limits for each scanner.",
            "Establish safe defaults and configurable platform-level ceilings.",
            "Ensure scanner-specific settings cannot exceed platform limits.",
            "Capture resource exhaustion as a structured execution failure.",
            "Define behavior when a scanner exceeds its resource budget.",
            "Prevent a single assessment from monopolizing worker resources.",
            "Document the expected resource requirements for each scanner."
        ],
        "acceptance_criteria": [
            "Each scanner has approved resource limits.",
            "Limits are enforced by the execution environment.",
            "Resource exhaustion is reported consistently.",
            "User configuration cannot bypass platform ceilings.",
            "Tests verify enforcement and failure handling."
        ]
    },
    {
        "id": "P2-25",
        "slug": "P2-25_ENFORCE_SCANNER_EXECUTION_DEADLINES",
        "title": "Enforce Scanner Execution Deadlines",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/worker",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Ensure each scanner execution is bounded by an explicit deadline.",
        "requirements": [
            "Define scanner-level and assessment-level execution deadlines.",
            "Ensure scanner deadlines cannot exceed the assessment's overall deadline.",
            "Propagate deadlines from the assessment context to scanner adapters.",
            "Handle scanners that do not terminate within their allotted time.",
            "Record timeout reason and execution duration.",
            "Distinguish execution timeout from connection timeout.",
            "Ensure timeout handling does not leave orphaned processes."
        ],
        "acceptance_criteria": [
            "Every scanner execution has an effective deadline.",
            "Scanner deadlines respect assessment-level limits.",
            "Expired executions are stopped.",
            "Timeout states are recorded consistently.",
            "Tests cover scanner and overall assessment timeouts."
        ]
    },
    {
        "id": "P2-26",
        "slug": "P2-26_IMPLEMENT_FULL_SCANNER_PROCESS_CANCELLATION",
        "title": "Implement Full Scanner Process Cancellation",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/worker",
        "kind_label": "kind/feature",
        "priority_label": "priority/critical",
        "purpose": "Ensure cancelling an assessment terminates the associated scanner process and its child processes.",
        "requirements": [
            "Connect existing Phase 1 cancellation semantics to scanner execution.",
            "Propagate cancellation signals to active adapters.",
            "Terminate the full process tree or isolated execution container as appropriate.",
            "Prevent orphaned subprocesses.",
            "Stop collecting new scanner output after cancellation.",
            "Preserve already collected valid diagnostics.",
            "Distinguish user cancellation from timeout and infrastructure termination.",
            "Ensure cancellation is safe when requested repeatedly."
        ],
        "acceptance_criteria": [
            "Cancelling an assessment stops associated scanner execution.",
            "Child processes are terminated.",
            "Repeated cancellation requests are handled safely.",
            "Final execution state accurately reflects cancellation.",
            "Automated tests verify cleanup and absence of orphan processes."
        ]
    },
    {
        "id": "P2-27",
        "slug": "P2-27_INTEGRATE_SCANNER_PROGRESS_REPORTING",
        "title": "Integrate Scanner Progress Reporting",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/worker",
        "kind_label": "kind/feature",
        "priority_label": "priority/medium",
        "purpose": "Expose meaningful execution progress from the assessment engine without depending on scanner-specific output formats.",
        "requirements": [
            "Define normalized execution stages: Preflight, Scanner initialization, Scanner execution, Output collection, Result normalization, Completion.",
            "Allow adapters to report supported progress information.",
            "Avoid fabricating percentage completion when a scanner cannot provide reliable progress.",
            "Publish progress through the existing assessment lifecycle mechanisms.",
            "Record stage transitions with timestamps.",
            "Ensure progress reporting does not expose sensitive scanner output."
        ],
        "acceptance_criteria": [
            "Assessment execution stages are observable.",
            "Supported scanner progress is mapped consistently.",
            "Unknown progress is represented honestly.",
            "Stage transitions are traceable.",
            "Tests cover normal and interrupted execution."
        ]
    },
    {
        "id": "P2-28",
        "slug": "P2-28_IMPLEMENT_ASSESSMENT_CONCURRENCY_CONTROLS",
        "title": "Implement Assessment Concurrency Controls",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/worker",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Prevent uncontrolled simultaneous scanner execution from exhausting platform resources or overwhelming targets.",
        "requirements": [
            "Define global concurrency limits.",
            "Define per-tenant concurrency limits.",
            "Define scanner-specific concurrency limits.",
            "Integrate concurrency controls with the existing queue architecture.",
            "Handle queued work when capacity is unavailable.",
            "Prevent race conditions when acquiring and releasing execution capacity.",
            "Ensure crashed workers do not permanently consume concurrency slots.",
            "Define observable capacity and saturation metrics."
        ],
        "acceptance_criteria": [
            "Global and per-tenant concurrency limits are enforced.",
            "Scanner-specific caps are respected.",
            "Capacity is released after success, failure, timeout, or worker recovery.",
            "Concurrent execution tests pass.",
            "Queue saturation is observable."
        ]
    },
    {
        "id": "P2-29",
        "slug": "P2-29_IMPLEMENT_PER_TARGET_REQUEST_PACING",
        "title": "Implement Per-Target Request Pacing",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/security",
        "kind_label": "kind/security",
        "priority_label": "priority/high",
        "purpose": "Control the rate at which scanners send requests to a target.",
        "requirements": [
            "Define request pacing defaults for each scanner.",
            "Support platform-enforced request-rate ceilings.",
            "Apply limits consistently to built-in checks and scanner adapters.",
            "Prevent users from setting rates above approved limits.",
            "Define how redirects and requests to discovered URLs are accounted for.",
            "Distinguish request pacing from worker concurrency.",
            "Record throttling events where useful for diagnostics.",
            "Document how pacing affects assessment duration."
        ],
        "acceptance_criteria": [
            "Request-rate limits are enforced.",
            "Scanner configuration cannot bypass platform ceilings.",
            "Per-target pacing is applied consistently.",
            "Throttling behavior is testable and observable.",
            "Tests verify rate enforcement under concurrent execution."
        ]
    },
    {
        "id": "P2-30",
        "slug": "P2-30_DEFINE_SCANNER_FAILURE_CLASSIFICATION",
        "title": "Define Scanner Failure Classification",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Create consistent failure categories so the assessment engine can distinguish scanner problems from target and infrastructure problems.",
        "requirements": [
            "Define standard failure categories, including: Invalid scanner configuration, Unsupported scanner version, Target connection failure, Scope restriction failure, Scanner process failure, Scanner timeout, Resource exhaustion, Output parsing failure, Worker infrastructure failure.",
            "Map scanner-specific exit codes and error messages into standard categories.",
            "Avoid relying entirely on free-text error messages.",
            "Define which failures are terminal and which may be retryable.",
            "Ensure diagnostic details do not leak secrets."
        ],
        "acceptance_criteria": [
            "A common scanner failure taxonomy exists.",
            "Each integrated scanner maps known failures into it.",
            "Unknown failures are represented safely.",
            "Failure categories are available to orchestration logic.",
            "Tests verify representative failure mappings."
        ]
    },
    {
        "id": "P2-31",
        "slug": "P2-31_IMPLEMENT_SAFE_SCANNER_RETRY_POLICIES",
        "title": "Implement Safe Scanner Retry Policies",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/worker",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Define when scanner execution may be retried without creating uncontrolled repeated target traffic or duplicate assessment results.",
        "requirements": [
            "Define retry policies per scanner and failure category.",
            "Retry only failures classified as safe and transient.",
            "Do not retry invalid configuration, authorization failures, or scope violations.",
            "Use bounded retry counts and backoff.",
            "Respect assessment deadlines and request budgets.",
            "Integrate with Phase 1 idempotency and recovery semantics.",
            "Record each retry attempt and its reason.",
            "Prevent queue redelivery from creating uncontrolled repeated execution."
        ],
        "acceptance_criteria": [
            "Retry rules are documented and implemented.",
            "Retry attempts are bounded.",
            "Non-retryable failures are not retried.",
            "Retries respect deadlines and resource limits.",
            "Tests cover transient failure, permanent failure, and repeated delivery."
        ]
    },
    {
        "id": "P2-32",
        "slug": "P2-32_DEFINE_PARTIAL_ASSESSMENT_COMPLETION_SEMANTICS",
        "title": "Define Partial Assessment Completion Semantics",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Represent assessments where some scanner integrations succeed while others fail or become unavailable.",
        "requirements": [
            "Define how the system handles a profile containing multiple scanners.",
            "Distinguish: Fully completed assessment, Completed with warnings, Partially completed assessment, Failed assessment, Cancelled assessment.",
            "Preserve valid results from successful scanners.",
            "Record which scanners completed and which did not.",
            "Define whether dependent checks should continue after a scanner fails.",
            "Avoid presenting a partial result as a complete assessment."
        ],
        "acceptance_criteria": [
            "Partial execution states are defined.",
            "Successful scanner results remain available when another scanner fails.",
            "Failed scanner executions have explicit status and diagnostics.",
            "Overall assessment status reflects the actual outcome.",
            "Tests cover mixed success and failure scenarios."
        ]
    },
    {
        "id": "P2-33",
        "slug": "P2-33_IMPLEMENT_BOUNDED_SCANNER_OUTPUT_CAPTURE",
        "title": "Implement Bounded Scanner Output Capture",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/worker",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Capture scanner output safely without allowing excessive output to exhaust memory or storage.",
        "requirements": [
            "Capture standard output and standard error separately.",
            "Define maximum output sizes.",
            "Support streaming or chunked collection for larger outputs.",
            "Detect truncated output.",
            "Handle invalid encodings and malformed content.",
            "Avoid unbounded in-memory buffering.",
            "Ensure output capture continues to respect cancellation and execution deadlines.",
            "Record whether output was complete or truncated."
        ],
        "acceptance_criteria": [
            "Output capture is bounded.",
            "Large output cannot exhaust worker memory.",
            "Truncated output is identified.",
            "Standard output and error remain distinguishable.",
            "Tests cover empty, normal, oversized, and malformed output."
        ]
    },
    {
        "id": "P2-34",
        "slug": "P2-34_IMPLEMENT_RAW_SCANNER_OUTPUT_STAGING_AND_CLEANUP",
        "title": "Implement Raw Scanner Output Staging and Cleanup",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/worker",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Manage raw scanner output before it is validated and normalized.",
        "requirements": [
            "Define where raw output is temporarily stored.",
            "Use assessment-specific workspace boundaries.",
            "Ensure raw output is not exposed as trusted finding data.",
            "Integrate retention and cleanup with the Phase 1 evidence lifecycle policy.",
            "Prevent one tenant from accessing another tenant's raw output.",
            "Handle incomplete output after crashes and cancellation.",
            "Record cleanup failures for operational review.",
            "Avoid retaining unnecessary duplicate copies of sensitive output."
        ],
        "acceptance_criteria": [
            "Raw scanner output has a controlled storage lifecycle.",
            "Temporary output is isolated by assessment.",
            "Cleanup follows approved retention rules.",
            "Failed cleanup is observable.",
            "Tests cover normal cleanup and interrupted execution."
        ]
    },
    {
        "id": "P2-35",
        "slug": "P2-35_RECORD_IMMUTABLE_ASSESSMENT_EXECUTION_MANIFESTS",
        "title": "Record Immutable Assessment Execution Manifests",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/database",
        "kind_label": "kind/security",
        "priority_label": "priority/high",
        "purpose": "Make each assessment execution reproducible and auditable by recording the exact configuration and runtime components used.",
        "requirements": [
            "Create an execution manifest at assessment start.",
            "Record: Assessment profile and version, Scanner identifiers and versions, Scanner image digests, Ruleset or template catalog versions, Validated target reference, Effective resource and timeout limits, Execution start time.",
            "Ensure the manifest cannot be silently modified after execution begins.",
            "Record relevant configuration changes as separate events.",
            "Avoid storing secrets or unnecessary sensitive configuration values."
        ],
        "acceptance_criteria": [
            "Each assessment has an execution manifest.",
            "Scanner and ruleset versions are traceable.",
            "Effective configuration is recorded.",
            "The manifest is protected from silent modification.",
            "Tests verify manifest completeness and immutability."
        ]
    },
    {
        "id": "P2-36",
        "slug": "P2-36_IMPLEMENT_SCANNER_EXECUTION_PROVENANCE_AND_DIAGNOSTICS",
        "title": "Implement Scanner Execution Provenance and Diagnostics",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/worker",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Provide sufficient operational information to understand how a scanner executed and why it produced a particular outcome.",
        "requirements": [
            "Record scanner start and completion events.",
            "Capture execution duration and exit status.",
            "Associate diagnostics with assessment and scanner identifiers.",
            "Include correlation IDs and relevant trace context.",
            "Record retries, timeouts, cancellations, and resource failures.",
            "Redact secrets and sensitive values.",
            "Separate operational diagnostics from normalized security findings.",
            "Use the structured logging and audit foundations established in Phase 1."
        ],
        "acceptance_criteria": [
            "Scanner executions have traceable provenance.",
            "Diagnostics can be associated with the correct assessment.",
            "Sensitive values are redacted.",
            "Operational logs do not become finding records.",
            "Tests verify expected diagnostic events."
        ]
    },
    {
        "id": "P2-37",
        "slug": "P2-37_VALIDATE_SCANNER_REPORTED_TARGETS_AGAINST_ASSESSMENT_SCOPE",
        "title": "Validate Scanner-Reported Targets Against Assessment Scope",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/security",
        "kind_label": "kind/security",
        "priority_label": "priority/critical",
        "purpose": "Ensure that output from scanners cannot introduce findings or follow-up targets outside the approved assessment scope.",
        "requirements": [
            "Validate hostnames, URLs, ports, and other target references reported by scanners.",
            "Reuse the Phase 1 canonical target and scope validation rules.",
            "Reject or quarantine results that reference unauthorized targets.",
            "Do not automatically launch follow-up scans based on scanner output.",
            "Record rejected references as structured diagnostics.",
            "Ensure parser implementations cannot bypass scope enforcement.",
            "Define how findings referring to third-party resources are represented."
        ],
        "acceptance_criteria": [
            "Scanner-reported targets are independently validated.",
            "Out-of-scope references cannot trigger additional scanning.",
            "Unauthorized target references are handled consistently.",
            "Rejections are traceable.",
            "Automated tests cover out-of-scope scanner output."
        ]
    },
    {
        "id": "P2-38",
        "slug": "P2-38_HARDEN_SCANNER_OUTPUT_PARSING_AGAINST_UNTRUSTED_DATA",
        "title": "Harden Scanner Output Parsing Against Untrusted Data",
        "workstream": "Workstream C — Worker Execution & Orchestration",
        "workstream_label": "workstream/c-worker-orchestration",
        "area_label": "area/security",
        "kind_label": "kind/security",
        "priority_label": "priority/critical",
        "purpose": "Treat scanner output as untrusted input and prevent malformed or malicious output from compromising KELVIN.",
        "requirements": [
            "Validate input formats before parsing.",
            "Apply maximum document size, nesting, and field-length limits.",
            "Reject malformed or unsupported structures safely.",
            "Prevent path traversal through output-provided filenames.",
            "Avoid unsafe deserialization and dynamic code execution.",
            "Sanitize values before logging or displaying them.",
            "Ensure parser failures cannot crash unrelated worker executions.",
            "Add adversarial fixtures for malformed and unexpected scanner output."
        ],
        "acceptance_criteria": [
            "Parsers enforce size and structure limits.",
            "Malformed output fails safely.",
            "Scanner-provided values cannot trigger unsafe file or process operations.",
            "Parser errors are observable.",
            "Security-focused parser tests pass."
        ]
    },

    # Workstream D
    {
        "id": "P2-39",
        "slug": "P2-39_IMPLEMENT_OWASP_ZAP_OUTPUT_PARSER",
        "title": "Implement OWASP ZAP Output Parser",
        "workstream": "Workstream D — Result Parsing & Normalization",
        "workstream_label": "workstream/d-normalization",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Convert ZAP Baseline output into KELVIN's internal scanner result representation.",
        "requirements": [
            "Support the approved ZAP output format.",
            "Parse alert identifiers, names, descriptions, risk levels, affected URLs, and available evidence.",
            "Preserve ZAP-specific metadata.",
            "Handle missing optional fields.",
            "Reject malformed or unsupported output safely.",
            "Track parser and format versions.",
            "Keep parsing separate from scanner execution.",
            "Ensure extracted target references undergo scope validation."
        ],
        "acceptance_criteria": [
            "Valid ZAP fixtures are parsed correctly.",
            "Missing and malformed fields are handled safely.",
            "ZAP metadata is preserved.",
            "Output conforms to the common scanner result envelope.",
            "Parser tests cover representative alerts and failure cases."
        ]
    },
    {
        "id": "P2-40",
        "slug": "P2-40_IMPLEMENT_NUCLEI_OUTPUT_PARSER",
        "title": "Implement Nuclei Output Parser",
        "workstream": "Workstream D — Result Parsing & Normalization",
        "workstream_label": "workstream/d-normalization",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Convert structured Nuclei output into KELVIN's internal scanner result representation.",
        "requirements": [
            "Support the approved structured output format.",
            "Parse template identifiers, names, severity, matched locations, descriptions, and available evidence.",
            "Preserve template and scanner version information.",
            "Handle optional and missing fields.",
            "Reject malformed records without crashing the assessment worker.",
            "Validate reported targets against assessment scope.",
            "Prevent untrusted output fields from being interpreted as executable instructions."
        ],
        "acceptance_criteria": [
            "Valid Nuclei fixtures are parsed correctly.",
            "Template identifiers and metadata are preserved.",
            "Invalid records are handled safely.",
            "Reported targets are scope-validated.",
            "Parser tests cover valid, partial, and malformed records."
        ]
    },
    {
        "id": "P2-41",
        "slug": "P2-41_IMPLEMENT_BUILT_IN_HTTP_AND_TLS_RESULT_PARSERS",
        "title": "Implement Built-In HTTP and TLS Result Parsers",
        "workstream": "Workstream D — Result Parsing & Normalization",
        "workstream_label": "workstream/d-normalization",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Normalize the structured output generated by KELVIN's built-in HTTP, cookie, header, and TLS checks.",
        "requirements": [
            "Define parsing logic for each built-in assessment adapter.",
            "Convert individual check outcomes into the common scanner result representation.",
            "Preserve the specific rule identifier and version.",
            "Capture relevant response or certificate evidence.",
            "Distinguish a confirmed configuration issue from an inconclusive check.",
            "Handle unavailable or incomplete target responses.",
            "Ensure outputs follow the same validation rules as external scanner results."
        ],
        "acceptance_criteria": [
            "Built-in check results use the common result representation.",
            "Rule identifiers and versions are preserved.",
            "Inconclusive checks are not represented as confirmed findings.",
            "Evidence fields are validated.",
            "Automated tests cover each built-in rule family."
        ]
    },
    {
        "id": "P2-42",
        "slug": "P2-42_NORMALIZE_SCANNER_RESULTS_INTO_CANONICAL_FINDING_SCHEMA",
        "title": "Normalize Scanner Results into the Canonical Finding Schema",
        "workstream": "Workstream D — Result Parsing & Normalization",
        "workstream_label": "workstream/d-normalization",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/critical",
        "purpose": "Convert scanner-specific results into the canonical finding and evidence model established in Phase 1.",
        "requirements": [
            "Implement a shared normalization layer.",
            "Map scanner-specific fields to the Phase 1 finding schema (`finding.v1.json`).",
            "Preserve scanner source and rule identifiers.",
            "Map affected target references.",
            "Map descriptions, evidence, and relevant metadata.",
            "Ensure every normalized finding references its assessment and source scanner.",
            "Handle incomplete records consistently.",
            "Avoid changing the Phase 1 canonical schema without an approved schema or ADR update."
        ],
        "acceptance_criteria": [
            "All MVP scanner adapters produce normalized findings.",
            "Normalized findings satisfy the canonical schema.",
            "Source scanner metadata is retained.",
            "Invalid records are rejected or quarantined safely.",
            "Contract tests verify normalized output across all integrations."
        ]
    },
    {
        "id": "P2-43",
        "slug": "P2-43_IMPLEMENT_SEVERITY_AND_CONFIDENCE_MAPPING",
        "title": "Implement Severity and Confidence Mapping",
        "workstream": "Workstream D — Result Parsing & Normalization",
        "workstream_label": "workstream/d-normalization",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Translate scanner-specific severity and confidence indicators into KELVIN's common classification model.",
        "requirements": [
            "Define mappings from each scanner's severity levels to KELVIN's canonical severity values (`INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).",
            "Document differences between scanner severity models.",
            "Preserve original scanner severity.",
            "Define how confidence or certainty is represented (`LOW`, `MEDIUM`, `HIGH`, `CONFIRMED`).",
            "Avoid assigning unsupported confidence values.",
            "Handle missing or unknown severity explicitly.",
            "Version the mapping rules.",
            "Keep advanced business risk scoring and cross-finding prioritization deferred to Phase 3."
        ],
        "acceptance_criteria": [
            "Every MVP scanner has a documented severity mapping.",
            "Original scanner severity remains available.",
            "Unknown severity is handled consistently.",
            "Confidence is not fabricated when unavailable.",
            "Mapping tests cover all supported values."
        ]
    },
    {
        "id": "P2-44",
        "slug": "P2-44_IMPLEMENT_NORMALIZED_RESULT_VALIDATION_AND_COMPLETENESS_CHECKS",
        "title": "Implement Normalized Result Validation and Completeness Checks",
        "workstream": "Workstream D — Result Parsing & Normalization",
        "workstream_label": "workstream/d-normalization",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/high",
        "purpose": "Ensure that normalized scanner results satisfy KELVIN's data quality and integrity requirements before being accepted by downstream modules.",
        "requirements": [
            "Validate normalized finding structures against the canonical schema.",
            "Check required identifiers and assessment references.",
            "Verify scanner provenance.",
            "Validate target references and evidence structures.",
            "Reject unsupported severity values.",
            "Detect malformed records and duplicate records within a single parser response where safe to do so, without implementing cross-assessment finding correlation.",
            "Record rejected record counts and reasons.",
            "Distinguish parser success from result validation success."
        ],
        "acceptance_criteria": [
            "Normalized results undergo validation before acceptance.",
            "Invalid records cannot silently enter the trusted result store.",
            "Rejection reasons are recorded.",
            "Validation outcomes are observable.",
            "Tests cover valid, incomplete, malformed, and inconsistent records."
        ]
    },

    # Workstream E
    {
        "id": "P2-45",
        "slug": "P2-45_COMPLETE_PHASE_2_E2E_PIPELINE_AND_READINESS_REVIEW",
        "title": "Complete Phase 2 End-to-End Assessment Pipeline and Readiness Review",
        "workstream": "Workstream E — Integration Testing & Phase 2 Completion",
        "workstream_label": "workstream/e-testing-readiness",
        "area_label": "area/scanner-engine",
        "kind_label": "kind/feature",
        "priority_label": "priority/critical",
        "purpose": "Verify that KELVIN can execute a complete, authorized, bounded assessment through its integrated scanner pipeline and deliver normalized results reliably.",
        "requirements": [
            "End-to-End Workflow: Submit assessment with valid Phase 1 profile -> Validate target & scope -> Queue and dispatch via worker -> Execute selected scanner adapters -> Capture progress & diagnostics -> Collect raw output -> Parse and validate scanner results -> Normalize into canonical finding schema -> Persist/hand off accepted results through Phase 1 persistence boundaries.",
            "Security Verification: Verify out-of-scope targets rejected -> Verify redirects cannot escape scope -> Verify scanner runtimes cannot bypass worker restrictions -> Verify resource, rate, and time limits -> Verify cancellation stops scanner processes -> Verify malicious/malformed output handled safely -> Verify repeated queue delivery prevents duplicate execution.",
            "Reliability Verification: Test scanner unavailable scenarios -> Test scanner timeout and crash scenarios -> Test partial assessment completion -> Test retry behavior -> Test cleanup after success, failure, cancellation -> Test recovery after worker interruption.",
            "Documentation: Document supported scanners and versions -> Document MVP assessment profiles and limits -> Document scanner execution and failure semantics -> Document test coverage and known limitations -> Record remaining technical debt and deferred capabilities."
        ],
        "acceptance_criteria": [
            "A complete assessment executes successfully in an isolated test environment.",
            "All selected MVP scanner integrations pass their adapter tests.",
            "Results are normalized against the Phase 1 canonical schema.",
            "Security and scope enforcement tests pass.",
            "Cancellation, timeout, retry, and partial completion behavior is verified.",
            "No critical Phase 2 integration defects remain unresolved.",
            "Supported scanner versions and limitations are documented.",
            "A Phase 2 readiness report is approved."
        ]
    }
]

output_dir = "/home/kush05bhardwaj/Desktop/Kelvin/Kelvin/.github/issues/phase-2"
os.makedirs(output_dir, exist_ok=True)

for item in phase2_issues:
    filename = f"{item['slug']}.md"
    filepath = os.path.join(output_dir, filename)
    
    req_bullets = "\n".join([f"- {req}" for req in item["requirements"]])
    crit_bullets = "\n".join([f"- [ ] {crit}" for crit in item["acceptance_criteria"]])
    
    content = f"""---
title: "{item['id']} — {item['title']}"
labels: ["phase/2-scanner-engine", "{item['workstream_label']}", "{item['area_label']}", "{item['kind_label']}", "{item['priority_label']}", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "{item['workstream']}"
issue_id: "{item['id']}"
priority: "{item['priority_label'].replace('priority/', '')}"
status: "ready-for-dev"
---

# {item['id']} — {item['title']}

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** {item['workstream']}  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

{item['purpose']}

---

## 📋 Detailed Requirements

{req_bullets}

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

{crit_bullets}

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

print(f"Successfully generated {len(phase2_issues)} issues in {output_dir}")

