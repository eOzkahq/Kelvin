# Kelvin — MVP Scanner Selection and Capability Matrix

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Phase 2 decision baseline |
| **Milestone** | Phase 2 — Assessment Engine & Scanner Integrations (`P2-01`) |
| **Owner** | Platform Engineering / Product Security |
| **Review cadence** | Before adding or upgrading an engine, and quarterly |
| **Related decisions** | `ADR-0002`, `ADR-0005` |
| **Related specifications** | `SCAN_PROFILES.md`, `TARGET_SCOPE_ENFORCEMENT.md`, `EXECUTION_ISOLATION.md`, `FINDING_SCHEMA.md` |

## 1. Decision

Kelvin MVP supports five scanner components: built-in HTTP/HTTPS preflight, built-in TLS configuration assessment, built-in HTTP security header and cookie checks, OWASP ZAP Baseline, and Nuclei restricted to a versioned curated template set. The three built-in checks share Kelvin's bounded HTTP transport and do not add third-party scanner dependencies. ZAP and Nuclei run as separate controlled OCI worker images under ADR-0005.

This is a capability decision, not a claim that every check is harmless. Every check that contacts a target requires a validated Phase 1 scope context, consumes the assessment request budget, and is subject to worker-level deadlines, concurrency, memory, CPU, and egress controls. A check that cannot enforce those bounds is unavailable in the MVP.

## 2. Evaluation criteria

Candidates were assessed against product fit, capability and overlap, maintenance and release practices, licensing and redistribution, integration and parsing effort, resource footprint, OCI portability, scope enforcement, and safe request behavior. Selection favors narrow web assessment coverage without raw-socket privileges or broad host discovery. Exact image digests, engine versions, template revisions, and license notices are release artifacts and must be pinned and reviewed before distribution; this document does not imply a particular release is already packaged.

## 3. Approved MVP selection matrix

| Component | Purpose and responsibility | Request behavior / impact | Boundary and overlap | License / distribution |
| :--- | :--- | :--- | :--- | :--- |
| Built-in HTTP/HTTPS preflight | Establish reachability, final in-scope URL after bounded redirects, response status, basic server/protocol metadata, and transport failures. | Sends a small number of ordinary GET/HEAD requests; low impact, but still target traffic. Redirects are revalidated at every hop. | No crawling or vulnerability payloads. Supplies the URL and response baseline used by the other HTTP checks. | Kelvin code; no external scanner binary. Track licenses of any introduced libraries through normal dependency review. |
| Built-in TLS assessor | Assess certificate validity/chain, hostname match, expiry, negotiated protocol, and supported TLS configuration observable through the bounded connection. | Opens TLS connections and may perform a small number of handshakes; low impact. No exhaustive cipher brute force. | Does not infer application vulnerabilities. Some protocol observations overlap with preflight metadata and should be emitted once. | Kelvin code; no external scanner binary. Track TLS library licenses through dependency review. |
| Built-in headers and cookies | Check a bounded HTTP response for selected security headers and cookie attributes such as `Secure`, `HttpOnly`, and `SameSite`. | Reuses preflight responses where possible; otherwise sends a small number of ordinary requests. Low impact, state-free methods only. | Overlaps with ZAP passive rules. Kelvin owns stable baseline checks; duplicate findings are normalized/deduplicated. | Kelvin code; no external scanner binary. Track licenses of any introduced libraries through normal dependency review. |
| OWASP ZAP Baseline | Passive spider and passive rule analysis for common web configuration and response issues. | Generates HTTP requests while spidering. Medium impact due to crawl breadth; baseline passive rules do not authorize active attack scanning. | Overlaps with headers/cookies, TLS observations, and some Nuclei HTTP checks. Retain ZAP coverage where its passive rule set adds value; deduplicate canonical findings. | OWASP ZAP is Apache-2.0. For redistributable images, include required license/notice materials and review the pinned distribution's dependencies and notices. |
| Nuclei (curated safe set) | Detect known exposures and misconfigurations represented by explicitly approved templates, including selected technology/configuration checks. | Sends template-defined HTTP requests and may send specific protocol requests. Impact depends on each template; default set is restricted and paced. | Overlaps with ZAP and built-ins. A template is admitted only with documented request behavior, scope, expected impact, and evidence; duplicates are deduplicated. | Nuclei engine is MIT-licensed. Templates have their own licensing and provenance; review each included template and preserve required notices. Never assume the engine license covers template content. |

### 3.1 Capability boundary for Nuclei

The executable is not granted arbitrary template access. The worker image contains only an immutable, reviewed template revision and an allow-list of template IDs. Invocation must select that allow-list; user-provided paths, remote template downloads, unsigned updates, custom templates, workflow files, code protocols, and unknown flags are rejected. Template updates are reviewed as code and require a versioned image rebuild. Review includes whether a template sends state-changing methods, uses intrusive payloads, tests denial of service, or could reach an unapproved host; any such template is excluded from the default MVP set.

### 3.2 Capability boundary for ZAP

Only the Baseline mode is enabled. Active scan policies, authenticated contexts, user-supplied add-ons/scripts, AJAX or broad crawling expansions, and command-line options that enable attack behavior are unavailable in the default MVP profile. The adapter uses the validated target and scope-aware network path. If the selected ZAP mode cannot be constrained to the assessed origin and the applicable request budget, that execution is rejected.

## 4. Check classification and operational defaults

“Passive” describes the nature of a check's logic, not an absence of network traffic. Kelvin's built-in HTTP checks, ZAP spidering/passive analysis, and Nuclei templates all make requests when run against a live target. Only external-information discovery with no target connection is zero-target-traffic.

| Class | MVP use | Target traffic | Default treatment |
| :--- | :--- | :--- | :--- |
| Passive external discovery | Not part of these five components | None | May run under an applicable discovery profile. |
| Bounded observation | Built-in preflight, TLS, headers/cookies | Small number of ordinary requests/connections | Included in standard MVP; count all requests and redirects against budgets. |
| Passive crawling/analysis | ZAP Baseline | Multiple ordinary requests based on discovered links | Profile and spider fanout are bounded, but the current Baseline integration cannot enforce strict pacing or scope-aware network access. ZAP remains network-disabled until those worker controls are available. |
| Template-driven checks | Curated Nuclei | Template-dependent requests | Included only for templates individually approved for the standard profile and through enforced rate, request, scope, and resource limits. |
| Active or state-changing tests | None | Potentially crafted or mutating traffic | Excluded from default MVP profiles. No exploit execution or state-changing checks. |
| Denial-of-service / stress / unrestricted discovery | None | Potentially high-volume or broad traffic | Prohibited in the MVP. |

### 4.1 Effective profile requirement

The `standard` profile values currently shown in `SCAN_PROFILES.md` (50 requests/second, 5,000 requests/target, and 10 concurrent connections) are not approved defaults for this lineup. Before enabling ZAP or Nuclei in a release, Phase 2 must define a conservative web-baseline budget and make the profile, adapters, and worker limiter agree. Limits must be enforced by the worker boundary, not trusted to scanner flags alone. Each adapter must reject profiles whose limits it cannot enforce. The ZAP integration remains network-disabled because its Baseline CLI has no documented strict pacing option and Phase 1 scope-aware egress is not wired into the process path.

Requests made for redirects, retries, crawling, template checks, and scanner health/verification against the target all consume the same per-target budget. Redirect destinations must pass the shared scope policy independently. Rate limits apply across the entire assessment and target, not independently per engine. Default behavior excludes login, authentication, payment, checkout, logout, and other stateful paths; path exclusions supplement rather than replace scope enforcement.

## 5. Overlap and finding ownership

| Capability | Primary owner | Secondary coverage | Resolution |
| :--- | :--- | :--- | :--- |
| Reachability and redirect behavior | Built-in preflight | ZAP crawl startup | Reuse preflight facts when possible; never follow an unvalidated redirect. |
| Certificate and TLS posture | Built-in TLS assessor | ZAP/Nuclei may report selected TLS findings | Emit one canonical observation where equivalent; retain a scanner finding only when it adds distinct evidence. |
| Security headers and cookie flags | Built-in checks | ZAP passive rules; selected Nuclei templates | Normalize title, vulnerability key, target, and evidence through `finding.v1.json`; deduplicate equivalent findings. |
| Known web exposures and misconfiguration | Curated Nuclei | ZAP passive rules | Preserve distinct checks; deduplicate only equivalent vulnerability evidence, not merely similar titles. |

Adapters treat scanner output as untrusted. They parse and normalize it, redact secrets, map severity, and validate against the canonical finding contract before persistence. Raw stdout, stderr, requests, or responses are not findings and must not be rendered as trusted content.

## 6. Exclusions and deferred candidates

| Candidate / capability | Decision | Reason |
| :--- | :--- | :--- |
| Unrestricted Nmap/Masscan port scanning | Excluded from default MVP | Broad host/port enumeration, raw socket or capability pressure, and greater impact exceed the initial web-assessment requirement. May be reconsidered only as a separately authorized, tightly scoped capability. |
| Exploit modules and destructive checks | Prohibited in MVP | Can alter data, gain access, or disrupt service; incompatible with the non-intrusive default. |
| Denial-of-service tools and fuzzers | Prohibited in MVP | Intentionally high-volume or destabilizing behavior. |
| Arbitrary Nuclei templates, workflows, or user template uploads | Excluded | Template behavior is executable policy and cannot be safely inferred from user input at runtime. Curated reviewed IDs only. |
| Full/active ZAP scan | Deferred | Sends attack payloads and requires a distinct authorization/profile and stronger operational controls than baseline mode. |
| OpenVAS / Greenbone | Deferred | Broader infrastructure vulnerability management, substantial data/feed and compute footprint, and licensing/distribution review beyond the MVP web scope. |
| Commercial DAST platforms | Deferred | Product/vendor dependency, licensing and service integration costs, and unnecessary overlap before MVP coverage is validated. |
| Trivy and other dependency/image scanners | Deferred from target assessment | Useful for source, artifact, and container supply-chain workflows, but distinct from scanning an authorized live target. |

Deferred means no adapter or image is enabled by this decision. It does not prohibit a later issue from proposing a scanner with a dedicated capability, licensing, safety, and resource review.

## 7. Mandatory architecture constraints

1. **Isolation:** External ZAP and Nuclei execution uses versioned, signed OCI images and ADR-0005 controls: rootless runtime, container process UID `10001`, all capabilities dropped, read-only root filesystem, ephemeral bounded writable areas, seccomp plus AppArmor/SELinux, no host mounts or runtime socket, and CPU, memory, PID, and deadline limits. Built-in checks use the same scope-aware egress path and applicable worker budgets.
2. **Scope:** Every request uses the validated Phase 1 scope context and pinned/checked DNS policy. Every redirect and discovered URL is revalidated. Egress policy independently blocks private, loopback, link-local, metadata, and control-plane destinations. A scanner that bypasses the enforced path cannot be enabled.
3. **Resource and traffic limits:** Worker runtime enforces hard deadline, CPU/memory limits, concurrency, request rate, total target request count, and output caps. A scanner's own flags are defense in depth, not the source of truth.
4. **Data integrity:** Output is untrusted, redacted, normalized, and validated against `finding.v1.json` / `FINDING_SCHEMA.md`; invalid output is rejected.
5. **Supply chain:** Pin image digests and engine/template versions; verify signatures and provenance; scan and patch images; retain license and notice inventory. No runtime downloads or mutable `latest` tags.
6. **Fail closed:** Unsupported flags, unavailable enforcement, unknown template IDs, scope violations, and missing budgets reject the job before target traffic.

## 8. Release gate and change control

Before an external scanner is enabled for users, its adapter must document the exact image digest and versions, license notices, invocation allow-list, input/output format, scope behavior, request accounting, profile-to-engine mapping, resource limits, and failure behavior. Product Security reviews the ZAP mode and every Nuclei template revision. Updating an engine, template set, or enabled capability requires review and a versioned artifact. Review this matrix quarterly and whenever a scanner or profile changes.

## 9. Traceability

| Requirement | Reference |
| :--- | :--- |
| Invocation input contract | `.github/issues/phase-2/P2-03_DEFINE_SCANNER_INVOCATION_INPUT_CONTRACT.md` |
| Adapter interface | `.github/issues/phase-2/P2-02_DEFINE_SCANNER_ADAPTER_INTERFACE.md` |
| Controlled scanner images | `.github/issues/phase-2/P2-08_PACKAGE_SCANNERS_AS_CONTROLLED_RUNTIME_IMAGES.md` |
| ZAP integration | `.github/issues/phase-2/P2-15_INTEGRATE_OWASP_ZAP_BASELINE_SCANNER.md` |
| Scope and egress | `TARGET_SCOPE_ENFORCEMENT.md`, `EXECUTION_ISOLATION.md`, ADR-0005 |
| Profiles and budgets | `SCAN_PROFILES.md` |
| Finding contract | `FINDING_SCHEMA.md`, ADR-0002 |
