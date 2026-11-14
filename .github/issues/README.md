# Kelvin GitHub Issues & Architectural Planning Suite

This directory contains the foundational master issues, evolutionary roadmaps, phase execution plans, and individual workstream issues for the Kelvin Security Platform.

---

## 🏆 Active Milestones

| Milestone | Target Date | Total Issues | Status | Link |
| :--- | :--- | :--- | :--- | :--- |
| **Phase 2 — Assessment Engine & Scanner Integrations** | Q1 2027 (2027-03-31) | 45 Issues | COMPLETED | [**MILESTONE_PHASE_2.md**](MILESTONE_PHASE_2.md) |
| **Phase 3 — Findings Intelligence, Evidence & Reporting** | Q2 2027 (2027-06-30) | 45 Issues | IN PROGRESS | [**MILESTONE_PHASE_3.md**](MILESTONE_PHASE_3.md) |
| **Phase 4 — Enterprise Platform, Security & Scalability** | Q3 2027 (2027-09-30) | 45 Issues | IN PROGRESS | [**MILESTONE_PHASE_4.md**](MILESTONE_PHASE_4.md) |
| **Pre-Phase 5 — Final Audit & Phase Transition** | October 2027 (2027-10-15) | 1 Quality Gate | READY | [**MILESTONE_PRE_PHASE_5.md**](MILESTONE_PRE_PHASE_5.md) |
| **Frontend Development & Product Experience** | Q4 2027 (`2027-12-31`) | 25 Issues | `READY` | [**MILESTONE_FRONTEND.md**](MILESTONE_FRONTEND.md) |
| **Post-Phase 5 — Infrastructure & Production Integration** | November 2027 (`2027-11-30`) | 1 Issue | `COMPLETED` | [**MILESTONE_INFRASTRUCTURE.md**](MILESTONE_INFRASTRUCTURE.md) |
| **Pre-Deployment Production Hardening** | November 2027 (`2027-11-20`) | 9 Issues | `READY` | [**MILESTONE_PRE_DEPLOYMENT.md**](MILESTONE_PRE_DEPLOYMENT.md) |
| **Scanner Execution Platform** | Q4 2026 / Active | 32 Issues | `IN PROGRESS` | [**scanner-execution/README.md**](scanner-execution/README.md) |

---

## 📋 Master Issues & Epics Index

| Issue File | Issue Title & Focus | Milestone | Assigned Labels | Visual Graphs Included |
| :--- | :--- | :--- | :--- | :--- |
| **[`ISSUE-01`](ISSUE-01_FEATURES_AND_ARCHITECTURAL_DESIGN.md)** | **[EPIC] Feature Specification & Architectural Design Baseline** | Phase 1 & 2 Foundation | `kind/epic`, `area/architecture`, `area/docs`, `phase/1-foundation`, `phase/2-scanner-engine`, `priority/high`, `status/in-progress` | • Architecture Diagram (Tiered micro-modular)<br>• Data Ingestion Pipeline (Flowchart)<br>• Domain Model & Interfaces (Class Diagram) |
| **[`ISSUE-02`](ISSUE-02_ENGINEERING_ROADMAP.md)** | **[ROADMAP] Master Engineering Roadmap & 225-Issue Evolutionary Lifecycle** | Master Roadmap (Phases 1 — 6) | `kind/roadmap`, `area/project-management`, `area/docs`, `priority/high`, `status/accepted` | • 6-Phase Engineering Lifecycle (Gantt Chart)<br>• Trunk-Based Gitflow (Gitgraph Diagram)<br>• GitHub Insights Tracking Standards |
| **[`ISSUE-03`](ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)** | **[EPIC] MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan** | Phase 2 — Assessment Engine & Scanner Integrations | `kind/epic`, `area/mvp`, `area/scanner-engine`, `phase/2-scanner-engine`, `priority/critical`, `status/ready-for-dev` | • Scope Bifurcation (Flowchart)<br>• Relational Data Model (ERD)<br>• Assessment & Job FSM (State Diagram)<br>• 45-Issue Workstream Breakdown |

---

## 🗂️ Phase 2 Individual Issues (45 Issues Total)

All 45 Phase 2 issues are individually tracked as independent GitHub issue documents in the [**`phase-2/`**](phase-2/) directory:

### Workstream A — Scanner Architecture & Integration Foundation
- [`P2-01`](phase-2/P2-01_DEFINE_MVP_SCANNER_SELECTION_AND_CAPABILITY_MATRIX.md) — Define the MVP Scanner Selection and Capability Matrix
- [`P2-02`](phase-2/P2-02_DEFINE_SCANNER_ADAPTER_INTERFACE.md) — Define the Scanner Adapter Interface
- [`P2-03`](phase-2/P2-03_DEFINE_SCANNER_INVOCATION_INPUT_CONTRACT.md) — Define the Scanner Invocation Input Contract
- [`P2-04`](phase-2/P2-04_DEFINE_SCANNER_OUTPUT_ENVELOPE.md) — Define the Scanner Output Envelope
- [`P2-05`](phase-2/P2-05_DEFINE_SCANNER_CONFIGURATION_SCHEMA.md) — Define the Scanner Configuration Schema
- [`P2-06`](phase-2/P2-06_IMPLEMENT_SCANNER_REGISTRY_AND_CAPABILITY_DISCOVERY.md) — Implement the Scanner Registry and Capability Discovery
- [`P2-07`](phase-2/P2-07_IMPLEMENT_SCANNER_VERSION_AND_COMPATIBILITY_MANAGEMENT.md) — Implement Scanner Version and Compatibility Management
- [`P2-08`](phase-2/P2-08_PACKAGE_SCANNERS_AS_CONTROLLED_RUNTIME_IMAGES.md) — Package Scanners as Controlled Runtime Images
- [`P2-09`](phase-2/P2-09_IMPLEMENT_SAFE_SCANNER_PROCESS_INVOCATION.md) — Implement Safe Scanner Process Invocation
- [`P2-10`](phase-2/P2-10_BUILD_SCANNER_ADAPTER_CONFORMANCE_TEST_HARNESS.md) — Build the Scanner Adapter Conformance Test Harness

### Workstream B — MVP Scanner Integrations
- [`P2-11`](phase-2/P2-11_IMPLEMENT_HTTP_HTTPS_PREFLIGHT_ASSESSMENT_ADAPTER.md) — Implement the HTTP/HTTPS Preflight Assessment Adapter
- [`P2-12`](phase-2/P2-12_IMPLEMENT_SAFE_REDIRECT_CHAIN_EVALUATION.md) — Implement Safe Redirect Chain Evaluation
- [`P2-13`](phase-2/P2-13_IMPLEMENT_TLS_CONFIGURATION_ASSESSMENT_ADAPTER.md) — Implement the TLS Configuration Assessment Adapter
- [`P2-14`](phase-2/P2-14_IMPLEMENT_HTTP_SECURITY_HEADER_AND_COOKIE_CHECKS.md) — Implement HTTP Security Header and Cookie Checks
- [`P2-15`](phase-2/P2-15_INTEGRATE_OWASP_ZAP_BASELINE_SCANNER.md) — Integrate OWASP ZAP Baseline Scanner
- [`P2-16`](phase-2/P2-16_DEFINE_AND_ENFORCE_ZAP_BASELINE_SAFETY_PROFILE.md) — Define and Enforce the ZAP Baseline Safety Profile
- [`P2-17`](phase-2/P2-17_INTEGRATE_NUCLEI_THROUGH_A_CONTROLLED_ADAPTER.md) — Integrate Nuclei Through a Controlled Adapter
- [`P2-18`](phase-2/P2-18_ESTABLISH_CURATED_NUCLEI_TEMPLATE_CATALOG.md) — Establish a Curated Nuclei Template Catalog
- [`P2-19`](phase-2/P2-19_IMPLEMENT_MVP_ASSESSMENT_PROFILE_DEFINITIONS.md) — Implement MVP Assessment Profile Definitions
- [`P2-20`](phase-2/P2-20_IMPLEMENT_SCANNER_AVAILABILITY_AND_RUNTIME_READINESS_CHECKS.md) — Implement Scanner Availability and Runtime Readiness Checks

### Workstream C — Worker Execution & Orchestration
- [`P2-21`](phase-2/P2-21_INTEGRATE_SCANNER_ADAPTERS_WITH_THE_ASSESSMENT_WORKER.md) — Integrate Scanner Adapters with the Assessment Worker
- [`P2-22`](phase-2/P2-22_IMPLEMENT_PER_ASSESSMENT_WORKSPACE_MANAGEMENT.md) — Implement Per-Assessment Workspace Management
- [`P2-23`](phase-2/P2-23_APPLY_SCANNER_SPECIFIC_NETWORK_EGRESS_POLICIES.md) — Apply Scanner-Specific Network Egress Policies
- [`P2-24`](phase-2/P2-24_APPLY_SCANNER_SPECIFIC_RESOURCE_LIMITS.md) — Apply Scanner-Specific Resource Limits
- [`P2-25`](phase-2/P2-25_ENFORCE_SCANNER_EXECUTION_DEADLINES.md) — Enforce Scanner Execution Deadlines
- [`P2-26`](phase-2/P2-26_IMPLEMENT_FULL_SCANNER_PROCESS_CANCELLATION.md) — Implement Full Scanner Process Cancellation
- [`P2-27`](phase-2/P2-27_INTEGRATE_SCANNER_PROGRESS_REPORTING.md) — Integrate Scanner Progress Reporting
- [`P2-28`](phase-2/P2-28_IMPLEMENT_ASSESSMENT_CONCURRENCY_CONTROLS.md) — Implement Assessment Concurrency Controls
- [`P2-29`](phase-2/P2-29_IMPLEMENT_PER_TARGET_REQUEST_PACING.md) — Implement Per-Target Request Pacing
- [`P2-30`](phase-2/P2-30_DEFINE_SCANNER_FAILURE_CLASSIFICATION.md) — Define Scanner Failure Classification
- [`P2-31`](phase-2/P2-31_IMPLEMENT_SAFE_SCANNER_RETRY_POLICIES.md) — Implement Safe Scanner Retry Policies
- [`P2-32`](phase-2/P2-32_DEFINE_PARTIAL_ASSESSMENT_COMPLETION_SEMANTICS.md) — Define Partial Assessment Completion Semantics
- [`P2-33`](phase-2/P2-33_IMPLEMENT_BOUNDED_SCANNER_OUTPUT_CAPTURE.md) — Implement Bounded Scanner Output Capture
- [`P2-34`](phase-2/P2-34_IMPLEMENT_RAW_SCANNER_OUTPUT_STAGING_AND_CLEANUP.md) — Implement Raw Scanner Output Staging and Cleanup
- [`P2-35`](phase-2/P2-35_RECORD_IMMUTABLE_ASSESSMENT_EXECUTION_MANIFESTS.md) — Record Immutable Assessment Execution Manifests
- [`P2-36`](phase-2/P2-36_IMPLEMENT_SCANNER_EXECUTION_PROVENANCE_AND_DIAGNOSTICS.md) — Implement Scanner Execution Provenance and Diagnostics
- [`P2-37`](phase-2/P2-37_VALIDATE_SCANNER_REPORTED_TARGETS_AGAINST_ASSESSMENT_SCOPE.md) — Validate Scanner-Reported Targets Against Assessment Scope
- [`P2-38`](phase-2/P2-38_HARDEN_SCANNER_OUTPUT_PARSING_AGAINST_UNTRUSTED_DATA.md) — Harden Scanner Output Parsing Against Untrusted Data

### Workstream D — Result Parsing & Normalization
- [`P2-39`](phase-2/P2-39_IMPLEMENT_OWASP_ZAP_OUTPUT_PARSER.md) — Implement OWASP ZAP Output Parser
- [`P2-40`](phase-2/P2-40_IMPLEMENT_NUCLEI_OUTPUT_PARSER.md) — Implement Nuclei Output Parser
- [`P2-41`](phase-2/P2-41_IMPLEMENT_BUILT_IN_HTTP_AND_TLS_RESULT_PARSERS.md) — Implement Built-In HTTP and TLS Result Parsers
- [`P2-42`](phase-2/P2-42_NORMALIZE_SCANNER_RESULTS_INTO_CANONICAL_FINDING_SCHEMA.md) — Normalize Scanner Results into the Canonical Finding Schema
- [`P2-43`](phase-2/P2-43_IMPLEMENT_SEVERITY_AND_CONFIDENCE_MAPPING.md) — Implement Severity and Confidence Mapping
- [`P2-44`](phase-2/P2-44_IMPLEMENT_NORMALIZED_RESULT_VALIDATION_AND_COMPLETENESS_CHECKS.md) — Implement Normalized Result Validation and Completeness Checks

### Workstream E — Integration Testing & Phase 2 Completion
- [`P2-45`](phase-2/P2-45_COMPLETE_PHASE_2_E2E_PIPELINE_AND_READINESS_REVIEW.md) — Complete Phase 2 End-to-End Assessment Pipeline and Readiness Review

---

## 🏷️ Standard Label Taxonomy

All issues follow the standardized taxonomy configured in [`.github/labels.yml`](../labels.yml):
- **Kinds (`kind/*`):** `kind/epic`, `kind/feature`, `kind/bug`, `kind/docs`, `kind/roadmap`, `kind/scanner-integration`, `kind/security`, `kind/infra`
- **Areas (`area/*`):** `area/architecture`, `area/api`, `area/web`, `area/worker`, `area/scanner-engine`, `area/database`, `area/project-management`, `area/mvp`
- **Phases (`phase/*`):** `phase/1-foundation`, `phase/2-scanner-engine`, `phase/3-findings`, `phase/4-enterprise`, `phase/5-continuous`, `phase/6-extensibility`
- **Workstreams (`workstream/*`):** `workstream/a-foundation`, `workstream/b-integrations`, `workstream/c-worker-orchestration`, `workstream/d-normalization`, `workstream/e-testing-readiness`
- **Priorities (`priority/*`):** `priority/critical`, `priority/high`, `priority/medium`, `priority/low`
- **Statuses (`status/*`):** `status/triage`, `status/ready-for-dev`, `status/in-progress`, `status/in-review`, `status/accepted`, `status/deferred`
