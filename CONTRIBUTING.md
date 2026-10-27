# Contributing to the Kelvin Security Platform

Thank you for contributing to Kelvin! Kelvin is an enterprise-grade, modular security assessment and vulnerability management platform designed exclusively for authorized security assessments.

Please read this document carefully before submitting code, filing issues, or opening pull requests.

---

## 1. Code of Conduct & Acceptable Use

Kelvin is built for defensive security and authorized testing. All contributors must strictly adhere to our [Acceptable Use Policy](docs/security/ACCEPTABLE_USE.md).

We strictly prohibit:
- Committing weaponized exploits or unconstrained scanner payloads.
- Circumventing built-in target validation, anti-SSRF filters, or DNS rebinding protections.
- Scanning arbitrary third-party networks or systems without explicit, documented authorization.
- Committing secrets, production keys, or internal credentials to the repository.

---

## 2. Security Vulnerability Reporting

If you discover a security vulnerability within the Kelvin platform itself, **do not open a public GitHub issue**. Please review [SECURITY.md](SECURITY.md) for our coordinated disclosure process and submit your report privately via GitHub Private Security Advisories or to `security@kelvin-security.internal`.

---

## 3. Getting Started & Development Setup

Before contributing code, set up your local development environment following our single-command onboarding guide:

1. Follow the prerequisites (Docker 24+, Go 1.22+, Node.js 20+) in [docs/development/LOCAL_SETUP.md](docs/development/LOCAL_SETUP.md).
2. Copy `.env.example` to `.env`.
3. Launch the containerized local development stack (PostgreSQL 15+, Redis 7+, MinIO S3, and isolated mock target lab):
   ```bash
   npm run docker:up
   ```
4. Verify the build and test suites:
   ```bash
   npm test
   npm run lint
   npm run build
   ```

---

## 4. Branching Strategy & Git Workflow

Kelvin follows a **Trunk-based development flow** centered around `main` (production-ready) and `develop` (integration branch):

1. **Create a feature branch:**
   Branch names must follow the format:
   - `feature/<issue-number>-<short-description>` (e.g. `feature/18-contributor-workflows`)
   - `fix/<issue-number>-<short-description>` (e.g. `fix/42-ssrf-dns-rebinding`)
   - `docs/<issue-number>-<short-description>` (e.g. `docs/17-testing-strategy`)

2. **Commit conventions:**
   All commit messages must adhere to the [Conventional Commits](https://www.conventionalcommits.org/) specification:
   ```text
   <type>(<scope>): <short imperative summary>

   [optional body explaining problem, rationale, and design]

   Refs: P1-XX / Fixes #XX
   ```
   Allowed types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.  
   Allowed scopes: `api`, `worker`, `web`, `schemas`, `common`, `scope`, `auth`, `db`, `devex`, `security`.

---

## 5. Coding & Testing Standards

Review our detailed testing requirements in [docs/development/TESTING_STRATEGY.md](docs/development/TESTING_STRATEGY.md):

- **Zero Outbound Internet Requests:** Tests must never make live network calls to the external internet. Use `httptest.NewServer`, `miniredis`, `go-sqlmock`, or mock fixtures (`packages/schemas/fixtures/raw/`).
- **Mandatory Negative Security Tests:** Any PR modifying scope verification, anti-SSRF, auth middleware, or RLS policies must include negative test suites demonstrating that invalid or adversarial inputs are safely rejected.
- **Coverage Quality Gates:**
  - Security modules (`scope`, `auth`, `validation`): ≥ 85% statement coverage.
  - Application services (`apps/api`, `apps/worker`): ≥ 75% statement coverage.
  - Monorepo packages (`packages/schemas`, `packages/common`): ≥ 85% statement coverage.
- **Linting & Verification:** All Go code must pass `golangci-lint` and `govulncheck`; all TypeScript code must pass `eslint` and `tsc --noEmit`.

---

## 6. Architecture Decision Records (ADRs)

Kelvin uses Architecture Decision Records to document significant technical choices. Before introducing a major dependency, changing a database engine, or altering worker sandboxing:
1. Review existing ADRs in `docs/architecture/decisions/`.
2. Copy `docs/architecture/decisions/0000-template.md` to `docs/architecture/decisions/ADR-XXXX.md`.
3. Submit the ADR for review by Platform Engineering and Product Security.

---

## 7. Submitting Pull Requests

1. Ensure all quality gates pass locally:
   ```bash
   npm run lint
   npm test
   npm run test:web
   npm run build:web
   ```
2. Open a Pull Request against the `develop` branch.
3. The PR description will automatically populate from `.github/PULL_REQUEST_TEMPLATE.md`. Complete all sections, link relevant issues, and describe verification results.
4. Obtain required code reviews from designated owners listed in `.github/CODEOWNERS`.
5. Once CI checks pass with 100% success and approvals are granted, maintainers will squash and merge your PR.
