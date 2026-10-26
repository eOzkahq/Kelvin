# Contributing to Kelvin

Thank you for contributing to Kelvin! Kelvin is an enterprise-grade, modular security assessment and vulnerability management platform designed exclusively for authorized security assessments.

## How to Contribute

1. **Fork the repository** and create a feature branch from `develop`.
2. **Follow the branch naming convention:** `feature/<issue-number>-<short-description>`.
3. **Implement your change** with tests and documentation.
4. **Open a pull request** against `develop`. PRs require:
   - 100% passing CI (linting, static analysis, unit tests)
   - Mandatory security negative tests for input validation and authentication
   - Minimum 1 approved code review from code owners
5. **Squash and merge** to maintain a linear Git history.

## Architecture Decision Records (ADRs)

Kelvin uses Architecture Decision Records (ADRs) to document major technical decisions. Before proposing a significant technology choice (language, database, message queue, ORM, container runtime, etc.), please:

1. Review existing ADRs in `docs/architecture/decisions/` to avoid duplicating a settled decision.
2. Copy `docs/architecture/decisions/0000-template.md` to a new file `docs/architecture/decisions/ADR-XXXX.md` (next available number).
3. Complete the template: Context, Problem Statement, Decision Drivers, Considered Alternatives, Decision, Consequences, Related Decisions, Notes.
4. Open a pull request for review. ADRs require sign-off from Platform Engineering and Product Security before being marked `Accepted`.
5. Once Accepted, an ADR is **immutable**: changes require a new ADR that supersedes it.

See `docs/architecture/decisions/0000-template.md` for the full template.

## Git Commit Convention (Conventional Commits)

Kelvin uses **[Conventional Commits](https://www.conventionalcommits.org/)** to automate changelog generation, semantic versioning, and `git bisect` debugging.

### Format

```
<type>(<optional scope>): <description>

[optional body]

[optional footer(s)]
```

### Commit Types

| Type | Use Case | Example |
| :--- | :--- | :--- |
| `feat` | New feature | `feat(api): add target scope validation` |
| `fix` | Bug fix | `fix(worker): handle scanner OOM crash` |
| `docs` | Documentation only | `docs: update repository layout spec` |
| `style` | Formatting, no code change | `style: format Go files with gofmt` |
| `refactor` | Code restructure, no behavior change | `refactor(web): extract findings table component` |
| `perf` | Performance improvement | `perf(api): reduce findings query latency` |
| `test` | Adding or correcting tests | `test(api): add SSRF negative test suite` |
| `chore` | Build, CI, dependencies | `chore(deps): update Go to 1.22` |
| `revert` | Revert a previous commit | `revert: remove unused worker adapter` |

### Scope

Scope indicates the affected area: `api`, `web`, `worker`, `schemas`, `common`, `deps`, `ci`, or `docs`. Omit the scope for cross-cutting changes.

### Breaking Changes

Append `!` after the type/scope and include a `BREAKING CHANGE:` footer:

```
feat(api)!: remove deprecated assessment endpoint

BREAKING CHANGE: The /assessments/legacy endpoint is removed. Use /assessments/v2.
```

## Branching Strategy (Trunk-Based Development)

Kelvin enforces **Trunk-Based Gitflow** with squash merges. Direct commits to `main` are prohibited.

### Branch Types

| Branch Type | Pattern | Source | Target | Example |
| :--- | :--- | :--- | :--- | :--- |
| Main release | `main` | `develop` (tagged) | — | `main` |
| Integration trunk | `develop` | `main` | `main` (release) | `develop` |
| Feature | `feature/<issue>-<desc>` | `develop` | `develop` (squash) | `feature/p1-25-target-validation` |
| Bugfix | `fix/<issue>-<desc>` | `develop` | `develop` (squash) | `fix/p1-26-scope-validation` |
| Docs | `docs/<issue>-<desc>` | `develop` | `develop` (squash) | `docs/p1-08-repo-layout` |
| Hotfix | `hotfix/<issue>-<desc>` | `main` | `main` + `develop` | `hotfix/p1-27-critical-fix` |

### Rules

1. Feature branches are short-lived (≤ 5 days).
2. All feature work targets `develop`, never `main` directly.
3. `main` only receives tagged releases from `develop`.
4. Squash merge to maintain a linear, bisectable history.
5. Branch names reference the planning issue (e.g., `P1-08`) for traceability.

## Pull Request Review Conventions

| Gate | Requirement |
| :--- | :--- |
| CI | 100% passing automated CI (linting, static analysis, unit tests) |
| Security | Mandatory security negative tests for input validation and authentication |
| Review | Minimum 1 approved code review from code owners (`.github/CODEOWNERS`) |
| History | Linear Git history via Squash & Merge |
| Convention | Commit messages conform to Conventional Commits |

## Code of Conduct

Kelvin is a security platform. Contributors must adhere to the Acceptable Use Policy in `docs/security/ACCEPTABLE_USE.md` and must not submit code that facilitates unauthorized access, weaponized exploitation, or unconstrained scanning.

## License

Apache-2.0. See LICENSE for details.
