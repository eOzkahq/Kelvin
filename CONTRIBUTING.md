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

## Code of Conduct

Kelvin is a security platform. Contributors must adhere to the Acceptable Use Policy in `docs/security/ACCEPTABLE_USE.md` and must not submit code that facilitates unauthorized access, weaponized exploitation, or unconstrained scanning.

## License

Apache-2.0. See LICENSE for details.
