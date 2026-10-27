## 📌 Pull Request Description

### Summary of Changes
<!-- Provide a concise overview of what this pull request introduces, fixes, or refactors. -->

### Related Issue(s)
Fixes #<!-- Enter issue number, e.g. #14 -->
Resolves #<!-- Enter issue number, e.g. #15 -->

---

## 📐 Architecture & Security Impact

- [ ] **Data Model / Database:** Touches schema migrations (`apps/api/db/migrations`) or RLS policies.
- [ ] **Security Controls:** Touches scope validation (`scope`), egress filters, anti-SSRF, or auth (`auth`).
- [ ] **Configuration / Secrets:** Modifies environment variables or secret handling (`.env.example`, `config.go`).
- [ ] **Worker Sandboxing:** Modifies worker execution privileges or scanner isolation (ADR-0005).
- [ ] **API Contract:** Modifies OpenAPI specifications (`apps/api/openapi/openapi.yaml`) or shared schemas (`packages/schemas`).

---

## 🧪 Verification & Testing Checklist

### Automated Quality Gates
- [ ] Unit tests added / updated and passing with zero external internet dependencies (`npm test`).
- [ ] Code formatting and linting pass with zero warnings (`npm run lint`).
- [ ] Frontend unit tests pass (`npm run test:web`) and production build succeeds (`npm run build:web`).
- [ ] Security negative tests included for any modified scope rules, auth, or input validation logic.
- [ ] Schema validation harness passes with valid draft 2020-12 compliance (`npm test --prefix scripts/schema-validation`).

### Evidence / Local Run Output
<!-- Paste command output, test results, or screenshots demonstrating that the changes work predictably. -->
```text
Paste test output or execution log here
```

---

## 📝 Conventional Commits & Contributor Agreement

- [ ] All commit messages adhere to [Conventional Commits](https://www.conventionalcommits.org/) (e.g. `feat(scope): add CIDR validation`, `fix(api): correct tenant context leak`).
- [ ] No secrets, real API keys, passwords, or private certificates are contained in this diff or Git history.
- [ ] I have read and agree to Kelvin's [Acceptable Use Policy](docs/security/ACCEPTABLE_USE.md) and [Contributing Guidelines](CONTRIBUTING.md).

