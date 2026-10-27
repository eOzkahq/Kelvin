# Security Policy — Kelvin Security Platform

**Classification:** Public — Vulnerability Disclosure Policy  
**Effective Date:** 2026-10-27  
**Owner:** Product Security Team (`security@kelvin-security.internal`)

---

## 1. Our Security Commitment

The Kelvin Security Platform is an enterprise-grade security assessment and vulnerability management system. As a platform built by and for security professionals, we hold our own software to the highest security standards.

We take all security vulnerabilities seriously and welcome coordinated, responsible disclosure from the independent security research community, customers, and contributors.

---

## 2. Supported Versions

Security updates, vulnerability patches, and CVE fixes are actively maintained and released for the following versions:

| Version Branch | Supported | Release Type |
| :--- | :--- | :--- |
| `main` / Latest Release (v0.x / v1.x) | :white_check_mark: Yes | Active Development / Latest Stable |
| Prior Minor Releases (< Current - 1) | :x: No | Community / Archived |

We strongly recommend always running the latest stable release or container image.

---

## 3. Reporting a Vulnerability (Coordinated Disclosure)

> [!CAUTION]
> **DO NOT report suspected security vulnerabilities through public GitHub issues, discussions, or pull requests.**
> Public disclosure puts organizations and users at risk of exploitation before a defensive patch can be distributed.

If you believe you have discovered a vulnerability in Kelvin (including in the API control plane, worker daemon sandboxing, frontend web dashboard, or shared packages), please report it privately using one of the following methods:

### Method 1: GitHub Private Security Advisories (Recommended)
1. Navigate to the repository's **Security** tab on GitHub.
2. Under "Reporting", click **Report a vulnerability** to open a draft private advisory.
3. Provide a clear description, reproduction steps, affected versions, and a proof of concept (PoC).

### Method 2: Encrypted Email Disclosure
If GitHub Private Advisories are unavailable, send an email to:
- **Primary Security Contact:** `security@kelvin-security.internal`
- **Subject Line:** `[VULNERABILITY DISCLOSURE] Kelvin - <Vulnerability Class / Short Summary>`
- If submitting sensitive details or working exploit code, please encrypt your email using our PGP public key (fingerprint available on key servers or upon request).

---

## 4. What to Include in Your Report

To help our security response team triage and remediate the issue rapidly, please provide:
1. **Description & Impact:** A clear explanation of the flaw and its potential security impact (e.g., cross-tenant data leakage, container breakout, anti-SSRF bypass, privilege escalation).
2. **Affected Components:** Specific services, files, API endpoints, or commit hashes involved.
3. **Step-by-Step Reproduction:** Minimal, deterministic steps or HTTP requests required to reproduce the issue.
4. **Proof of Concept (PoC):** Non-destructive code or script demonstrating the flaw.
5. **Proposed Remediation:** If you have developed a patch or mitigation, please share it with us.

---

## 5. Our Response Timeline

We commit to the following response timeline for all reported vulnerabilities:

| Stage | Target Response Time | Action |
| :--- | :--- | :--- |
| **Initial Acknowledgment** | **Within 24 hours** | Confirmation of report receipt and initial assessment by an engineer. |
| **Triage & Validation** | **Within 72 hours** | Reproduction of the vulnerability and assignment of severity (CVSS v3.1). |
| **Remediation & Patching** | **7 to 30 days** | Creation of a private fix branch, code review, and automated regression testing. |
| **Public Release & Advisory** | Coordinated Date | Distribution of patched releases and publication of GitHub Security Advisory with contributor credit. |

---

## 6. Safe Harbor & Responsible Research Principles

We consider security research conducted under this policy to be authorized. We will not pursue civil or criminal action against researchers who:
- Make a good faith effort to avoid privacy violations, destruction of data, and interruption or degradation of services.
- Only interact with test accounts or isolated local installations under their direct ownership (e.g. running the local lab target).
- Do not access, modify, or exfiltrate another user's or tenant's data.
- Maintain confidentiality and give the Kelvin engineering team reasonable time to release a patch prior to public disclosure.

Thank you for helping keep Kelvin and our community secure!

