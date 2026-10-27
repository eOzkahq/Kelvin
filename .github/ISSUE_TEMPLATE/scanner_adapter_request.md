---
name: Scanner Adapter Request (RFC)
about: Propose integrating a new security scanner engine or adapter into Kelvin
title: "[ADAPTER] Support for <Scanner Name> (e.g. Nuclei, Trivy, Semgrep)"
labels: ["kind/scanner-integration", "area/worker", "status/triage"]
assignees: []
---

## 🔍 Scanner Information

- **Scanner Name:** (e.g., Trivy, Semgrep, Amass, OpenVAS)
- **Primary Category:** (DAST / SAST / Network Scanner / Cloud Security / Secret Scanner)
- **Official Repository / Documentation URL:**
- **License:** (Must be compatible with Kelvin's Apache-2.0 license)
- **Distribution Format:** (Static binary / Container image / CLI tool)

## 🎯 Target Assessment Types & Capabilities

- What target types does this scanner inspect? (Domain, IPv4, IPv6, URL, CIDR, Container Image, Git Repo)
- Does it support rootless, non-privileged execution in containers (ADR-0005)?
- Does it support headless execution and streaming structured outputs (JSON / XML)?

## 📤 Finding Normalization & Output Mapping

How will this tool's raw output map into Kelvin's Unified Finding Schema (`packages/schemas/finding.v1.json`)?

- **Vulnerability Title & Description:**
- **Severity Mapping:** (Map tool severities to `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- **CVSS / CWE / CVE extraction:**
- **Evidence artifact generation:** (Raw HTTP dump, log excerpt, file location)

## 🛡️ Egress & Sandboxing Isolation (ADR-0005)

- Can this scanner's network activity be bounded through an egress proxy and anti-SSRF filters?
- Does it require access to any local network interfaces, privileged kernel capabilities, or host filesystems? (Note: Kelvin prohibits root execution in workers).

