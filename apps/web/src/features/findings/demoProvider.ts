import { getAllLiveScanResults } from "../reports/liveScanStore";
import type {
  BatchUpdatePayload,
  BatchUpdateResponse,
  Finding,
  FindingDetail,
  FindingsFilterParams,
  FindingsListResponse,
  FindingSeverity,
} from "./types";

function buildLiveFindings(): Finding[] {
  const results = getAllLiveScanResults();
  const out: Finding[] = [];
  for (const { assessmentId, result } of results) {
    const tier: 1 | 2 | 3 = result.planTier ?? 1;
    for (const f of result.findings) {
      out.push({
        id: `${assessmentId}-${f.id}`,
        assessmentId,
        fingerprint: `live:${result.hostname}:${f.id}`,
        title: f.title,
        severity: f.severity,
        status: "OPEN",
        target: result.hostname,
        affectedEndpoint: f.endpoint,
        scanner: f.scanner,
        cvssScore: f.cvss,
        riskScore: Math.min(10, Number((f.cvss * 1.05).toFixed(1))),
        cweId: f.cwe,
        cveIds: [],
        firstSeenAt: result.logs[0]?.timestamp || new Date().toISOString(),
        lastSeenAt: result.logs[result.logs.length - 1]?.timestamp || new Date().toISOString(),
        description: f.description,
        remediation: f.remediation,
        remediationGuidance: f.remediation,
        requiredTier: tier,
      });
    }
  }
  return out;
}

const severityWeights: Record<FindingSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export const INITIAL_FINDINGS: Finding[] = [
  {
    id: "fnd-001",
    fingerprint: "sha256:4a8b79e1c312",
    title: "Apache Log4j Remote Code Execution (Log4Shell)",
    severity: "CRITICAL",
    status: "OPEN",
    target: "api.staging.kelvin-sec.internal",
    affectedEndpoint: "https://api.staging.kelvin-sec.internal:8443/auth/ldap",
    scanner: "Nuclei",
    cvssScore: 10.0,
    riskScore: 9.8,
    cweId: "CWE-502",
    cveIds: ["CVE-2021-44228", "CVE-2021-45046"],
    firstSeenAt: "2026-10-28T09:15:00Z",
    lastSeenAt: "2026-11-03T08:30:00Z",
    assignee: "sec-ops@kelvin.io",
    description: "JNDI lookup injection allows unauthenticated remote attackers to execute arbitrary code.",
    remediation: "Upgrade log4j-core dependency to >= 2.17.1 or set log4j2.formatMsgNoLookups=true.",
    remediationGuidance: "Upgrade log4j-core dependency to >= 2.17.1 or set log4j2.formatMsgNoLookups=true.",
  },
  {
    id: "fnd-002",
    fingerprint: "sha256:9f2d1e8c7b6a",
    title: "SQL Injection in Search Query Handler",
    severity: "CRITICAL",
    status: "CONFIRMED",
    target: "app.staging.kelvin-sec.internal",
    affectedEndpoint: "https://app.staging.kelvin-sec.internal/api/v1/search?q=",
    scanner: "OWASP-ZAP",
    cvssScore: 9.8,
    riskScore: 9.5,
    cweId: "CWE-89",
    cveIds: [],
    firstSeenAt: "2026-10-29T14:20:00Z",
    lastSeenAt: "2026-11-02T19:45:00Z",
    assignee: "appsec-team@kelvin.io",
    description: "Unsanitized user input concatenated directly into dynamic SQL query statement.",
    remediation: "Replace dynamic SQL queries with parameterized prepared statements or ORM binding.",
    remediationGuidance: "Replace dynamic SQL queries with parameterized prepared statements or ORM binding.",
  },
  {
    id: "fnd-003",
    fingerprint: "sha256:3b6a9c1d2e5f",
    title: "Spring Framework Remote Code Execution (Spring4Shell)",
    severity: "HIGH",
    status: "IN_PROGRESS",
    target: "portal.staging.kelvin-sec.internal",
    affectedEndpoint: "https://portal.staging.kelvin-sec.internal/helloworld",
    scanner: "Nuclei",
    cvssScore: 8.8,
    riskScore: 8.4,
    cweId: "CWE-94",
    cveIds: ["CVE-2022-22965"],
    firstSeenAt: "2026-10-30T11:00:00Z",
    lastSeenAt: "2026-11-03T02:10:00Z",
    assignee: "backend-lead@kelvin.io",
    description: "Data binding via AccessLogValve leads to arbitrary file write and RCE in Tomcat deployments.",
    remediation: "Upgrade spring-framework to >= 5.3.18 or 5.2.20.",
    remediationGuidance: "Upgrade spring-framework to >= 5.3.18 or 5.2.20.",
  },
  {
    id: "fnd-004",
    fingerprint: "sha256:7c8d9e0f1a2b",
    title: "Expired TLS/SSL Certificate on Edge Router",
    severity: "HIGH",
    status: "OPEN",
    target: "edge-router-01.kelvin-sec.internal",
    affectedEndpoint: "edge-router-01.kelvin-sec.internal:443",
    scanner: "TLS-Check",
    cvssScore: 7.5,
    riskScore: 7.1,
    cweId: "CWE-295",
    cveIds: [],
    firstSeenAt: "2026-11-01T04:00:00Z",
    lastSeenAt: "2026-11-03T07:15:00Z",
    assignee: "netops@kelvin.io",
    description: "Server certificate expired on 2026-10-31. Clients receive trust validation errors.",
    remediation: "Issue new certificate via Let's Encrypt / corporate PKI and deploy to router.",
    remediationGuidance: "Issue new certificate via Let's Encrypt / corporate PKI and deploy to router.",
  },
  {
    id: "fnd-005",
    fingerprint: "sha256:1a2b3c4d5e6f",
    title: "Cleartext Transmission of Sensitive Information (HTTP)",
    severity: "MEDIUM",
    status: "OPEN",
    target: "legacy-admin.staging.kelvin-sec.internal",
    affectedEndpoint: "http://legacy-admin.staging.kelvin-sec.internal:80/status",
    scanner: "OWASP-ZAP",
    cvssScore: 6.5,
    riskScore: 5.8,
    cweId: "CWE-319",
    cveIds: [],
    firstSeenAt: "2026-10-25T12:00:00Z",
    lastSeenAt: "2026-11-02T16:00:00Z",
    assignee: "devops@kelvin.io",
    description: "Internal metrics endpoint served over unencrypted HTTP protocol.",
    remediation: "Redirect all port 80 HTTP traffic to port 443 HTTPS and enforce HSTS header.",
    remediationGuidance: "Redirect all port 80 HTTP traffic to port 443 HTTPS and enforce HSTS header.",
  },
  {
    id: "fnd-006",
    fingerprint: "sha256:8e7d6c5b4a3f",
    title: "Cross-Origin Resource Sharing (CORS) Overly Permissive Wildcard",
    severity: "MEDIUM",
    status: "ACCEPTED_RISK",
    target: "api.staging.kelvin-sec.internal",
    affectedEndpoint: "https://api.staging.kelvin-sec.internal/graphql",
    scanner: "OWASP-ZAP",
    cvssScore: 5.3,
    riskScore: 4.9,
    cweId: "CWE-942",
    cveIds: [],
    firstSeenAt: "2026-10-27T08:00:00Z",
    lastSeenAt: "2026-11-01T22:30:00Z",
    assignee: "sec-ops@kelvin.io",
    description: "Access-Control-Allow-Origin header set to '*' on sensitive API route.",
    remediation: "Specify explicit trusted domains in Access-Control-Allow-Origin response header.",
    remediationGuidance: "Specify explicit trusted domains in Access-Control-Allow-Origin response header.",
  },
  {
    id: "fnd-007",
    fingerprint: "sha256:5f4e3d2c1b0a",
    title: "Missing Content-Security-Policy (CSP) Header",
    severity: "LOW",
    status: "RESOLVED",
    target: "app.staging.kelvin-sec.internal",
    affectedEndpoint: "https://app.staging.kelvin-sec.internal/",
    scanner: "OWASP-ZAP",
    cvssScore: 3.8,
    riskScore: 3.2,
    cweId: "CWE-693",
    cveIds: [],
    firstSeenAt: "2026-10-20T10:00:00Z",
    lastSeenAt: "2026-10-31T14:00:00Z",
    assignee: "frontend-team@kelvin.io",
    description: "No Content-Security-Policy header defined on root document response.",
    remediation: "Deploy strict CSP header restricting script-src and object-src directives.",
    remediationGuidance: "Deploy strict CSP header restricting script-src and object-src directives.",
  },
  {
    id: "fnd-008",
    fingerprint: "sha256:2b1a0f9e8d7c",
    title: "Web Server Version Banner Disclosure",
    severity: "INFO",
    status: "OPEN",
    target: "portal.staging.kelvin-sec.internal",
    affectedEndpoint: "https://portal.staging.kelvin-sec.internal/",
    scanner: "Nuclei",
    cvssScore: 0.0,
    riskScore: 1.0,
    cweId: "CWE-200",
    cveIds: [],
    firstSeenAt: "2026-10-15T00:00:00Z",
    lastSeenAt: "2026-11-03T01:00:00Z",
    assignee: undefined,
    description: "Server response header exposes 'nginx/1.24.0 (Ubuntu)'.",
    remediation: "Disable server_tokens directive in nginx.conf.",
    remediationGuidance: "Disable server_tokens directive in nginx.conf.",
    requiredTier: 1,
  },
  {
    id: "fnd-009",
    fingerprint: "sha256:9d118b7a5e2f",
    title: "Vulnerable OpenSSL 3.0.11 Container Image Package (Trivy SBOM)",
    severity: "HIGH",
    status: "OPEN",
    target: "registry.staging.kelvin-sec.internal",
    affectedEndpoint: "ghcr.io/eozka/kelvin-api:v1.8 (libssl3 3.0.11)",
    scanner: "Trivy",
    cvssScore: 7.8,
    riskScore: 7.6,
    cweId: "CWE-119",
    cveIds: ["CVE-2024-5535"],
    firstSeenAt: "2026-11-01T08:00:00Z",
    lastSeenAt: "2026-11-04T09:15:00Z",
    assignee: "sec-ops@kelvin.io",
    description: "Container layer contains libssl3 affected by SSL_select_next_proto buffer overread detected by Pro SBOM scanner.",
    remediation: "Rebuild base Alpine runtime image pinning openssl >= 3.0.14-r0.",
    remediationGuidance: "Rebuild base Alpine runtime image pinning openssl >= 3.0.14-r0.",
    requiredTier: 2,
  },
  {
    id: "fnd-010",
    fingerprint: "sha256:c4a9e8f10b72",
    title: "Permissive SPF Record (+all) & Missing DNS CAA Issuance Lock",
    severity: "HIGH",
    status: "OPEN",
    target: "edge.eozka-perimeter.io",
    affectedEndpoint: "dns://edge.eozka-perimeter.io (TXT / CAA)",
    scanner: "Custom-Workers",
    cvssScore: 7.4,
    riskScore: 7.2,
    cweId: "CWE-290",
    cveIds: [],
    firstSeenAt: "2026-11-02T11:30:00Z",
    lastSeenAt: "2026-11-05T10:00:00Z",
    assignee: "perimeter-ops@kelvin.io",
    description: "Enterprise DNS compliance probe detected +all SPF authorization and zero CAA records restricting certificate authorities.",
    remediation: "Replace +all with -all in SPF TXT and publish DNS CAA issue records for DigiCert / Let's Encrypt.",
    remediationGuidance: "Replace +all with -all in SPF TXT and publish DNS CAA issue records for DigiCert / Let's Encrypt.",
    requiredTier: 3,
  },
  {
    id: "fnd-011",
    fingerprint: "sha256:e7f2a1d49c03",
    title: "SAML 2.0 Identity Federation Missing Strict AudienceRestriction Validation",
    severity: "CRITICAL",
    status: "CONFIRMED",
    target: "sso.kelvin-enterprise.internal",
    affectedEndpoint: "https://sso.kelvin-enterprise.internal/saml/acs",
    scanner: "Custom-Workers",
    cvssScore: 9.1,
    riskScore: 9.0,
    cweId: "CWE-347",
    cveIds: [],
    firstSeenAt: "2026-11-03T15:40:00Z",
    lastSeenAt: "2026-11-06T06:20:00Z",
    assignee: "iam-security@kelvin.io",
    description: "Enterprise SSO ACS endpoint accepts assertions without verifying AudienceRestriction URI or InResponseTo freshness window.",
    remediation: "Enforce exact SP EntityID AudienceRestriction matching and single-use Assertion ID replay cache.",
    remediationGuidance: "Enforce exact SP EntityID AudienceRestriction matching and single-use Assertion ID replay cache.",
    requiredTier: 3,
  },
  {
    id: "fnd-012",
    fingerprint: "sha256:6b8c4f1d9a22",
    title: "Multi-Cluster KMS Envelope Key Exceeds 365-Day Rotation Policy",
    severity: "MEDIUM",
    status: "OPEN",
    target: "kms.cluster-eu.kelvin-sec.internal",
    affectedEndpoint: "arn:aws:kms:eu-central-1:9012:key/perimeter-ledger",
    scanner: "Custom-Workers",
    cvssScore: 5.5,
    riskScore: 5.3,
    cweId: "CWE-320",
    cveIds: [],
    firstSeenAt: "2026-11-04T09:10:00Z",
    lastSeenAt: "2026-11-06T12:00:00Z",
    assignee: "cloud-sec@kelvin.io",
    description: "Compliance worker audit detected static CMK encryption material exceeding SOC 2 CC6.6 365-day cryptographic rotation ceiling.",
    remediation: "Enable annual KMS automatic key rotation and verify SIEM alert delivery webhook.",
    remediationGuidance: "Enable annual KMS automatic key rotation and verify SIEM alert delivery webhook.",
    requiredTier: 3,
  },
];

let mockFindingsStore: Finding[] = JSON.parse(JSON.stringify(INITIAL_FINDINGS)).map((f: Finding) => {
  f.assessmentId = f.assessmentId || "asmt-2026-001";
  if (f.requiredTier) return f;
  const s = f.scanner.toLowerCase();
  if (s === "owasp-zap" || s === "trivy") return { ...f, requiredTier: 2 as const };
  if (s === "custom-workers") return { ...f, requiredTier: 3 as const };
  return { ...f, requiredTier: 1 as const };
});

export const demoFindingsProvider = {
  fetchFindings(params?: FindingsFilterParams): Promise<FindingsListResponse> {
    const combined = [...buildLiveFindings(), ...mockFindingsStore];
    let filtered = combined;

    if (params?.assessmentId) {
      filtered = filtered.filter(
        (f: Finding) =>
          f.assessmentId === params.assessmentId ||
          f.id.startsWith(`${params.assessmentId}-`)
      );
    }

    if (params?.target) {
      const qTarget = params.target.replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].toLowerCase();
      filtered = filtered.filter((f: Finding) => {
        const fHost = (f.target || "").replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].toLowerCase();
        const fEnd = (f.affectedEndpoint || "").replace(/^https?:\/\//i, "").split("/")[0].split(":")[0].toLowerCase();
        return fHost === qTarget || fHost.endsWith(`.${qTarget}`) || fEnd === qTarget || fEnd.endsWith(`.${qTarget}`);
      });
    }

    const maxTier = params?.maxTier;
    const lockedTierCounts =
      maxTier !== undefined
        ? {
            pro: maxTier < 2 ? filtered.filter((f) => (f.requiredTier ?? 1) === 2).length : 0,
            enterprise: maxTier < 3 ? filtered.filter((f) => (f.requiredTier ?? 1) === 3).length : 0,
          }
        : undefined;

    if (maxTier !== undefined) {
      filtered = filtered.filter((f) => (f.requiredTier ?? 1) <= maxTier);
    }

    if (params?.search) {
      const q = params.search.toLowerCase();
      filtered = filtered.filter(
        (f: Finding) =>
          f.title.toLowerCase().includes(q) ||
          f.affectedEndpoint.toLowerCase().includes(q) ||
          f.target.toLowerCase().includes(q) ||
          f.cweId?.toLowerCase().includes(q) ||
          f.cveIds?.some((cve: string) => cve.toLowerCase().includes(q))
      );
    }

    if (params?.severity) {
      const sevs = Array.isArray(params.severity) ? params.severity : [params.severity];
      filtered = filtered.filter((f: Finding) => sevs.includes(f.severity));
    }

    if (params?.status) {
      const stats = Array.isArray(params.status) ? params.status : [params.status];
      filtered = filtered.filter((f: Finding) => stats.includes(f.status));
    }

    if (params?.target) {
      filtered = filtered.filter((f: Finding) => f.target.toLowerCase().includes(params.target!.toLowerCase()));
    }

    if (params?.scanner) {
      filtered = filtered.filter((f: Finding) => f.scanner.toLowerCase() === params.scanner!.toLowerCase());
    }

    const sortBy = params?.sortBy || params?.sort || "riskScore";
    const sortOrder = params?.sortOrder || params?.order || "desc";

    filtered.sort((a: Finding, b: Finding) => {
      let comp = 0;
      if (sortBy === "severity") {
        comp = severityWeights[a.severity] - severityWeights[b.severity];
      } else if (sortBy === "riskScore") {
        comp = (a.riskScore ?? 0) - (b.riskScore ?? 0);
      } else if (sortBy === "lastSeenAt") {
        comp = new Date(a.lastSeenAt).getTime() - new Date(b.lastSeenAt).getTime();
      } else if (sortBy === "title") {
        comp = a.title.localeCompare(b.title);
      }
      return sortOrder === "asc" ? comp : -comp;
    });

    const page = params?.page || 1;
    const limit = params?.limit || 25;
    const total = filtered.length;
    const totalPages = Math.ceil(total / limit) || 1;
    const startIndex = (page - 1) * limit;
    const items = filtered.slice(startIndex, startIndex + limit);

    return Promise.resolve({
      items,
      total,
      page,
      limit,
      totalPages,
      lockedTierCounts,
    });
  },

  getFindingDetail(id: string): Promise<FindingDetail> {
    const all = [...buildLiveFindings(), ...mockFindingsStore];
    const finding = all.find((f) => f.id === id) || mockFindingsStore[0];
    return Promise.resolve({
      ...finding,
      riskExplainability: {
        formula: "min(10.0, baseCvss * assetMultiplier * exposureMultiplier)",
        contributingFactors: [
          { name: "Base CVSS", weight: 1.0, impact: `${finding.cvssScore ?? 8.5}` },
          { name: "Internet Exposure", weight: 1.2, impact: "+1.2x" },
          { name: "Production Asset", weight: 1.1, impact: "+1.1x" },
        ],
        baseCvss: finding.cvssScore ?? 8.5,
        contextualScore: finding.riskScore ?? 9.2,
      },
      evidence: [
        {
          id: `ev-${id}-1`,
          findingId: id,
          name: "HTTP Request / Response Sanitized Trace",
          storagePath: `evidence/${id}/trace.json`,
          sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          sanitizedPayload: `GET ${finding.affectedEndpoint || "/"} HTTP/1.1\r\nHost: ${finding.target}\r\nAuthorization: Bearer [REDACTED_JWT_TOKEN]\r\n\r\n[Payload Processed Safely]`,
          isSafe: true,
          redactionCount: 1,
        },
      ],
      observations: [
        {
          id: `obs-${id}-1`,
          findingId: id,
          timestamp: finding.lastSeenAt,
          scanner: finding.scanner,
          target: finding.target,
          evidenceRefs: [`ev-${id}-1`],
        },
      ],
      auditTrail: [
        {
          id: `aud-${id}-1`,
          timestamp: finding.firstSeenAt,
          actor: "system:scanner",
          toStatus: finding.status,
          justification: "Initial finding detection and automated ingestion",
        },
      ],
    });
  },

  transitionFindingStatus(
    id: string,
    newStatus: Finding["status"],
    justification?: string,
    assignee?: string,
    dueDate?: string
  ): Promise<FindingDetail> {
    return this.getFindingDetail(id).then((detail) => {
      detail.status = newStatus;
      if (assignee) detail.assignee = assignee;
      if (dueDate) detail.dueDate = dueDate;
      detail.auditTrail.unshift({
        id: `aud-${Date.now()}`,
        timestamp: new Date().toISOString(),
        actor: assignee || "lead-analyst@kelvin.io",
        toStatus: newStatus,
        justification: justification || "Status transition applied by analyst",
      });

      const stored = mockFindingsStore.find((f) => f.id === id);
      if (stored) {
        stored.status = newStatus;
        if (assignee) stored.assignee = assignee;
        if (dueDate) stored.dueDate = dueDate;
      }

      return detail;
    });
  },

  batchUpdateFindings(payload: BatchUpdatePayload): Promise<BatchUpdateResponse> {
    const validIds = new Set(mockFindingsStore.map((f: Finding) => f.id));
    const errors: { id: string; error: string }[] = [];
    let updatedCount = 0;

    for (const id of payload.findingIds) {
      if (!validIds.has(id)) {
        errors.push({ id, error: `Finding ${id} not found` });
      }
    }

    mockFindingsStore = mockFindingsStore.map((f: Finding) => {
      if (payload.findingIds.includes(f.id)) {
        updatedCount++;
        return {
          ...f,
          status: payload.status ?? f.status,
          assignee: payload.assignee ?? f.assignee,
        };
      }
      return f;
    });

    return Promise.resolve({
      updatedCount,
      success: errors.length === 0,
      message:
        errors.length > 0
          ? `Partially updated ${updatedCount} findings (${errors.length} failed)`
          : `Successfully updated ${updatedCount} findings`,
      errors: errors.length > 0 ? errors : undefined,
    });
  },

  resetMockFindings(): void {
    mockFindingsStore = JSON.parse(JSON.stringify(INITIAL_FINDINGS)).map((f: Finding) => {
      f.assessmentId = f.assessmentId || "asmt-2026-001";
      if (f.requiredTier) return f;
      const s = f.scanner.toLowerCase();
      if (s === "owasp-zap" || s === "trivy") return { ...f, requiredTier: 2 as const };
      if (s === "custom-workers") return { ...f, requiredTier: 3 as const };
      return { ...f, requiredTier: 1 as const };
    });
  },
};
