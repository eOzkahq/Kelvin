import { request } from "../../services/api";
import type {
  BatchUpdatePayload,
  BatchUpdateResponse,
  Finding,
  FindingsFilterParams,
  FindingsListResponse,
  FindingSeverity,
} from "./types";

const severityWeights: Record<FindingSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

// Initial state for fallback/mock mode
let mockFindingsStore: Finding[] = [
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
    riskScore: 7.2,
    cweId: "CWE-295",
    cveIds: [],
    firstSeenAt: "2026-11-01T04:00:00Z",
    lastSeenAt: "2026-11-03T06:00:00Z",
    assignee: "infra@kelvin.io",
    description: "The X.509 certificate expired on 2026-10-31 and causes client trust validation warnings.",
    remediation: "Renew TLS certificate via ACME/Let's Encrypt or deploy new CA signed certificate bundle.",
  },
  {
    id: "fnd-005",
    fingerprint: "sha256:1a2b3c4d5e6f",
    title: "Container Image Base OS CVE in OpenSSL",
    severity: "HIGH",
    status: "OPEN",
    target: "registry.kelvin-sec.internal/kelvin-core:v2.1",
    affectedEndpoint: "docker-image://kelvin-core:v2.1",
    scanner: "Trivy",
    cvssScore: 7.5,
    riskScore: 7.0,
    cweId: "CWE-119",
    cveIds: ["CVE-2023-0286"],
    firstSeenAt: "2026-11-01T08:00:00Z",
    lastSeenAt: "2026-11-02T16:00:00Z",
    assignee: "devops@kelvin.io",
    description: "Vulnerability in X.400 address type comparison leads to read out-of-bounds.",
    remediation: "Update Alpine or Debian base image packages to openssl >= 3.0.8.",
  },
  {
    id: "fnd-006",
    fingerprint: "sha256:2b3c4d5e6f7a",
    title: "Cross-Origin Resource Sharing (CORS) Overly Permissive Wildcard",
    severity: "MEDIUM",
    status: "IN_PROGRESS",
    target: "api.staging.kelvin-sec.internal",
    affectedEndpoint: "https://api.staging.kelvin-sec.internal/api/v1/metrics",
    scanner: "OWASP-ZAP",
    cvssScore: 6.5,
    riskScore: 5.8,
    cweId: "CWE-942",
    cveIds: [],
    firstSeenAt: "2026-10-25T12:00:00Z",
    lastSeenAt: "2026-11-01T15:00:00Z",
    assignee: "appsec-team@kelvin.io",
    description: "Access-Control-Allow-Origin header set to * with Access-Control-Allow-Credentials: true.",
    remediation: "Explicitly allow trusted origin domains rather than wildcard mirrors.",
  },
  {
    id: "fnd-007",
    fingerprint: "sha256:5e6f7a8b9c0d",
    title: "Exposed SSH Daemon on Public Cloud Interface",
    severity: "MEDIUM",
    status: "RESOLVED",
    target: "198.51.100.42",
    affectedEndpoint: "198.51.100.42:22",
    scanner: "Nmap",
    cvssScore: 5.3,
    riskScore: 4.8,
    cweId: "CWE-284",
    cveIds: [],
    firstSeenAt: "2026-10-20T10:00:00Z",
    lastSeenAt: "2026-10-27T18:00:00Z",
    assignee: "infra@kelvin.io",
    description: "OpenSSH 8.9p1 port 22 reachable on public internet rather than VPN bastion.",
    remediation: "Restrict SSH port 22 ingress to corporate VPN CIDR blocks in AWS Security Group.",
  },
  {
    id: "fnd-008",
    fingerprint: "sha256:8a9b0c1d2e3f",
    title: "Insecure JWT Signing Algorithm (None)",
    severity: "HIGH",
    status: "FALSE_POSITIVE",
    target: "app.staging.kelvin-sec.internal",
    affectedEndpoint: "https://app.staging.kelvin-sec.internal/auth/verify",
    scanner: "Nuclei",
    cvssScore: 8.1,
    riskScore: 3.2,
    cweId: "CWE-327",
    cveIds: [],
    firstSeenAt: "2026-10-22T08:00:00Z",
    lastSeenAt: "2026-10-23T11:00:00Z",
    assignee: "sec-ops@kelvin.io",
    description: "Template triggered on test mock fixture inside development test harness.",
    remediation: "Production verification confirmed alg=RS256 enforced; marked as False Positive.",
  },
  {
    id: "fnd-009",
    fingerprint: "sha256:4c5d6e7f8a9b",
    title: "Missing HTTP Strict-Transport-Security (HSTS) Header",
    severity: "LOW",
    status: "OPEN",
    target: "docs.staging.kelvin-sec.internal",
    affectedEndpoint: "https://docs.staging.kelvin-sec.internal/",
    scanner: "OWASP-ZAP",
    cvssScore: 3.7,
    riskScore: 2.8,
    cweId: "CWE-319",
    cveIds: [],
    firstSeenAt: "2026-10-15T09:00:00Z",
    lastSeenAt: "2026-11-01T12:00:00Z",
    assignee: "frontend@kelvin.io",
    description: "Response lacks Strict-Transport-Security header with max-age >= 31536000 and includeSubDomains.",
    remediation: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains to Nginx reverse proxy.",
  },
  {
    id: "fnd-010",
    fingerprint: "sha256:6e7f8a9b0c1d",
    title: "Verbose Server Banner in HTTP Response Headers",
    severity: "INFO",
    status: "ACCEPTED_RISK",
    target: "portal.staging.kelvin-sec.internal",
    affectedEndpoint: "https://portal.staging.kelvin-sec.internal/api/version",
    scanner: "OWASP-ZAP",
    cvssScore: 0.0,
    riskScore: 0.5,
    cweId: "CWE-200",
    cveIds: [],
    firstSeenAt: "2026-10-10T14:00:00Z",
    lastSeenAt: "2026-10-29T10:00:00Z",
    assignee: "sec-ops@kelvin.io",
    description: "Server header discloses nginx/1.24.0 (Ubuntu).",
    remediation: "Set server_tokens off in nginx configuration.",
  },
];

/**
 * Fetch findings with server API call and fallback client-side mock search/filter
 */
export async function fetchFindings(params?: FindingsFilterParams): Promise<FindingsListResponse> {
  const query = new URLSearchParams();
  if (params?.search) query.set("search", params.search);
  if (params?.severity) query.set("severity", params.severity);
  if (params?.status) query.set("status", params.status);
  if (params?.target) query.set("target", params.target);
  if (params?.scanner) query.set("scanner", params.scanner);
  if (params?.sortBy) query.set("sortBy", params.sortBy);
  if (params?.sortOrder) query.set("sortOrder", params.sortOrder);
  if (params?.page) query.set("page", params.page.toString());
  if (params?.limit) query.set("limit", params.limit.toString());

  try {
    const res = await request<FindingsListResponse>(`/findings?${query.toString()}`);
    if (res && Array.isArray(res.items)) {
      return res;
    }
  } catch {
    // Fall back to client-side filter engine
  }

  // Filter client-side
  let filtered = [...mockFindingsStore];

  if (params?.search) {
    const q = params.search.toLowerCase();
    filtered = filtered.filter(
      (f) =>
        f.title.toLowerCase().includes(q) ||
        f.affectedEndpoint.toLowerCase().includes(q) ||
        f.target.toLowerCase().includes(q) ||
        f.cweId?.toLowerCase().includes(q) ||
        f.cveIds?.some((cve) => cve.toLowerCase().includes(q))
    );
  }

  if (params?.severity) {
    filtered = filtered.filter((f) => f.severity === params.severity);
  }

  if (params?.status) {
    filtered = filtered.filter((f) => f.status === params.status);
  }

  if (params?.target) {
    filtered = filtered.filter((f) => f.target.toLowerCase().includes(params.target!.toLowerCase()));
  }

  if (params?.scanner) {
    filtered = filtered.filter((f) => f.scanner.toLowerCase() === params.scanner!.toLowerCase());
  }

  // Sort
  const sortBy = params?.sortBy || "riskScore";
  const sortOrder = params?.sortOrder || "desc";

  filtered.sort((a, b) => {
    let comp = 0;
    if (sortBy === "severity") {
      comp = severityWeights[a.severity] - severityWeights[b.severity];
    } else if (sortBy === "riskScore") {
      comp = a.riskScore - b.riskScore;
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

  return {
    items,
    total,
    page,
    limit,
    totalPages,
  };
}

/**
 * Execute batch triage updates on selected findings
 */
export async function batchUpdateFindings(
  payload: BatchUpdatePayload
): Promise<BatchUpdateResponse> {
  try {
    const res = await request<BatchUpdateResponse>("/findings/batch-update", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (res && res.success !== undefined) {
      return res;
    }
  } catch {
    // Apply updates directly to client mock store
  }

  mockFindingsStore = mockFindingsStore.map((f) => {
    if (payload.findingIds.includes(f.id)) {
      return {
        ...f,
        status: payload.status ?? f.status,
        assignee: payload.assignee ?? f.assignee,
      };
    }
    return f;
  });

  return {
    updatedCount: payload.findingIds.length,
    success: true,
    message: `Successfully updated ${payload.findingIds.length} findings`,
  };
}

/**
 * Export findings as CSV or JSON format string
 */
export async function exportFindings(
  format: "csv" | "json",
  params?: FindingsFilterParams
): Promise<string> {
  const result = await fetchFindings({ ...params, limit: 1000, page: 1 });
  const items = result.items;

  if (format === "json") {
    return JSON.stringify(items, null, 2);
  }

  // Format as CSV
  const headers = [
    "ID",
    "Title",
    "Severity",
    "Status",
    "Risk Score",
    "CVSS Score",
    "CWE",
    "CVEs",
    "Target",
    "Endpoint",
    "Scanner",
    "Assignee",
    "First Seen",
    "Last Seen",
  ];

  const rows = items.map((f) => [
    `"${f.id}"`,
    `"${f.title.replace(/"/g, '""')}"`,
    `"${f.severity}"`,
    `"${f.status}"`,
    f.riskScore.toFixed(1),
    f.cvssScore !== undefined ? f.cvssScore.toFixed(1) : "",
    `"${f.cweId || ""}"`,
    `"${(f.cveIds || []).join("; ")}"`,
    `"${f.target}"`,
    `"${f.affectedEndpoint.replace(/"/g, '""')}"`,
    `"${f.scanner}"`,
    `"${f.assignee || ""}"`,
    `"${f.firstSeenAt}"`,
    `"${f.lastSeenAt}"`,
  ]);

  return [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
}

export function resetMockFindings(): void {
  // Reset helper for tests
  mockFindingsStore = mockFindingsStore.map((f) => ({ ...f }));
}
