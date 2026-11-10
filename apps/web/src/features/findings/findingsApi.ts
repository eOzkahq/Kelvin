import { request } from "../../services/api";
import type {
  BatchUpdatePayload,
  BatchUpdateResponse,
  Finding,
  FindingDetail,
  FindingsFilterParams,
  FindingsListResponse,
  FindingSeverity,
  FindingStatus,
} from "./types";

export type {
  BatchUpdatePayload,
  BatchUpdateResponse,
  Finding,
  FindingDetail,
  FindingsFilterParams,
  FindingsListResponse,
  FindingSeverity,
  FindingStatus,
};

const severityWeights: Record<FindingSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

const INITIAL_FINDINGS: Finding[] = [
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
    riskScore: 7.2,
    cweId: "CWE-295",
    cveIds: [],
    firstSeenAt: "2026-11-01T04:00:00Z",
    lastSeenAt: "2026-11-03T06:00:00Z",
    assignee: "infra@kelvin.io",
    description: "The X.509 certificate expired on 2026-10-31 and causes client trust validation warnings.",
    remediation: "Renew TLS certificate via ACME/Let's Encrypt or deploy new CA signed certificate bundle.",
    remediationGuidance: "Renew TLS certificate via ACME/Let's Encrypt or deploy new CA signed certificate bundle.",
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
    remediationGuidance: "Update Alpine or Debian base image packages to openssl >= 3.0.8.",
  },
  {
    id: "fnd-006",
    fingerprint: "sha256:2b3c4d5e6f7a",
    title: "Cross-Origin Resource Sharing (CORS) Overly Permissive Wildcard",
    severity: "MEDIUM",
    status: "OPEN",
    target: "api.staging.kelvin-sec.internal",
    affectedEndpoint: "https://api.staging.kelvin-sec.internal/graphql",
    scanner: "ZAP",
    cvssScore: 5.3,
    riskScore: 5.1,
    cweId: "CWE-942",
    cveIds: [],
    firstSeenAt: "2026-11-01T10:00:00Z",
    lastSeenAt: "2026-11-03T07:15:00Z",
    assignee: "frontend-team@kelvin.io",
    description: "Access-Control-Allow-Origin header set to wildcard '*' while credentials flag is true.",
    remediation: "Specify explicit authorized origin domains in CORS filter configuration.",
    remediationGuidance: "Specify explicit authorized origin domains in CORS filter configuration.",
  },
  {
    id: "fnd-007",
    fingerprint: "sha256:3c4d5e6f7a8b",
    title: "Content Security Policy (CSP) Missing object-src Directive",
    severity: "LOW",
    status: "OPEN",
    target: "portal.staging.kelvin-sec.internal",
    affectedEndpoint: "https://portal.staging.kelvin-sec.internal/",
    scanner: "HTTP-Preflight",
    cvssScore: 3.1,
    riskScore: 2.9,
    cweId: "CWE-1021",
    cveIds: [],
    firstSeenAt: "2026-11-02T01:00:00Z",
    lastSeenAt: "2026-11-03T09:00:00Z",
    description: "Missing object-src directive in CSP header may allow plugin execution.",
    remediation: "Add 'object-src 'none'' to Content-Security-Policy response headers.",
    remediationGuidance: "Add 'object-src 'none'' to Content-Security-Policy response headers.",
  },
];

let mockFindingsStore: Finding[] = JSON.parse(JSON.stringify(INITIAL_FINDINGS));

export async function fetchFindings(params?: FindingsFilterParams): Promise<FindingsListResponse> {
  try {
    const q = new URLSearchParams();
    if (params?.search) q.set("q", params.search);
    if (params?.severity) q.set("severity", Array.isArray(params.severity) ? params.severity.join(",") : params.severity);
    if (params?.status) q.set("status", Array.isArray(params.status) ? params.status.join(",") : params.status);
    if (params?.target) q.set("target", params.target);
    if (params?.scanner) q.set("scanner", params.scanner);
    if (params?.page) q.set("page", String(params.page));
    if (params?.limit) q.set("limit", String(params.limit));

    const queryStr = q.toString() ? `?${q.toString()}` : "";
    const res = await request<FindingsListResponse>(`/findings${queryStr}`);
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

  // Sort
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

  return {
    items,
    total,
    page,
    limit,
    totalPages,
  };
}

export async function getFindingDetail(id: string): Promise<FindingDetail> {
  try {
    return await request<FindingDetail>(`/findings/${encodeURIComponent(id)}`);
  } catch {
    const finding = mockFindingsStore.find((f) => f.id === id) || mockFindingsStore[0];
    return {
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
          sanitizedPayload: "GET /api/v1/auth/ldap HTTP/1.1\r\nHost: api.staging.kelvin-sec.internal\r\nAuthorization: Bearer [REDACTED_JWT_TOKEN]\r\n\r\n[Payload Processed Safely]",
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
    };
  }
}

export async function transitionFindingStatus(
  id: string,
  newStatus: FindingStatus,
  justification?: string,
  assignee?: string,
  dueDate?: string
): Promise<FindingDetail> {
  try {
    return await request<FindingDetail>(`/findings/${encodeURIComponent(id)}/transition`, {
      method: "POST",
      body: JSON.stringify({ target_status: newStatus, reason: justification, assignee, due_date: dueDate }),
    });
  } catch {
    const detail = await getFindingDetail(id);
    detail.status = newStatus;
    if (assignee) {
      detail.assignee = assignee;
    }
    if (dueDate) {
      detail.dueDate = dueDate;
    }
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
  }
}

export async function batchUpdateFindings(
  payload: BatchUpdatePayload
): Promise<BatchUpdateResponse> {
  try {
    const res = await request<BatchUpdateResponse>("/findings/batch-update", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (res && res.updatedCount !== undefined) {
      return res;
    }
  } catch {
    // Apply updates directly to client mock store
  }

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

  return {
    updatedCount,
    success: errors.length === 0,
    message:
      errors.length > 0
        ? `Partially updated ${updatedCount} findings (${errors.length} failed)`
        : `Successfully updated ${updatedCount} findings`,
    errors: errors.length > 0 ? errors : undefined,
  };
}

export async function exportFindings(
  format: "csv" | "json",
  params?: FindingsFilterParams
): Promise<string> {
  const result = await fetchFindings({ ...params, limit: 1000, page: 1 });
  const items = result.items;

  if (format === "json") {
    return JSON.stringify(items, null, 2);
  }

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

  const rows = items.map((f: Finding) => [
    `"${f.id}"`,
    `"${f.title.replace(/"/g, '""')}"`,
    `"${f.severity}"`,
    `"${f.status}"`,
    (f.riskScore ?? 0).toFixed(1),
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

  return [headers.join(","), ...rows.map((r: string[]) => r.join(","))].join("\n");
}

export async function exportFindingsBlob(
  format: "csv" | "json",
  params?: FindingsFilterParams
): Promise<Blob> {
  const content = await exportFindings(format, params);
  const mimeType = format === "json" ? "application/json" : "text/csv;charset=utf-8;";
  return new Blob([content], { type: mimeType });
}

export function resetMockFindings(): void {
  mockFindingsStore = JSON.parse(JSON.stringify(INITIAL_FINDINGS));
}
