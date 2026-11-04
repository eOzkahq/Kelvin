import { request } from "../../services/api";
import type { AuditEvent, AuditFilterParams } from "./types";

let mockAuditStore: AuditEvent[] = [
  {
    id: "aud-evt-005",
    timestamp: "2026-11-03T20:30:00Z",
    actor: "inkeskdozing@gmail.com",
    action: "finding.status_transition",
    category: "FINDINGS",
    resourceType: "Finding",
    resourceId: "fnd-001",
    ipAddress: "198.51.100.15",
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0",
    correlationId: "req-98fbc1-4401",
    outcome: "SUCCESS",
    details: {
      fromStatus: "OPEN",
      toStatus: "IN_PROGRESS",
      findingTitle: "Apache Log4j Remote Code Execution (Log4Shell)",
      justification: "Assigned to Alice for patch verification.",
    },
    sha256Hash: "4a8b79e1c312784d123498765abcdef0123456789abcdef0123456789abcdef0",
    prevRecordHash: "9f2d1e8c7b6a1234876543210abcdef0123456789abcdef0123456789abcdef0",
    chainVerified: true,
  },
  {
    id: "aud-evt-004",
    timestamp: "2026-11-03T19:45:00Z",
    actor: "mrinalprakashfsd@kelvin.io",
    action: "assessment.launch",
    category: "ASSESSMENT",
    resourceType: "Assessment",
    resourceId: "asm-2026-042",
    ipAddress: "203.0.113.88",
    userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    correlationId: "req-7c8d9e-1102",
    outcome: "SUCCESS",
    details: {
      assessmentTitle: "Weekly Comprehensive Security Sweep #42",
      scanners: ["Nuclei", "OWASP-ZAP", "Nmap"],
      targetCount: 3,
    },
    sha256Hash: "9f2d1e8c7b6a1234876543210abcdef0123456789abcdef0123456789abcdef0",
    prevRecordHash: "3b6a9c1d2e5f67890abcdef123456789abcdef0123456789abcdef0123456789",
    chainVerified: true,
  },
  {
    id: "aud-evt-003",
    timestamp: "2026-11-03T18:15:00Z",
    actor: "alice@kelvin.io",
    action: "auth.login_sso",
    category: "AUTHENTICATION",
    resourceType: "Session",
    resourceId: "sess-8471b3e9",
    ipAddress: "198.51.100.22",
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    correlationId: "req-3b6a9c-0914",
    outcome: "SUCCESS",
    details: {
      idp: "Okta SAML 2.0",
      entityId: "http://www.okta.com/exk9823487123kelvin",
      mfaVerified: true,
    },
    sha256Hash: "3b6a9c1d2e5f67890abcdef123456789abcdef0123456789abcdef0123456789",
    prevRecordHash: "7c8d9e0f1a2b34567890abcdef0123456789abcdef0123456789abcdef012345",
    chainVerified: true,
  },
  {
    id: "aud-evt-002",
    timestamp: "2026-11-03T14:00:00Z",
    actor: "scanner:kelvin-worker-01",
    action: "targets.scope_violation_blocked",
    category: "TARGETS",
    resourceType: "Target",
    resourceId: "tgt-01",
    ipAddress: "10.0.1.42",
    userAgent: "KelvinScannerEngine/2.0",
    correlationId: "req-1a2b3c-7721",
    outcome: "FAILURE",
    details: {
      endpoint: "https://api.staging.kelvin-sec.internal/auth/logout",
      reason: "Excluded subpath guardrail triggered. Request aborted.",
    },
    sha256Hash: "7c8d9e0f1a2b34567890abcdef0123456789abcdef0123456789abcdef012345",
    prevRecordHash: "0000000000000000000000000000000000000000000000000000000000000000",
    chainVerified: true,
  },
  {
    id: "aud-evt-001",
    timestamp: "2026-11-03T10:00:00Z",
    actor: "inkeskdozing@gmail.com",
    action: "policy.mfa_enforced",
    category: "POLICY",
    resourceType: "Organization",
    resourceId: "org-kelvin-corp",
    ipAddress: "198.51.100.15",
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    correlationId: "req-0a1b2c-0001",
    outcome: "SUCCESS",
    details: {
      previousPolicy: "OPTIONAL",
      newPolicy: "ADMINS_ONLY",
    },
    sha256Hash: "0000000000000000000000000000000000000000000000000000000000000000",
    prevRecordHash: "GENESIS_BLOCK_00000000000000000000000000000000000000000000000000",
    chainVerified: true,
  },
];

export async function fetchAuditLogs(filters?: AuditFilterParams): Promise<AuditEvent[]> {
  const query = new URLSearchParams();
  if (filters?.search) query.set("search", filters.search);
  if (filters?.category) query.set("category", filters.category);
  if (filters?.outcome) query.set("outcome", filters.outcome);
  if (filters?.actor) query.set("actor", filters.actor);

  try {
    const res = await request<AuditEvent[]>(`/audit/events?${query.toString()}`);
    if (res && Array.isArray(res)) return res;
  } catch {
    // Local fallback
  }

  let list = [...mockAuditStore];

  if (filters?.search) {
    const q = filters.search.toLowerCase();
    list = list.filter(
      (e) =>
        e.action.toLowerCase().includes(q) ||
        e.actor.toLowerCase().includes(q) ||
        e.resourceId.toLowerCase().includes(q) ||
        e.correlationId.toLowerCase().includes(q)
    );
  }

  if (filters?.category) {
    list = list.filter((e) => e.category === filters.category);
  }

  if (filters?.outcome) {
    list = list.filter((e) => e.outcome === filters.outcome);
  }

  if (filters?.actor) {
    list = list.filter((e) => e.actor.toLowerCase().includes(filters.actor!.toLowerCase()));
  }

  return list;
}

export async function exportAuditLogs(
  format: "csv" | "ndjson",
  filters?: AuditFilterParams
): Promise<string> {
  const events = await fetchAuditLogs(filters);

  if (format === "ndjson") {
    return events.map((e) => JSON.stringify(e)).join("\n");
  }

  const headers = [
    "ID",
    "Timestamp UTC",
    "Actor",
    "Action",
    "Category",
    "Resource Type",
    "Resource ID",
    "IP Address",
    "Outcome",
    "Correlation ID",
    "SHA-256 Hash",
  ];

  const rows = events.map((e) => [
    `"${e.id}"`,
    `"${e.timestamp}"`,
    `"${e.actor}"`,
    `"${e.action}"`,
    `"${e.category}"`,
    `"${e.resourceType}"`,
    `"${e.resourceId}"`,
    `"${e.ipAddress}"`,
    `"${e.outcome}"`,
    `"${e.correlationId}"`,
    `"${e.sha256Hash}"`,
  ]);

  return [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
}

export function resetMockAudit(): void {
  mockAuditStore = mockAuditStore.map((e) => ({ ...e, details: { ...e.details } }));
}
