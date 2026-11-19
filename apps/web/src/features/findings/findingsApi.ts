import { request } from "../../services/api";
import { isDemoMode } from "../../config/env";
import { demoFindingsProvider } from "./demoProvider";
import { getLiveScanResult, getAllLiveScanResults, type LiveProbeFinding } from "../reports/liveScanStore";
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

function convertLiveProbeFinding(
  f: LiveProbeFinding,
  assessmentId: string,
  targetHost: string
): Finding {
  return {
    id: f.id,
    assessmentId,
    fingerprint: `live-${f.cwe || f.title}-${targetHost}`,
    title: f.title,
    severity: (f.severity.toUpperCase() as FindingSeverity) || "INFO",
    status: "OPEN",
    target: targetHost,
    affectedEndpoint: f.endpoint || targetHost,
    scanner: f.scanner || "Live Diagnostic Engine",
    cvssScore: f.cvss,
    riskScore: f.cvss,
    cweId: f.cwe,
    cveIds: [],
    firstSeenAt: new Date().toISOString(),
    lastSeenAt: new Date().toISOString(),
    occurrenceCount: 1,
    description: f.description,
    remediation: f.remediation,
    remediationGuidance: f.remediation,
  };
}

export function normalizeFinding(raw: any): Finding {
  if (!raw || typeof raw !== "object") {
    return {
      id: String(raw || ""),
      fingerprint: "",
      title: "Unknown Finding",
      severity: "INFO",
      status: "OPEN",
      target: "Unknown Target",
      affectedEndpoint: "",
      scanner: "Automated Scanner",
      riskScore: 0,
      firstSeenAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      cveIds: [],
    };
  }

  const rawScanner =
    raw.scanner ||
    raw.scanner_name ||
    raw.scannerName ||
    raw.scanner_data?.scanner_name ||
    raw.scanner_data?.engine ||
    raw.scanner_data?.name ||
    "Automated Scanner";

  const rawTarget =
    raw.target ||
    raw.affected_endpoint ||
    raw.affectedEndpoint ||
    raw.target_asset ||
    "N/A";

  const rawRiskScore =
    typeof raw.riskScore === "number"
      ? raw.riskScore
      : typeof raw.risk_score === "number"
      ? raw.risk_score
      : typeof raw.cvssScore === "number"
      ? raw.cvssScore
      : typeof raw.cvss_score === "number"
      ? raw.cvss_score
      : 0;

  const rawCvss =
    typeof raw.cvssScore === "number"
      ? raw.cvssScore
      : typeof raw.cvss_score === "number"
      ? raw.cvss_score
      : undefined;

  const rawCveIds = Array.isArray(raw.cveIds)
    ? raw.cveIds
    : Array.isArray(raw.cve_ids)
    ? raw.cve_ids
    : [];

  const rawFirstSeen =
    raw.firstSeenAt ||
    raw.first_seen_at ||
    raw.createdAt ||
    raw.created_at ||
    new Date().toISOString();

  const rawLastSeen =
    raw.lastSeenAt ||
    raw.last_seen_at ||
    raw.updatedAt ||
    raw.updated_at ||
    rawFirstSeen;

  return {
    id: String(raw.id || ""),
    assessmentId: raw.assessmentId || raw.assessment_id || undefined,
    fingerprint: String(raw.fingerprint || ""),
    title: String(raw.title || "Untitled Finding"),
    severity: (String(raw.severity || "INFO").toUpperCase() as FindingSeverity),
    status: (String(raw.status || "OPEN").toUpperCase() as FindingStatus),
    target: String(rawTarget),
    affectedEndpoint: String(raw.affected_endpoint || raw.affectedEndpoint || rawTarget),
    scanner: String(rawScanner),
    cvssScore: rawCvss,
    riskScore: Number(rawRiskScore) || 0,
    cweId: raw.cweId || raw.cwe_id || "",
    cveIds: rawCveIds,
    firstSeenAt: String(rawFirstSeen),
    lastSeenAt: String(rawLastSeen),
    occurrenceCount: Number(raw.occurrenceCount ?? raw.occurrence_count ?? 1),
    assignee: raw.assignee || "",
    dueDate: raw.dueDate || raw.due_date || "",
    description: raw.description || "",
    remediation: raw.remediation || "",
    remediationGuidance: raw.remediationGuidance || raw.remediation_guidance || "",
    remediationSlaDays: raw.remediationSlaDays ?? raw.remediation_sla_days,
  };
}

export async function fetchFindings(params?: FindingsFilterParams): Promise<FindingsListResponse> {
  if (isDemoMode()) {
    return demoFindingsProvider.fetchFindings(params);
  }

  const q = new URLSearchParams();
  if (params?.search) q.set("q", params.search);
  if (params?.severity) q.set("severity", Array.isArray(params.severity) ? params.severity.join(",") : params.severity);
  if (params?.status) q.set("status", Array.isArray(params.status) ? params.status.join(",") : params.status);
  if (params?.target) q.set("target", params.target);
  if (params?.scanner) q.set("scanner", params.scanner);
  if (params?.assessmentId) q.set("assessment_id", params.assessmentId);
  if (params?.page) q.set("page", String(params.page));
  if (params?.limit) q.set("limit", String(params.limit));
  
  const sort = params?.sortBy || params?.sort || "risk_score";
  q.set("sort", sort);
  q.set("sort_by", sort);

  const order = params?.sortOrder || params?.order || "desc";
  q.set("order", order);
  q.set("sort_order", order);

  const queryStr = q.toString() ? `?${q.toString()}` : "";
  const raw = await request<unknown>(`/findings${queryStr}`);

  const page = params?.page ?? 1;
  const limit = params?.limit ?? 25;

  let rawItems: unknown[] = [];
  let total = 0;

  if (Array.isArray(raw)) {
    rawItems = raw;
    total = raw.length;
  } else if (raw && typeof raw === "object") {
    const obj = raw as Record<string, unknown>;
    if (Array.isArray(obj.items)) {
      rawItems = obj.items;
      total = typeof obj.total === "number" ? obj.total : rawItems.length;
    } else if (Array.isArray(obj.data)) {
      rawItems = obj.data;
      total = typeof obj.total === "number" ? obj.total : rawItems.length;
    }
  }

  let items = rawItems.map(normalizeFinding);

  // If remote returned 200 OK with 0 findings, hydrate from live probe findings
  if (items.length === 0) {
    if (params?.assessmentId) {
      const probe = getLiveScanResult(params.assessmentId);
      if (probe && probe.findings && probe.findings.length > 0) {
        items = probe.findings.map((f) => convertLiveProbeFinding(f, params.assessmentId!, probe.targetUrl));
        total = items.length;
      }
    } else {
      const allResults = getAllLiveScanResults();
      const collected: Finding[] = [];
      allResults.forEach(({ assessmentId, result }) => {
        if (result && Array.isArray(result.findings)) {
          result.findings.forEach((f) => {
            collected.push(convertLiveProbeFinding(f, assessmentId, result.targetUrl));
          });
        }
      });
      if (collected.length > 0) {
        items = collected;
        total = collected.length;
      }
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / limit));

  return {
    items,
    total,
    page,
    limit,
    totalPages,
  };
}

export async function getFindingDetail(id: string): Promise<FindingDetail> {
  if (isDemoMode()) {
    return demoFindingsProvider.getFindingDetail(id);
  }

  // If this is a live diagnostic probe finding, resolve from live scan store
  if (id.includes("-probe-") || id.startsWith("live-")) {
    const all = getAllLiveScanResults();
    for (const { assessmentId, result } of all) {
      const match = result.findings.find((f) => f.id === id);
      if (match) {
        const base = convertLiveProbeFinding(match, assessmentId, result.targetUrl);
        return {
          ...base,
          observations: [
            {
              id: `obs-${id}`,
              findingId: id,
              assessmentId,
              status: "OPEN",
              scanner: match.scanner,
              target: result.targetUrl,
              observedAt: new Date().toISOString(),
              timestamp: new Date().toISOString(),
              evidenceRefs: [],
              evidenceCount: 1,
              rawMetadata: { evidence: match.evidence },
            },
          ],
          evidence: match.evidence
            ? [
                {
                  id: `ev-${id}`,
                  findingId: id,
                  title: "HTTP Diagnostic Evidence",
                  evidenceType: "http_trace",
                  rawPayload: match.evidence,
                },
              ]
            : [],
          auditTrail: [
            {
              id: `trail-${id}`,
              timestamp: new Date().toISOString(),
              actor: "Kelvin Live Diagnostic Scanner",
              action: "Initial Discovery",
              fromStatus: "",
              toStatus: "OPEN",
              justification: "Automated perimeter probe validation",
              note: match.description,
            },
          ],
          riskExplainability: {
            formula: "CVSS Base * Asset Criticality Multiplier",
            contributingFactors: [{ name: "Base Severity", impact: match.severity, weight: 1.0 }],
            baseCvss: match.cvss,
            contextualScore: match.cvss,
          },
        };
      }
    }
  }

  const raw = await request<any>(`/findings/${encodeURIComponent(id)}`);

  const findingObj = raw?.finding ? raw.finding : raw;
  const baseFinding = normalizeFinding(findingObj);

  const rawObservations = Array.isArray(raw?.observations)
    ? raw.observations
    : Array.isArray(findingObj?.observations)
    ? findingObj.observations
    : [];

  const observations = rawObservations.map((obs: any) => ({
    id: obs.id || String(Math.random()),
    findingId: obs.findingId || obs.finding_id || baseFinding.id,
    assessmentId: obs.assessmentId || obs.assessment_id || "",
    status: obs.status || baseFinding.status,
    scanner: obs.scanner || obs.scanner_id || baseFinding.scanner,
    target: obs.target || baseFinding.target,
    observedAt: obs.observedAt || obs.observed_at || baseFinding.lastSeenAt,
    timestamp: obs.timestamp || obs.observed_at || baseFinding.lastSeenAt,
    evidenceRefs: obs.evidenceRefs || obs.evidence_refs || [],
    evidenceCount: obs.evidenceCount || (obs.evidence_refs ? obs.evidence_refs.length : 0),
    rawMetadata: obs.rawMetadata || obs.raw_metadata || {},
  }));

  const rawTimeline = Array.isArray(raw?.auditTrail)
    ? raw.auditTrail
    : Array.isArray(raw?.timeline)
    ? raw.timeline
    : [];

  const auditTrail = rawTimeline.map((entry: any) => ({
    id: entry.id || String(Math.random()),
    timestamp: entry.timestamp || entry.created_at || new Date().toISOString(),
    actor: entry.actor || "System",
    action: entry.action || "Status Change",
    fromStatus: entry.fromStatus || entry.from_status || "",
    toStatus: entry.toStatus || entry.to_status || baseFinding.status,
    justification: entry.justification || entry.reason || "",
    note: entry.note || "",
  }));

  return {
    ...baseFinding,
    observations,
    evidence: raw?.evidence || [],
    auditTrail,
    riskExplainability: raw?.riskExplainability || {
      formula: "CVSS Base * Asset Criticality Multiplier",
      contributingFactors: [
        { name: "Base Severity", impact: baseFinding.severity, weight: 1.0 },
      ],
      baseCvss: baseFinding.cvssScore || 5.0,
      contextualScore: baseFinding.riskScore,
    },
  };
}

export async function transitionFindingStatus(
  id: string,
  newStatus: Finding["status"],
  justification?: string,
  assignee?: string,
  dueDate?: string
): Promise<FindingDetail> {
  if (isDemoMode()) {
    return demoFindingsProvider.transitionFindingStatus(id, newStatus, justification, assignee, dueDate);
  }
  return request<FindingDetail>(`/findings/${encodeURIComponent(id)}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status: newStatus, justification, assignee, dueDate }),
  });
}

export async function batchUpdateFindings(payload: BatchUpdatePayload): Promise<BatchUpdateResponse> {
  if (isDemoMode()) {
    return demoFindingsProvider.batchUpdateFindings(payload);
  }
  return request<BatchUpdateResponse>("/findings/batch", {
    method: "POST",
    body: JSON.stringify(payload),
  });
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
    "CVSS",
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
  const mimeType = format === "csv" ? "text/csv;charset=utf-8;" : "application/json;charset=utf-8;";
  return new Blob([content], { type: mimeType });
}

export function resetMockFindings(): void {
  demoFindingsProvider.resetMockFindings();
}
