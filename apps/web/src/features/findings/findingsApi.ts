import { request } from "../../services/api";
import { isDemoMode } from "../../config/env";
import { demoFindingsProvider, INITIAL_FINDINGS } from "./demoProvider";
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

export { INITIAL_FINDINGS };

export async function fetchFindings(
  params?: FindingsFilterParams
): Promise<FindingsListResponse> {
  if (isDemoMode()) {
    return demoFindingsProvider.fetchFindings(params);
  }

  const query = new URLSearchParams();
  if (params?.search) query.set("q", params.search);
  if (params?.severity) {
    const sevs = Array.isArray(params.severity) ? params.severity.join(",") : params.severity;
    query.set("severity", sevs);
  }
  if (params?.status) {
    const stats = Array.isArray(params.status) ? params.status.join(",") : params.status;
    query.set("status", stats);
  }
  if (params?.target) query.set("target", params.target);
  if (params?.scanner) query.set("scanner", params.scanner);
  if (params?.page) query.set("page", String(params.page));
  if (params?.limit) query.set("limit", String(params.limit));
  if (params?.sortBy || params?.sort) query.set("sort", params.sortBy || params.sort || "riskScore");
  if (params?.sortOrder || params?.order) query.set("order", params.sortOrder || params.order || "desc");

  const qs = query.toString();
  return request<FindingsListResponse>(`/findings${qs ? `?${qs}` : ""}`);
}

export async function getFindingDetail(id: string): Promise<FindingDetail> {
  if (isDemoMode()) {
    return demoFindingsProvider.getFindingDetail(id);
  }
  return request<FindingDetail>(`/findings/${encodeURIComponent(id)}`);
}

export async function transitionFindingStatus(
  id: string,
  newStatus: FindingStatus,
  justification?: string,
  assignee?: string,
  dueDate?: string
): Promise<FindingDetail> {
  if (
    !justification &&
    (newStatus === "RESOLVED" || newStatus === "FALSE_POSITIVE" || newStatus === "ACCEPTED_RISK")
  ) {
    throw new Error(`Justification note is required to transition finding to status ${newStatus}`);
  }

  if (isDemoMode()) {
    return demoFindingsProvider.transitionFindingStatus(id, newStatus, justification, assignee, dueDate);
  }

  return request<FindingDetail>(`/findings/${encodeURIComponent(id)}/transition`, {
    method: "POST",
    body: JSON.stringify({ target_status: newStatus, reason: justification, assignee, due_date: dueDate }),
  });
}

export async function batchUpdateFindings(
  payload: BatchUpdatePayload
): Promise<BatchUpdateResponse> {
  if (isDemoMode()) {
    return demoFindingsProvider.batchUpdateFindings(payload);
  }

  return request<BatchUpdateResponse>("/findings/batch-update", {
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
  demoFindingsProvider.resetMockFindings();
}
