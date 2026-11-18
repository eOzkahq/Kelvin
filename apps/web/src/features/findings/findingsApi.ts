import { request } from "../../services/api";
import { isDemoMode } from "../../config/env";
import { demoFindingsProvider } from "./demoProvider";
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
  if (params?.page) q.set("page", String(params.page));
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.sortBy || params?.sort) q.set("sort", params.sortBy || params.sort || "riskScore");
  if (params?.sortOrder || params?.order) q.set("order", params.sortOrder || params.order || "desc");

  const queryStr = q.toString() ? `?${q.toString()}` : "";
  const raw = await request<unknown>(`/findings${queryStr}`);

  const page = params?.page ?? 1;
  const limit = params?.limit ?? 20;

  if (Array.isArray(raw)) {
    return {
      items: raw as Finding[],
      total: raw.length,
      page,
      limit,
      totalPages: Math.max(1, Math.ceil(raw.length / limit)),
    };
  }

  if (raw && typeof raw === "object") {
    const obj = raw as Record<string, unknown>;
    const items = Array.isArray(obj.items) ? (obj.items as Finding[]) : [];
    const total = typeof obj.total === "number" ? obj.total : items.length;
    const totalPages = typeof obj.totalPages === "number" ? obj.totalPages : Math.max(1, Math.ceil(total / limit));
    return {
      items,
      total,
      page,
      limit,
      totalPages,
    };
  }

  return {
    items: [],
    total: 0,
    page,
    limit,
    totalPages: 1,
  };
}

export async function getFindingDetail(id: string): Promise<FindingDetail> {
  if (isDemoMode()) {
    return demoFindingsProvider.getFindingDetail(id);
  }
  return request<FindingDetail>(`/findings/${encodeURIComponent(id)}`);
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
