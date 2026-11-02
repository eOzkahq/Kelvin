// API client for Phase 3 Findings Intelligence, Evidence & Reporting

export interface Finding {
  id: string;
  tenant_id: string;
  project_id: string;
  assessment_id: string;
  fingerprint: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  status: "NEW" | "CONFIRMED" | "IN_PROGRESS" | "RESOLVED" | "REOPENED" | "FALSE_POSITIVE" | "ACCEPTED_RISK";
  affected_endpoint: string;
  cvss_score?: number;
  cwe_id?: string;
  cve_ids?: string[];
  risk_score?: number;
  risk_priority_band?: string;
  scanner_data?: Record<string, unknown>;
  first_seen_at: string;
  last_seen_at: string;
}

export interface FindingObservation {
  id: string;
  finding_id: string;
  assessment_id: string;
  scanner_id: string;
  observed_at: string;
  evidence_refs: string[];
}

export interface EvidenceItem {
  id: string;
  evidence_type: string;
  mime_type: string;
  is_redacted: boolean;
  sha256_checksum: string;
  preview_text?: string;
}

export interface DashboardMetrics {
  total_findings: number;
  open_findings: number;
  resolved_findings: number;
  severity_breakdown: Record<string, number>;
  status_breakdown: Record<string, number>;
  priority_breakdown: Record<string, number>;
  remediation_progress: Record<string, number>;
}

export interface AssessmentComparison {
  base_assessment_id: string;
  target_assessment_id: string;
  total_base_findings: number;
  total_target_findings: number;
  new_count: number;
  persistent_count: number;
  resolved_count: number;
  coverage_ratio: number;
}

export interface ReportItem {
  report_id: string;
  assessment_id: string;
  title: string;
  generated_at: string;
  template_version: string;
}

const API_BASE = "/api/v1";

export async function fetchFindings(params?: {
  q?: string;
  severity?: string;
  status?: string;
  scanner?: string;
  limit?: number;
  offset?: number;
}): Promise<{ items: Finding[]; total_count: number }> {
  const query = new URLSearchParams();
  if (params?.q) query.set("q", params.q);
  if (params?.severity) query.set("severity", params.severity);
  if (params?.status) query.set("status", params.status);
  if (params?.scanner) query.set("scanner", params.scanner);
  if (params?.limit) query.set("limit", params.limit.toString());
  if (params?.offset) query.set("offset", params.offset.toString());

  const res = await fetch(`${API_BASE}/findings?${query.toString()}`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`Failed to fetch findings: ${res.statusText}`);
  const json = await res.json();
  return {
    items: json.data || [],
    total_count: json.meta?.total_count ?? (json.data ? json.data.length : 0),
  };
}

export async function fetchDashboardMetrics(): Promise<DashboardMetrics> {
  const res = await fetch(`${API_BASE}/findings/dashboard`, {
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`Failed to fetch metrics: ${res.statusText}`);
  const json = await res.json();
  return json.data;
}

export async function fetchFindingDetail(id: string): Promise<Finding> {
  const res = await fetch(`${API_BASE}/findings/${id}`);
  if (!res.ok) throw new Error(`Failed to fetch finding ${id}: ${res.statusText}`);
  const json = await res.json();
  return json.data.finding;
}

export async function fetchFindingObservations(id: string): Promise<FindingObservation[]> {
  const res = await fetch(`${API_BASE}/findings/${id}/observations`);
  if (!res.ok) throw new Error(`Failed to fetch observations: ${res.statusText}`);
  const json = await res.json();
  return json.data || [];
}

export async function fetchFindingEvidence(id: string): Promise<EvidenceItem[]> {
  const res = await fetch(`${API_BASE}/findings/${id}/evidence`);
  if (!res.ok) throw new Error(`Failed to fetch evidence: ${res.statusText}`);
  const json = await res.json();
  return json.data || [];
}

export async function transitionFinding(
  id: string,
  targetStatus: string,
  reason: string
): Promise<void> {
  const res = await fetch(`${API_BASE}/findings/${id}/transition`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target_status: targetStatus, reason }),
  });
  if (!res.ok) throw new Error(`Failed to transition status: ${res.statusText}`);
}
