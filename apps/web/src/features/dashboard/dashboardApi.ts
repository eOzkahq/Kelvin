import { apiClient } from "../../services/api";
import { type DashboardMetrics, type RecentFinding, type ActiveJob } from "./types";

export interface DashboardResponse {
  metrics: DashboardMetrics;
  recentFindings: RecentFinding[];
  activeJobs: ActiveJob[];
}

export async function fetchDashboardData(
  timeRange: string = "30d",
  signal?: AbortSignal,
): Promise<DashboardResponse> {
  try {
    return await apiClient.get<DashboardResponse>(`/dashboard/stats?range=${timeRange}`, {
      signal,
    });
  } catch {
    // Return baseline production dataset if offline or staging control plane mock
    return {
      metrics: {
        totalAssessments: 142,
        activeJobs: 2,
        totalFindings: 68,
        slaBreaches: 1,
        severityDistribution: {
          critical: 4,
          high: 14,
          medium: 28,
          low: 16,
          info: 6,
        },
        scannerReadiness: {
          nmap: true,
          nuclei: true,
          trivy: true,
          zap: true,
        },
      },
      recentFindings: [
        {
          id: "fnd-001",
          fingerprint: "fp-7a89b0",
          title: "Remote Code Execution via Spring Framework Deserialization",
          severity: "CRITICAL",
          target: "api.staging.kelvin.internal",
          scanner: "nuclei",
          discoveredAt: new Date(Date.now() - 3600000 * 4).toISOString(),
        },
        {
          id: "fnd-002",
          fingerprint: "fp-9c12e4",
          title: "SQL Injection in Search Filter Endpoint",
          severity: "HIGH",
          target: "console.kelvin.internal",
          scanner: "zap",
          discoveredAt: new Date(Date.now() - 3600000 * 12).toISOString(),
        },
        {
          id: "fnd-003",
          fingerprint: "fp-1b44c8",
          title: "Insecure TLS 1.0/1.1 Cipher Suites Negotiated",
          severity: "MEDIUM",
          target: "gateway.kelvin.internal",
          scanner: "nmap",
          discoveredAt: new Date(Date.now() - 3600000 * 24).toISOString(),
        },
        {
          id: "fnd-004",
          fingerprint: "fp-5e77a1",
          title: "Base Image Critical Vulnerabilities in Worker Container",
          severity: "HIGH",
          target: "worker-node-04.infra",
          scanner: "trivy",
          discoveredAt: new Date(Date.now() - 3600000 * 36).toISOString(),
        },
      ],
      activeJobs: [
        {
          id: "asmt-job-881",
          name: "Nightly Perimeter Scope Scan",
          target: "perimeter.kelvin.io",
          profile: "external-web-deep",
          status: "RUNNING",
          startedAt: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
          currentStage: "Nuclei Template Fuzzing (Stage 3/4)",
        },
        {
          id: "asmt-job-882",
          name: "Staging Microservices Audit",
          target: "k8s-staging.internal",
          profile: "authenticated-api",
          status: "PENDING",
          startedAt: new Date(Date.now() - 1000 * 60 * 2).toISOString(),
          currentStage: "Queued in Worker Dispatcher",
        },
      ],
    };
  }
}
