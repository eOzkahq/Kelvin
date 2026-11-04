export interface SeverityDistribution {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface DashboardMetrics {
  totalAssessments: number;
  activeJobs: number;
  totalFindings: number;
  slaBreaches: number;
  severityDistribution: SeverityDistribution;
  scannerReadiness: {
    nmap: boolean;
    nuclei: boolean;
    trivy: boolean;
    zap: boolean;
  };
}

export interface RecentFinding {
  id: string;
  fingerprint: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  target: string;
  scanner: string;
  discoveredAt: string;
}

export interface ActiveJob {
  id: string;
  name: string;
  target: string;
  profile: string;
  status: "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";
  startedAt: string;
  currentStage: string;
}
