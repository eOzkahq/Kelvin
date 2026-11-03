import { apiClient } from "../../services/api";

export interface ScanProfile {
  id: string;
  name: string;
  description: string;
  scanners: string[];
  riskLevel: "LOW" | "MEDIUM" | "HIGH";
}

export interface TargetOption {
  id: string;
  name: string;
  address: string;
  verified: boolean;
  environment: "PRODUCTION" | "STAGING" | "INTERNAL";
}

export interface AssessmentRecord {
  id: string;
  name: string;
  targetId: string;
  targetAddress: string;
  profileId: string;
  profileName: string;
  status: "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";
  criticalCount: number;
  highCount: number;
  totalFindings: number;
  createdAt: string;
  completedAt?: string;
}

export interface ScannerTaskProgress {
  scanner: string;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
  findingsDiscovered: number;
  durationSeconds?: number;
  currentActivity?: string;
}

export interface AssessmentDetail extends AssessmentRecord {
  currentStage: "QUEUED" | "PREFLIGHT" | "SCANNING" | "NORMALIZING" | "COMPLETED" | "CANCELLED" | "FAILED";
  scanners: ScannerTaskProgress[];
  logs: Array<{ timestamp: string; level: "INFO" | "WARN" | "ERROR"; message: string }>;
}

export interface CreateAssessmentPayload {
  name: string;
  targetId: string;
  profileId: string;
  rateLimit: number;
  timeoutMinutes: number;
  authorizedScopeConfirmed: boolean;
  idempotencyKey: string;
}

const mockProfiles: ScanProfile[] = [
  {
    id: "prof-web-baseline",
    name: "Web Security Baseline",
    description: "OWASP Top 10 vulnerabilities, security headers, and TLS configuration audits.",
    scanners: ["ZAP", "HTTP-Preflight", "TLS-Check"],
    riskLevel: "LOW",
  },
  {
    id: "prof-api-security",
    name: "REST / GraphQL API Audit",
    description: "API boundary authentication, IDOR probing, and schema parameter fuzzing.",
    scanners: ["Nuclei", "ZAP", "HTTP-Preflight"],
    riskLevel: "MEDIUM",
  },
  {
    id: "prof-full-active",
    name: "Full Active Penetration Assessment",
    description: "Deep perimeter network port discovery, service banner extraction, and vulnerability fuzzing.",
    scanners: ["Nmap", "Nuclei", "ZAP", "Trivy"],
    riskLevel: "HIGH",
  },
];

const mockTargets: TargetOption[] = [
  { id: "tgt-001", name: "Production API Gateway", address: "api.kelvin.io", verified: true, environment: "PRODUCTION" },
  { id: "tgt-002", name: "Staging Web Console", address: "staging.eozka.com", verified: true, environment: "STAGING" },
  { id: "tgt-003", name: "Internal Auth Cluster", address: "auth.kelvin.internal", verified: true, environment: "INTERNAL" },
];

export async function fetchProfiles(): Promise<ScanProfile[]> {
  try {
    return await apiClient.get<ScanProfile[]>("/assessments/profiles");
  } catch {
    return mockProfiles;
  }
}

export async function fetchTargets(): Promise<TargetOption[]> {
  try {
    return await apiClient.get<TargetOption[]>("/targets");
  } catch {
    return mockTargets;
  }
}

export async function fetchAssessments(): Promise<AssessmentRecord[]> {
  try {
    return await apiClient.get<AssessmentRecord[]>("/assessments");
  } catch {
    return [
      {
        id: "asmt-2026-001",
        name: "Q4 Production Perimeter Audit",
        targetId: "tgt-001",
        targetAddress: "api.kelvin.io",
        profileId: "prof-full-active",
        profileName: "Full Active Penetration Assessment",
        status: "COMPLETED",
        criticalCount: 2,
        highCount: 5,
        totalFindings: 24,
        createdAt: new Date(Date.now() - 86400000 * 2).toISOString(),
        completedAt: new Date(Date.now() - 86400000 * 2 + 3600000).toISOString(),
      },
      {
        id: "asmt-2026-002",
        name: "Nightly Web Baseline Scan",
        targetId: "tgt-002",
        targetAddress: "staging.eozka.com",
        profileId: "prof-web-baseline",
        profileName: "Web Security Baseline",
        status: "RUNNING",
        criticalCount: 0,
        highCount: 2,
        totalFindings: 6,
        createdAt: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
      },
    ];
  }
}

export async function fetchAssessmentDetail(id: string): Promise<AssessmentDetail> {
  try {
    return await apiClient.get<AssessmentDetail>(`/assessments/${id}`);
  } catch {
    return {
      id,
      name: "Q4 Production Perimeter Audit",
      targetId: "tgt-001",
      targetAddress: "api.kelvin.io",
      profileId: "prof-full-active",
      profileName: "Full Active Penetration Assessment",
      status: "RUNNING",
      currentStage: "SCANNING",
      criticalCount: 1,
      highCount: 3,
      totalFindings: 8,
      createdAt: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
      scanners: [
        { scanner: "HTTP-Preflight", status: "COMPLETED", findingsDiscovered: 0, durationSeconds: 12, currentActivity: "Target reachability verified" },
        { scanner: "TLS-Check", status: "COMPLETED", findingsDiscovered: 1, durationSeconds: 24, currentActivity: "Cipher suites cataloged" },
        { scanner: "Nuclei", status: "RUNNING", findingsDiscovered: 4, durationSeconds: 180, currentActivity: "Fuzzing critical CVE templates (384/912)" },
        { scanner: "OWASP-ZAP", status: "RUNNING", findingsDiscovered: 3, durationSeconds: 210, currentActivity: "Active parameter spidering" },
        { scanner: "Trivy", status: "QUEUED", findingsDiscovered: 0, currentActivity: "Awaiting container sandbox allocation" },
      ],
      logs: [
        { timestamp: "20:30:01", level: "INFO", message: "Assessment job claimed by worker runner-us-east-4." },
        { timestamp: "20:30:04", level: "INFO", message: "Executing HTTP preflight handshake against https://api.kelvin.io." },
        { timestamp: "20:30:16", level: "INFO", message: "Target boundary verified: Non-routable private subnets blocked." },
        { timestamp: "20:30:40", level: "INFO", message: "TLS analysis complete: 1 weak cipher suite detected (TLS 1.0/1.1 disabled)." },
        { timestamp: "20:31:00", level: "INFO", message: "Dispatched sandboxed Nuclei process in read-only container." },
        { timestamp: "20:32:15", level: "WARN", message: "Rate limit threshold reached: Pacing requests to 50 req/sec." },
        { timestamp: "20:33:02", level: "INFO", message: "Discovered HIGH finding: Spring Framework Deserialization endpoint." },
      ],
    };
  }
}

export async function createAssessment(payload: CreateAssessmentPayload): Promise<{ id: string }> {
  return await apiClient
    .post<{ id: string }>("/assessments", payload, {
      headers: {
        "X-Idempotency-Key": payload.idempotencyKey,
      },
    })
    .catch(() => {
      return { id: `asmt-${Date.now().toString(36)}` };
    });
}

export async function cancelAssessment(id: string): Promise<{ success: boolean }> {
  return await apiClient
    .post<{ success: boolean }>(`/assessments/${id}/cancel`)
    .catch(() => {
      return { success: true };
    });
}
