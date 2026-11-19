import type { LiveProbeResult } from "../reports/liveScanStore";
import type {
  AssessmentDetail,
  AssessmentRecord,
  AssessmentCancelResponse,
  CreateAssessmentPayload,
  ScanProfile,
  TargetOption,
} from "./types";

export const mockProfiles: ScanProfile[] = [
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

export const mockTargets: TargetOption[] = [
  { id: "tgt-001", name: "Production API Gateway", address: "api.kelvin.io", verified: true, environment: "PRODUCTION" },
  { id: "tgt-002", name: "Staging Web Console", address: "staging.eozka.com", verified: true, environment: "STAGING" },
  { id: "tgt-003", name: "Internal Auth Cluster", address: "auth.kelvin.internal", verified: true, environment: "INTERNAL" },
];

export const INITIAL_ASSESSMENTS: AssessmentDetail[] = [
  {
    id: "asmt-2026-001",
    name: "Q4 Production Perimeter Audit",
    targetId: "tgt-001",
    targetAddress: "api.kelvin.io",
    profileId: "prof-full-active",
    profileName: "Full Active Penetration Assessment",
    status: "COMPLETED",
    currentStage: "COMPLETED",
    criticalCount: 2,
    highCount: 5,
    totalFindings: 24,
    createdAt: new Date(Date.now() - 86400000 * 2).toISOString(),
    completedAt: new Date(Date.now() - 86400000 * 2 + 3600000).toISOString(),
    scanners: [
      { id: "sc-1", scanner: "Nuclei", status: "COMPLETED", findingsCount: 14, startTime: "2026-11-08T10:00:00Z", endTime: "2026-11-08T10:30:00Z" },
      { id: "sc-2", scanner: "ZAP", status: "COMPLETED", findingsCount: 10, startTime: "2026-11-08T10:05:00Z", endTime: "2026-11-08T10:55:00Z" },
    ],
    logs: [
      { id: "log-1", timestamp: "2026-11-08T10:00:00Z", level: "INFO", message: "Starting preflight scope verification", stage: "PREFLIGHT" },
      { id: "log-2", timestamp: "2026-11-08T10:05:00Z", level: "INFO", message: "Dispatched scanner jobs to worker nodes", stage: "SCANNING" },
      { id: "log-3", timestamp: "2026-11-08T10:55:00Z", level: "INFO", message: "Assessment run successfully completed", stage: "COMPLETED" },
    ],
  },
  {
    id: "asmt-2026-002",
    name: "Nightly Web Baseline Scan",
    targetId: "tgt-002",
    targetAddress: "staging.eozka.com",
    profileId: "prof-web-baseline",
    profileName: "Web Security Baseline",
    status: "RUNNING",
    currentStage: "SCANNING",
    criticalCount: 0,
    highCount: 2,
    totalFindings: 6,
    createdAt: new Date(Date.now() - 1000 * 60 * 30).toISOString(),
    scanners: [
      { id: "sc-3", scanner: "ZAP", status: "RUNNING", findingsCount: 4, startTime: "2026-11-10T11:30:00Z" },
      { id: "sc-4", scanner: "TLS-Check", status: "COMPLETED", findingsCount: 2, startTime: "2026-11-10T11:30:00Z", endTime: "2026-11-10T11:35:00Z" },
    ],
    logs: [
      { id: "log-4", timestamp: "2026-11-10T11:30:00Z", level: "INFO", message: "TLS and HTTP Preflight completed", stage: "PREFLIGHT" },
      { id: "log-5", timestamp: "2026-11-10T11:32:00Z", level: "INFO", message: "ZAP crawler active on staging.eozka.com", stage: "SCANNING" },
    ],
  },
  {
    id: "asmt-2026-003",
    name: "Auth Cluster Boundary Check",
    targetId: "tgt-003",
    targetAddress: "auth.kelvin.internal",
    profileId: "prof-api-security",
    profileName: "REST / GraphQL API Audit",
    status: "QUEUED",
    currentStage: "QUEUED",
    criticalCount: 0,
    highCount: 0,
    totalFindings: 0,
    createdAt: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
    scanners: [
      { id: "sc-5", scanner: "Nuclei", status: "PENDING", findingsCount: 0 },
    ],
    logs: [
      { id: "log-6", timestamp: "2026-11-10T11:55:00Z", level: "INFO", message: "Job accepted by scheduler and queued", stage: "QUEUED" },
    ],
  },
];

let mockAssessmentsStore: AssessmentDetail[] = JSON.parse(JSON.stringify(INITIAL_ASSESSMENTS));

export const demoAssessmentProvider = {
  fetchProfiles(): Promise<ScanProfile[]> {
    return Promise.resolve(mockProfiles);
  },

  fetchTargets(): Promise<TargetOption[]> {
    return Promise.resolve(mockTargets);
  },

  fetchAssessments(): Promise<AssessmentRecord[]> {
    return Promise.resolve([...mockAssessmentsStore]);
  },

  fetchAssessmentDetail(id: string): Promise<AssessmentDetail> {
    const found = mockAssessmentsStore.find((a) => a.id === id);
    if (found) {
      return Promise.resolve(found);
    }
    return Promise.resolve({
      id,
      name: "Assessment Execution Run",
      targetAddress: "target.kelvin.internal",
      profileId: "prof-web-baseline",
      profileName: "Web Security Baseline",
      status: "RUNNING",
      currentStage: "SCANNING",
      criticalCount: 1,
      highCount: 2,
      totalFindings: 3,
      createdAt: new Date().toISOString(),
      scanners: [
        { id: `sc-nuclei-${id}`, scanner: "Nuclei", status: "RUNNING", findingsCount: 2, startTime: new Date().toISOString() },
        { id: `sc-zap-${id}`, scanner: "ZAP", status: "COMPLETED", findingsCount: 1, startTime: new Date().toISOString(), endTime: new Date().toISOString() },
      ],
      logs: [
        { id: `log-init-${id}`, timestamp: new Date().toISOString(), level: "INFO", message: "Worker initialized and running preflight", stage: "PREFLIGHT" },
        { id: `log-run-${id}`, timestamp: new Date().toISOString(), level: "INFO", message: "Streaming live logs from execution runner", stage: "SCANNING" },
      ],
    });
  },

  cancelAssessment(id: string): Promise<AssessmentCancelResponse> {
    const found = mockAssessmentsStore.find((a) => a.id === id);
    if (found) {
      found.status = "CANCELLED";
      found.currentStage = "CANCELLED";
    }
    return Promise.resolve({ success: true, message: `Assessment ${id} cancellation signal sent` });
  },

  createAssessment(payload: CreateAssessmentPayload): Promise<{ id: string }> {
    const newId = `asmt-${Date.now().toString(36)}`;
    const resolvedTarget =
      payload.targets?.[0]?.host ||
      mockTargets.find((t) => t.id === payload.targetId)?.address ||
      "configured-target.internal";
    const profileName =
      mockProfiles.find((p) => p.id === payload.profileId)?.name || "Standard Security Profile";

    const newRecord: AssessmentDetail = {
      id: newId,
      name: payload.name,
      targetId: payload.targetId,
      targetAddress: resolvedTarget,
      profileId: payload.profileId,
      profileName,
      status: "COMPLETED",
      currentStage: "COMPLETED",
      criticalCount: 0,
      highCount: 0,
      totalFindings: 0,
      createdAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      scanners: [
        { id: `sc-dns-${newId}`, scanner: "DNS & TLS Inspector", status: "COMPLETED", findingsCount: 0 },
        { id: `sc-hdr-${newId}`, scanner: "HTTP Header Auditor", status: "COMPLETED", findingsCount: 0 },
      ],
      logs: [
        { id: `log-init-${newId}`, timestamp: new Date(Date.now() - 4000).toISOString(), level: "INFO", message: "Assessment created and queued", stage: "QUEUED" },
        { id: `log-pref-${newId}`, timestamp: new Date(Date.now() - 3000).toISOString(), level: "INFO", message: `[Preflight] Validating target scope and DNS resolution for ${resolvedTarget}`, stage: "PREFLIGHT" },
        { id: `log-tls-${newId}`, timestamp: new Date(Date.now() - 2000).toISOString(), level: "INFO", message: `[Preflight] Verified SSL/TLS 1.2+ certificate validity and target reachability`, stage: "PREFLIGHT" },
        { id: `log-scan-${newId}`, timestamp: new Date(Date.now() - 1000).toISOString(), level: "INFO", message: `[Scanner Engine] Completed vulnerability probes; zero security anomalies detected within target scope (${resolvedTarget})`, stage: "SCANNING" },
        { id: `log-done-${newId}`, timestamp: new Date().toISOString(), level: "INFO", message: `Assessment execution completed successfully. Total findings discovered: 0`, stage: "COMPLETED" },
      ],
    };
    mockAssessmentsStore.unshift(newRecord);
    return Promise.resolve({ id: newId });
  },

  attachLiveProbe(id: string, probe: LiveProbeResult): void {
    const found = mockAssessmentsStore.find((a) => a.id === id);
    if (!found) return;
    found.targetAddress = probe.targetUrl;
    found.status = "COMPLETED";
    found.currentStage = "COMPLETED";
    found.completedAt = new Date().toISOString();
    found.criticalCount = probe.findings.filter((f) => f.severity === "CRITICAL").length;
    found.highCount = probe.findings.filter((f) => f.severity === "HIGH").length;
    found.totalFindings = probe.findings.length;
    found.scanners = [
      {
        id: `sc-dns-${id}`,
        scanner: "DNS & TLS Inspector",
        status: "COMPLETED",
        findingsCount: probe.findings.filter((f) => f.scanner === "dns-probe" || f.scanner === "tls-check").length,
        startTime: found.createdAt,
        endTime: found.completedAt,
      },
      {
        id: `sc-hdr-${id}`,
        scanner: "HTTP Header Auditor",
        status: "COMPLETED",
        findingsCount: probe.findings.filter((f) => f.scanner === "http-headers" || f.scanner === "http-preflight").length,
        startTime: found.createdAt,
        endTime: found.completedAt,
      },
    ];
    found.logs = probe.logs.map((l, idx) => ({
      id: `log-live-${idx}`,
      timestamp: l.timestamp,
      level: l.level,
      message: l.message,
      stage: l.stage,
    }));
  },

  resetMockAssessments(): void {
    mockAssessmentsStore = JSON.parse(JSON.stringify(INITIAL_ASSESSMENTS));
  },
};
