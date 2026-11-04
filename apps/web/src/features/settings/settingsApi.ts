import { request } from "../../services/api";
import type { PlatformWorkspaceSettings, QuotaUsage } from "./types";

let mockSettingsStore: PlatformWorkspaceSettings = {
  general: {
    workspaceName: "Primary Enterprise Core",
    slug: "primary-core",
    timezone: "UTC",
    contactEmail: "secops@kelvin.io",
  },
  assessmentDefaults: {
    maxRequestsPerSecond: 50,
    timeoutMinutes: 60,
    maxConcurrency: 5,
    maxRetries: 2,
  },
  retention: {
    retentionDays: 90,
    autoRedactionEnabled: true,
    hardDeleteAfterExpiry: true,
  },
  scanners: [
    { id: "nuclei", name: "Nuclei Template Scanner", description: "Vulnerability detection via community and corporate CVE templates", enabled: true },
    { id: "zap", name: "OWASP ZAP Active Spider", description: "Automated dynamic web application parameter fuzzing", enabled: true },
    { id: "nmap", name: "Nmap Network Scanner", description: "Port scanning, service detection, and OS fingerprinting", enabled: true },
    { id: "trivy", name: "Trivy Container Scanner", description: "OS packages and container image dependency auditing", enabled: true },
    { id: "tls", name: "TLS / SSL Cipher Analyzer", description: "Certificate expiration and cipher suite cryptographic validation", enabled: true },
  ],
  quotas: {
    monthlyAssessmentsUsed: 142,
    monthlyAssessmentsLimit: 500,
    concurrencySlotsUsed: 2,
    concurrencySlotsLimit: 10,
    storageUsedBytes: 2_400_000_000, // 2.4 GB
    storageLimitBytes: 10_000_000_000, // 10 GB
  },
};

export async function fetchPlatformSettings(): Promise<PlatformWorkspaceSettings> {
  try {
    const res = await request<PlatformWorkspaceSettings>("/settings/workspace");
    if (res && res.general) return res;
  } catch {
    // Local fallback
  }
  return {
    ...mockSettingsStore,
    scanners: [...mockSettingsStore.scanners],
    quotas: { ...mockSettingsStore.quotas },
  };
}

export async function updatePlatformSettings(
  updates: Partial<PlatformWorkspaceSettings>
): Promise<PlatformWorkspaceSettings> {
  try {
    const res = await request<PlatformWorkspaceSettings>("/settings/workspace", {
      method: "PATCH",
      body: JSON.stringify(updates),
    });
    if (res && res.general) return res;
  } catch {
    // Local fallback
  }

  mockSettingsStore = {
    ...mockSettingsStore,
    ...updates,
    general: { ...mockSettingsStore.general, ...(updates.general || {}) },
    assessmentDefaults: { ...mockSettingsStore.assessmentDefaults, ...(updates.assessmentDefaults || {}) },
    retention: { ...mockSettingsStore.retention, ...(updates.retention || {}) },
    scanners: updates.scanners || mockSettingsStore.scanners,
  };

  return mockSettingsStore;
}

export async function fetchQuotaUsage(): Promise<QuotaUsage> {
  try {
    const res = await request<QuotaUsage>("/settings/quotas");
    if (res && res.monthlyAssessmentsLimit) return res;
  } catch {
    // Local fallback
  }
  return { ...mockSettingsStore.quotas };
}

export async function purgeExpiredEvidence(): Promise<{ purgedCount: number; freedBytes: number }> {
  try {
    const res = await request<{ purgedCount: number; freedBytes: number }>("/settings/retention/purge", {
      method: "POST",
    });
    if (res && res.purgedCount !== undefined) return res;
  } catch {
    // Local fallback
  }

  mockSettingsStore.quotas.storageUsedBytes = Math.max(
    500_000_000,
    mockSettingsStore.quotas.storageUsedBytes - 800_000_000
  );

  return {
    purgedCount: 148,
    freedBytes: 800_000_000,
  };
}

export function resetMockSettings(): void {
  mockSettingsStore = {
    ...mockSettingsStore,
    scanners: mockSettingsStore.scanners.map((s) => ({ ...s })),
    quotas: { ...mockSettingsStore.quotas },
  };
}
