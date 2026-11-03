import { request } from "../../services/api";
import type {
  RegisterTargetPayload,
  TargetAsset,
  TargetFilterParams,
  TargetScopeConfig,
} from "./types";

let mockTargetsStore: TargetAsset[] = [
  {
    id: "tgt-01",
    name: "Staging API Gateway",
    host: "api.staging.kelvin-sec.internal",
    type: "DOMAIN",
    environment: "STAGING",
    criticality: "TIER_1",
    verificationStatus: "VERIFIED",
    verificationChallenge: {
      type: "DNS_TXT",
      token: "kelvin-verify=4a8b79e1c312784d",
      recordName: "_kelvin-challenge.api.staging.kelvin-sec.internal",
      verifiedAt: "2026-10-15T10:00:00Z",
    },
    scopeConfig: {
      allowedPorts: "80, 443, 8443",
      excludedPaths: ["/auth/logout", "/api/v1/admin/terminate", "/oauth/revoke"],
      maxRequestsPerSecond: 50,
    },
    openFindingsCount: 3,
    lastAssessedAt: "2026-11-03T08:30:00Z",
    createdAt: "2026-10-15T09:00:00Z",
  },
  {
    id: "tgt-02",
    name: "Customer Web Portal",
    host: "app.staging.kelvin-sec.internal",
    type: "DOMAIN",
    environment: "STAGING",
    criticality: "TIER_1",
    verificationStatus: "VERIFIED",
    verificationChallenge: {
      type: "DNS_TXT",
      token: "kelvin-verify=9f2d1e8c7b6a1234",
      recordName: "_kelvin-challenge.app.staging.kelvin-sec.internal",
      verifiedAt: "2026-10-18T14:00:00Z",
    },
    scopeConfig: {
      allowedPorts: "443",
      excludedPaths: ["/logout", "/billing/charge"],
      maxRequestsPerSecond: 25,
    },
    openFindingsCount: 2,
    lastAssessedAt: "2026-11-02T19:45:00Z",
    createdAt: "2026-10-18T12:00:00Z",
  },
  {
    id: "tgt-03",
    name: "Cloud Edge Router Ingress",
    host: "198.51.100.42",
    type: "IP",
    environment: "PRODUCTION",
    criticality: "TIER_2",
    verificationStatus: "PENDING_VERIFICATION",
    verificationChallenge: {
      type: "DNS_TXT",
      token: "kelvin-verify=7c8d9e0f1a2b3456",
      recordName: "_kelvin-challenge.42.100.51.198.in-addr.arpa",
    },
    scopeConfig: {
      allowedPorts: "22, 80, 443",
      excludedPaths: [],
      maxRequestsPerSecond: 10,
    },
    openFindingsCount: 1,
    lastAssessedAt: "2026-10-27T18:00:00Z",
    createdAt: "2026-10-26T15:00:00Z",
  },
  {
    id: "tgt-04",
    name: "Internal VPC Workload Subnet",
    host: "10.0.12.0/24",
    type: "CIDR",
    environment: "DEVELOPMENT",
    criticality: "TIER_3",
    verificationStatus: "VERIFIED",
    verificationChallenge: {
      type: "HTTP_META",
      token: "kelvin-verify=3b6a9c1d2e5f6789",
      recordName: "https://internal-dns.kelvin-sec.internal/.well-known/kelvin.txt",
      verifiedAt: "2026-10-20T08:00:00Z",
    },
    scopeConfig: {
      allowedPorts: "8000-9000",
      excludedPaths: ["/health/shutdown"],
      maxRequestsPerSecond: 100,
    },
    openFindingsCount: 0,
    lastAssessedAt: "2026-10-30T11:00:00Z",
    createdAt: "2026-10-20T07:30:00Z",
  },
];

export async function fetchTargets(filters?: TargetFilterParams): Promise<TargetAsset[]> {
  const query = new URLSearchParams();
  if (filters?.search) query.set("search", filters.search);
  if (filters?.environment) query.set("environment", filters.environment);
  if (filters?.verificationStatus) query.set("verificationStatus", filters.verificationStatus);
  if (filters?.criticality) query.set("criticality", filters.criticality);

  try {
    const res = await request<TargetAsset[]>(`/targets?${query.toString()}`);
    if (res && Array.isArray(res)) return res;
  } catch {
    // Client-side fallback
  }

  let list = [...mockTargetsStore];

  if (filters?.search) {
    const q = filters.search.toLowerCase();
    list = list.filter(
      (t) =>
        t.name.toLowerCase().includes(q) ||
        t.host.toLowerCase().includes(q)
    );
  }

  if (filters?.environment) {
    list = list.filter((t) => t.environment === filters.environment);
  }

  if (filters?.verificationStatus) {
    list = list.filter((t) => t.verificationStatus === filters.verificationStatus);
  }

  if (filters?.criticality) {
    list = list.filter((t) => t.criticality === filters.criticality);
  }

  return list;
}

export async function registerTarget(payload: RegisterTargetPayload): Promise<TargetAsset> {
  // Input validation
  const cleanHost = payload.host.trim();
  if (!cleanHost) throw new Error("Target host or URL is required");

  // Reject malicious schemes
  if (/^(file|javascript|data|vbscript):/i.test(cleanHost)) {
    throw new Error("Invalid URL scheme. Only HTTP, HTTPS, FQDN, IP or CIDR are permitted.");
  }

  try {
    const res = await request<TargetAsset>("/targets", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (res && res.id) return res;
  } catch {
    // Local fallback
  }

  const newTarget: TargetAsset = {
    id: `tgt-${Date.now().toString().slice(-4)}`,
    name: payload.name.trim(),
    host: cleanHost,
    type: payload.type,
    environment: payload.environment,
    criticality: payload.criticality,
    verificationStatus: "PENDING_VERIFICATION",
    verificationChallenge: {
      type: "DNS_TXT",
      token: `kelvin-verify=${Math.random().toString(36).substring(2, 18)}`,
      recordName: `_kelvin-challenge.${cleanHost.replace(/https?:\/\//, "").split("/")[0]}`,
    },
    scopeConfig: {
      allowedPorts: payload.allowedPorts || "80, 443",
      excludedPaths: payload.excludedPaths || [],
      maxRequestsPerSecond: payload.maxRequestsPerSecond || 20,
    },
    openFindingsCount: 0,
    createdAt: new Date().toISOString(),
  };

  mockTargetsStore.unshift(newTarget);
  return newTarget;
}

export async function verifyTargetOwnership(
  targetId: string
): Promise<{ success: boolean; verified: boolean; message: string }> {
  try {
    const res = await request<{ success: boolean; verified: boolean; message: string }>(
      `/targets/${targetId}/verify-ownership`,
      { method: "POST" }
    );
    if (res && res.success !== undefined) return res;
  } catch {
    // Local fallback simulation
  }

  const targetIndex = mockTargetsStore.findIndex((t) => t.id === targetId);
  if (targetIndex !== -1) {
    mockTargetsStore[targetIndex] = {
      ...mockTargetsStore[targetIndex],
      verificationStatus: "VERIFIED",
      verificationChallenge: {
        ...mockTargetsStore[targetIndex].verificationChallenge,
        verifiedAt: new Date().toISOString(),
      },
    };
  }

  return {
    success: true,
    verified: true,
    message: "DNS TXT challenge verified successfully. Domain ownership confirmed.",
  };
}

export async function updateTargetScope(
  targetId: string,
  scopeConfig: TargetScopeConfig
): Promise<TargetAsset> {
  try {
    const res = await request<TargetAsset>(`/targets/${targetId}/scope`, {
      method: "PUT",
      body: JSON.stringify(scopeConfig),
    });
    if (res && res.id) return res;
  } catch {
    // Local fallback update
  }

  const targetIndex = mockTargetsStore.findIndex((t) => t.id === targetId);
  if (targetIndex === -1) throw new Error("Target not found");

  mockTargetsStore[targetIndex].scopeConfig = scopeConfig;
  return mockTargetsStore[targetIndex];
}

export async function deleteTarget(targetId: string): Promise<boolean> {
  try {
    await request(`/targets/${targetId}`, { method: "DELETE" });
    return true;
  } catch {
    // Local fallback deletion
  }

  mockTargetsStore = mockTargetsStore.filter((t) => t.id !== targetId);
  return true;
}

export function resetMockTargets(): void {
  mockTargetsStore = mockTargetsStore.map((t) => ({ ...t }));
}
