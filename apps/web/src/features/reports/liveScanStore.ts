export interface LiveProbeFinding {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  cvss: number;
  cwe: string;
  endpoint: string;
  scanner: string;
  description: string;
  evidence: string;
  remediation: string;
}

export interface LiveProbeResult {
  targetUrl: string;
  hostname: string;
  planTier?: 1 | 2 | 3;
  resolvedIps: string[];
  httpStatus: number | null;
  latencyMs: number;
  redirectsToHttps: boolean | null;
  tls: {
    supported: boolean;
    protocol: string | null;
    cipher: string | null;
    issuer: string | null;
    validTo: string | null;
    daysRemaining: number | null;
  };
  headers: Record<string, string>;
  hasSecurityTxt: boolean;
  findings: LiveProbeFinding[];
  logs: Array<{ timestamp: string; level: "INFO" | "WARN" | "ERROR"; message: string; stage: string }>;
}

const STORAGE_KEY = "kelvin_live_scan_results";
const memoryStore = new Map<string, LiveProbeResult>();

function persistStore(): void {
  try {
    const obj: Record<string, LiveProbeResult> = {};
    memoryStore.forEach((v, k) => {
      obj[k] = v;
    });
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(obj));
  } catch {
    // ignore storage limits
  }
}

function hydrateStore(): void {
  if (memoryStore.size > 0) return;
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const obj = JSON.parse(raw) as Record<string, LiveProbeResult>;
    Object.entries(obj).forEach(([k, v]) => memoryStore.set(k, v));
  } catch {
    // ignore
  }
}

export function saveLiveScanResult(assessmentId: string, result: LiveProbeResult): void {
  memoryStore.set(assessmentId, result);
  persistStore();
}

export function getLiveScanResult(assessmentId: string): LiveProbeResult | undefined {
  hydrateStore();
  return memoryStore.get(assessmentId);
}

export function getAllLiveScanResults(): Array<{ assessmentId: string; result: LiveProbeResult }> {
  hydrateStore();
  return Array.from(memoryStore.entries()).map(([assessmentId, result]) => ({ assessmentId, result }));
}

export async function runLiveWebsiteProbe(
  target: string,
  tier: 1 | 2 | 3 = 1,
): Promise<LiveProbeResult> {
  const resp = await fetch("/services/kelvin/__live_probe", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, tier }),
  });
  const data = (await resp.json()) as LiveProbeResult & { error?: string };
  if (!resp.ok) {
    throw new Error(data.error || `Live probe returned HTTP ${resp.status}`);
  }
  return data;
}

