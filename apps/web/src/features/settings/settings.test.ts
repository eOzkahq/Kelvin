import { describe, it, expect, beforeEach } from "vitest";
import {
  fetchPlatformSettings,
  updatePlatformSettings,
  fetchQuotaUsage,
  purgeExpiredEvidence,
  resetMockSettings,
} from "./settingsApi";

describe("Workspace & Platform Settings (FE-17)", () => {
  beforeEach(() => {
    resetMockSettings();
  });

  it("retrieves workspace platform configuration and quotas", async () => {
    const settings = await fetchPlatformSettings();
    expect(settings).toBeDefined();
    expect(settings.general.workspaceName).toBeDefined();
    expect(settings.assessmentDefaults.maxRequestsPerSecond).toBeGreaterThan(0);
    expect(settings.retention.retentionDays).toBeDefined();
    expect(settings.scanners.length).toBeGreaterThanOrEqual(4);
    expect(settings.quotas.monthlyAssessmentsLimit).toBeGreaterThan(0);
  });

  it("updates assessment execution defaults and guardrails", async () => {
    const updated = await updatePlatformSettings({
      assessmentDefaults: {
        maxRequestsPerSecond: 100,
        timeoutMinutes: 120,
        maxConcurrency: 8,
        maxRetries: 3,
      },
    });

    expect(updated.assessmentDefaults.maxRequestsPerSecond).toBe(100);
    expect(updated.assessmentDefaults.timeoutMinutes).toBe(120);
    expect(updated.assessmentDefaults.maxConcurrency).toBe(8);
  });

  it("updates evidence retention period and privacy settings", async () => {
    const updated = await updatePlatformSettings({
      retention: {
        retentionDays: 180,
        autoRedactionEnabled: true,
        hardDeleteAfterExpiry: true,
      },
    });

    expect(updated.retention.retentionDays).toBe(180);
    expect(updated.retention.autoRedactionEnabled).toBe(true);
  });

  it("toggles specific scanner engine availability", async () => {
    const settings = await fetchPlatformSettings();
    const zap = settings.scanners.find((s) => s.id === "zap");
    expect(zap).toBeDefined();

    const nextScanners = settings.scanners.map((s) =>
      s.id === "zap" ? { ...s, enabled: false } : s
    );

    const updated = await updatePlatformSettings({ scanners: nextScanners });
    const updatedZap = updated.scanners.find((s) => s.id === "zap");
    expect(updatedZap?.enabled).toBe(false);
  });

  it("retrieves tenant quota and usage metrics", async () => {
    const quotas = await fetchQuotaUsage();
    expect(quotas.monthlyAssessmentsUsed).toBeDefined();
    expect(quotas.monthlyAssessmentsLimit).toBeGreaterThan(0);
    expect(quotas.storageUsedBytes).toBeGreaterThan(0);
  });

  it("purges expired evidence records and frees storage quota", async () => {
    const initialStorage = (await fetchQuotaUsage()).storageUsedBytes;
    const result = await purgeExpiredEvidence();

    expect(result.purgedCount).toBeGreaterThan(0);
    expect(result.freedBytes).toBeGreaterThan(0);

    const afterStorage = (await fetchQuotaUsage()).storageUsedBytes;
    expect(afterStorage).toBeLessThan(initialStorage);
  });
});
