import { describe, it, expect, beforeEach } from "vitest";
import {
  fetchTargets,
  registerTarget,
  verifyTargetOwnership,
  updateTargetScope,
  deleteTarget,
  resetMockTargets,
} from "./targetsApi";

describe("Targets & Asset Scope Management (FE-11)", () => {
  beforeEach(() => {
    resetMockTargets();
  });

  it("retrieves target inventory with ownership and scope metadata", async () => {
    const targets = await fetchTargets();
    expect(targets).toBeDefined();
    expect(targets.length).toBeGreaterThan(0);

    const first = targets[0];
    expect(first.host).toBeDefined();
    expect(first.environment).toBeDefined();
    expect(first.verificationStatus).toBeDefined();
    expect(first.scopeConfig).toBeDefined();
  });

  it("filters targets by environment accurately", async () => {
    const staging = await fetchTargets({ environment: "STAGING" });
    expect(staging.length).toBeGreaterThan(0);
    staging.forEach((t) => {
      expect(t.environment).toBe("STAGING");
    });

    const prod = await fetchTargets({ environment: "PRODUCTION" });
    expect(prod.length).toBeGreaterThan(0);
    prod.forEach((t) => {
      expect(t.environment).toBe("PRODUCTION");
    });
  });

  it("filters targets by verification status", async () => {
    const verified = await fetchTargets({ verificationStatus: "VERIFIED" });
    expect(verified.length).toBeGreaterThan(0);
    verified.forEach((t) => {
      expect(t.verificationStatus).toBe("VERIFIED");
    });
  });

  it("registers new authorized target with DNS TXT challenge generation", async () => {
    const newTarget = await registerTarget({
      name: "Security Sandbox Gateway",
      host: "sandbox.kelvin-sec.internal",
      type: "DOMAIN",
      environment: "DEVELOPMENT",
      criticality: "TIER_3",
      allowedPorts: "80, 443, 9000",
      excludedPaths: ["/admin/reset"],
      maxRequestsPerSecond: 30,
    });

    expect(newTarget.id).toBeDefined();
    expect(newTarget.verificationStatus).toBe("PENDING_VERIFICATION");
    expect(newTarget.verificationChallenge.type).toBe("DNS_TXT");
    expect(newTarget.verificationChallenge.token).toContain("kelvin-verify=");
  });

  it("rejects malicious or invalid URL schemes during registration", async () => {
    await expect(
      registerTarget({
        name: "Malicious Scheme",
        host: "javascript:alert(1)",
        type: "URL",
        environment: "DEVELOPMENT",
        criticality: "TIER_4",
      })
    ).rejects.toThrow("Invalid URL scheme");

    await expect(
      registerTarget({
        name: "Empty Host",
        host: "",
        type: "DOMAIN",
        environment: "DEVELOPMENT",
        criticality: "TIER_4",
      })
    ).rejects.toThrow("Target host or URL is required");
  });

  it("completes domain ownership verification via challenge check", async () => {
    const result = await verifyTargetOwnership("tgt-03");
    expect(result.success).toBe(true);
    expect(result.verified).toBe(true);

    const targets = await fetchTargets();
    const updated = targets.find((t) => t.id === "tgt-03");
    expect(updated?.verificationStatus).toBe("VERIFIED");
    expect(updated?.verificationChallenge.verifiedAt).toBeDefined();
  });

  it("updates scope boundaries including excluded paths and rate limits", async () => {
    const updated = await updateTargetScope("tgt-01", {
      allowedPorts: "443, 8443",
      excludedPaths: ["/logout", "/danger-zone"],
      maxRequestsPerSecond: 40,
    });

    expect(updated.scopeConfig.allowedPorts).toBe("443, 8443");
    expect(updated.scopeConfig.excludedPaths).toContain("/danger-zone");
    expect(updated.scopeConfig.maxRequestsPerSecond).toBe(40);
  });

  it("deletes a target asset from the registry", async () => {
    const initial = await fetchTargets();
    const targetToDelete = initial[0].id;

    const success = await deleteTarget(targetToDelete);
    expect(success).toBe(true);

    const after = await fetchTargets();
    expect(after.some((t) => t.id === targetToDelete)).toBe(false);
  });
});
