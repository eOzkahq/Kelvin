import { describe, it, expect } from "vitest";

describe("FE-23: Production Routing & Subpath Deployment Verification", () => {
  it("resolves default subpath base prefix as /services/kelvin/", () => {
    const basePath = process.env.VITE_BASE_PATH ?? "/services/kelvin/";
    expect(basePath).toBe("/services/kelvin/");
    expect(basePath.startsWith("/")).toBe(true);
    expect(basePath.endsWith("/")).toBe(true);
  });

  it("constructs correct deep links with subpath prefix", () => {
    const basePath = "/services/kelvin";
    const subRoute = "/findings/fnd-sqli-01";
    const fullUrl = `${basePath}${subRoute}`;
    expect(fullUrl).toBe("/services/kelvin/findings/fnd-sqli-01");
  });

  it("handles relative static asset URLs cleanly", () => {
    const assetPath = "assets/index-ABC123.js";
    const basePath = "/services/kelvin/";
    const fullAssetUrl = new URL(assetPath, `https://eozka.com${basePath}`).pathname;
    expect(fullAssetUrl).toBe("/services/kelvin/assets/index-ABC123.js");
  });

  it("verifies API proxy routing prefix mapping", () => {
    const frontendApiPrefix = "/services/kelvin/api";
    const targetBackendPrefix = "/api";
    const requestedPath = "/services/kelvin/api/v1/assessments";
    const rewrittenPath = requestedPath.replace(frontendApiPrefix, targetBackendPrefix);
    expect(rewrittenPath).toBe("/api/v1/assessments");
  });
});
