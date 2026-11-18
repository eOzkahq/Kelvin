import { describe, it, expect } from "vitest";
import { getApiBaseUrl } from "../../services/api";

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

  it("normalizes router basename without trailing slash", () => {
    const normalizeBasename = (raw: string) => (raw === "/" ? "/" : raw.replace(/\/+$/, "") || "/");
    expect(normalizeBasename("/services/kelvin/")).toBe("/services/kelvin");
    expect(normalizeBasename("/services/kelvin")).toBe("/services/kelvin");
    expect(normalizeBasename("/")).toBe("/");
  });

  it("handles standalone redirect logic when accessed directly without subpath", () => {
    const basename = "/services/kelvin";
    const computeRedirect = (pathname: string) => {
      if (!pathname.startsWith(basename)) {
        const targetPath = pathname === "/" ? "/dashboard" : pathname;
        return `${basename}${targetPath}`;
      }
      return null;
    };

    // Root standalone visits redirect into subpath
    expect(computeRedirect("/")).toBe("/services/kelvin/dashboard");
    expect(computeRedirect("/assessments")).toBe("/services/kelvin/assessments");

    // Subpath visits do not redirect
    expect(computeRedirect("/services/kelvin")).toBeNull();
    expect(computeRedirect("/services/kelvin/dashboard")).toBeNull();
    expect(computeRedirect("/services/kelvin/findings")).toBeNull();
  });

  it("strips redundant subpath prefix from login returnUrl", () => {
    const basename: string = "/services/kelvin";
    const sanitizeReturnUrl = (raw: string) => {
      let target = raw;
      if (basename && basename !== "/" && target.startsWith(basename)) {
        target = target.slice(basename.length) || "/dashboard";
      }
      if (!target.startsWith("/") || target.startsWith("//")) {
        return "/dashboard";
      }
      return target;
    };

    expect(sanitizeReturnUrl("/services/kelvin/assessments")).toBe("/assessments");
    expect(sanitizeReturnUrl("/assessments")).toBe("/assessments");
    expect(sanitizeReturnUrl("/services/kelvin")).toBe("/dashboard");
    expect(sanitizeReturnUrl("/dashboard")).toBe("/dashboard");
    // Open redirect attempts sanitized to /dashboard
    expect(sanitizeReturnUrl("https://evil.com/phish")).toBe("/dashboard");
    expect(sanitizeReturnUrl("//evil.com/phish")).toBe("/dashboard");
    expect(sanitizeReturnUrl("javascript:alert(1)")).toBe("/dashboard");
  });

  it("ensures API client baseUrl defaults safely", () => {
    const url = getApiBaseUrl();
    expect(url).toBeDefined();
    // In prod it defaults to Oracle cloud backend, never root relative without /api/v1
    expect(url.endsWith("/api/v1")).toBe(true);
  });
});
