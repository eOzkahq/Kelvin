import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import {
  apiClient,
  ApiError,
  setAuthToken,
  getAuthToken,
  clearAuthToken,
  setTenantContext,
  getTenantContext,
  onUnauthorized,
  request,
} from "./api";
import { loadAppConfig } from "../config/env";

describe("FE-01: Centralized API Client & Interceptors Suite", () => {
  beforeEach(() => {
    clearAuthToken();
    setTenantContext({});
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe("Authentication & Tenant Interceptors", () => {
    it("manages in-memory auth token correctly", () => {
      expect(getAuthToken()).toBeNull();
      setAuthToken("jwt-token-xyz");
      expect(getAuthToken()).toBe("jwt-token-xyz");
      clearAuthToken();
      expect(getAuthToken()).toBeNull();
    });

    it("injects Authorization: Bearer <token> into outgoing fetch requests", async () => {
      setAuthToken("test-bearer-token");

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ success: true, data: { status: "ok" } }),
      });
      vi.stubGlobal("fetch", mockFetch);

      await apiClient.get("/test-endpoint");

      expect(mockFetch).toHaveBeenCalledTimes(1);
      const [, init] = mockFetch.mock.calls[0];
      expect(init.headers["Authorization"]).toBe("Bearer test-bearer-token");
      expect(init.headers["Accept"]).toBe("application/json");
    });

    it("injects X-Tenant-ID and X-Workspace-ID headers when configured", async () => {
      setTenantContext({
        tenantId: "tenant-org-001",
        workspaceId: "ws-primary-002",
      });

      expect(getTenantContext()).toEqual({
        tenantId: "tenant-org-001",
        workspaceId: "ws-primary-002",
      });

      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ success: true, data: { status: "ok" } }),
      });
      vi.stubGlobal("fetch", mockFetch);

      await apiClient.get("/tenant-data");

      const [, init] = mockFetch.mock.calls[0];
      expect(init.headers["X-Tenant-ID"]).toBe("tenant-org-001");
      expect(init.headers["X-Workspace-ID"]).toBe("ws-primary-002");
    });
  });

  describe("Error Mapping & 401 Session Interceptor", () => {
    it("triggers onUnauthorized callbacks when API returns 401 status", async () => {
      const unauthorizedSpy = vi.fn();
      const unsubscribe = onUnauthorized(unauthorizedSpy);

      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        json: async () => ({
          type: "urn:kelvin:problem:unauthorized",
          title: "Session Expired",
          status: 401,
          detail: "Your authentication token has expired.",
          correlation_id: "corr-401-abc",
        }),
      });
      vi.stubGlobal("fetch", mockFetch);

      await expect(apiClient.get("/protected")).rejects.toThrow("Your authentication token has expired.");
      expect(unauthorizedSpy).toHaveBeenCalledTimes(1);

      // Unsubscribe check
      unsubscribe();
      await expect(apiClient.get("/protected")).rejects.toThrow();
      expect(unauthorizedSpy).toHaveBeenCalledTimes(1); // not called again
    });

    it("normalizes RFC 7807 Problem Details into ApiError instance", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 422,
        json: async () => ({
          type: "urn:kelvin:problem:validation_error",
          title: "Validation Error",
          status: 422,
          detail: "Target host must be a fully qualified domain or valid IP address.",
          correlation_id: "corr-val-999",
          errors: [{ field: "target", code: "invalid_format", message: "is loopback" }],
        }),
      });
      vi.stubGlobal("fetch", mockFetch);

      try {
        await apiClient.post("/targets", { address: "127.0.0.1" });
        expect.unreachable("Should have thrown ApiError");
      } catch (err) {
        expect(err).toBeInstanceOf(ApiError);
        const apiErr = err as ApiError;
        expect(apiErr.status).toBe(422);
        expect(apiErr.correlationId).toBe("corr-val-999");
        expect(apiErr.message).toBe("Target host must be a fully qualified domain or valid IP address.");
        expect(apiErr.code).toBe("urn:kelvin:problem:validation_error");
      }
    });
  });

  describe("Typed HTTP Methods", () => {
    it("executes POST with JSON serialized payload", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ success: true, data: { id: "asmt-123" } }),
      });
      vi.stubGlobal("fetch", mockFetch);

      const payload = { name: "Quarterly Assessment", profile: "deep-web" };
      const res = await apiClient.post<{ id: string }>("/assessments", payload);

      expect(res.id).toBe("asmt-123");
      const [, init] = mockFetch.mock.calls[0];
      expect(init.method).toBe("POST");
      expect(init.headers["Content-Type"]).toBe("application/json");
      expect(init.body).toBe(JSON.stringify(payload));
    });

    it("executes DELETE request with correct method", async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ success: true, data: { deleted: true } }),
      });
      vi.stubGlobal("fetch", mockFetch);

      await apiClient.delete("/targets/tgt-456");

      const [, init] = mockFetch.mock.calls[0];
      expect(init.method).toBe("DELETE");
    });
  });

  describe("Request Cancellation & Timeouts", () => {
    it("respects external AbortSignal cancellation", async () => {
      const controller = new AbortController();
      controller.abort(new Error("User cancelled"));

      const mockFetch = vi.fn().mockImplementation((_url, init) => {
        if (init?.signal?.aborted) {
          return Promise.reject(new Error("The user aborted a request."));
        }
        return Promise.resolve({
          ok: true,
          json: async () => ({ success: true, data: {} }),
        });
      });
      vi.stubGlobal("fetch", mockFetch);

      await expect(
        request("/long-running", { signal: controller.signal })
      ).rejects.toThrow("The user aborted a request.");
    });
  });

  describe("Environment Configuration Validation", () => {
    it("loads and validates default environment configuration", () => {
      const config = loadAppConfig();
      expect(config.apiBase).toMatch(/^\/api/);
      expect(typeof config.basePath).toBe("string");
      expect(typeof config.isProduction).toBe("boolean");
    });
  });
});
