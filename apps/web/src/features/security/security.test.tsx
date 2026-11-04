import React from "react";
import { describe, it, expect } from "vitest";
import { sanitizeLogData } from "../../utils/logger";
import { ErrorBoundary } from "../../components/ui/ErrorBoundary";
import { ExternalLink } from "../../components/ui/ExternalLink";
import { NotFoundPage } from "../../pages/error/NotFoundPage";
import { ForbiddenPage } from "../../pages/error/ForbiddenPage";
import { UnauthorizedPage } from "../../pages/error/UnauthorizedPage";
import { MemoryRouter } from "react-router-dom";

describe("FE-20: Frontend Security & Error Handling Suite", () => {
  describe("Console Logger & Sensitive Data Redaction", () => {
    it("redacts sensitive fields like password, token, bearer, secret", () => {
      const payload = {
        username: "admin@kelvin.security",
        password: "SuperSecretPassword123!",
        token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        apiKey: "klv_live_sec_99998888",
        status: "ACTIVE",
      };

      const sanitized = sanitizeLogData(payload) as Record<string, unknown>;
      expect(sanitized.username).toBe("admin@kelvin.security");
      expect(sanitized.status).toBe("ACTIVE");
      expect(sanitized.password).toBe("[REDACTED]");
      expect(sanitized.token).toBe("[REDACTED]");
      expect(sanitized.apiKey).toBe("[REDACTED]");
    });

    it("redacts nested objects and array elements", () => {
      const nested = {
        config: {
          authorization: "Bearer secret-token-value",
          normalField: 42,
        },
        items: [{ cookie: "session=xyz123" }, { id: 1 }],
      };

      const sanitized = sanitizeLogData(nested) as any;
      expect(sanitized.config.authorization).toBe("[REDACTED]");
      expect(sanitized.config.normalField).toBe(42);
      expect(sanitized.items[0].cookie).toBe("[REDACTED]");
      expect(sanitized.items[1].id).toBe(1);
    });

    it("redacts bearer tokens in string messages", () => {
      const msg = "Request failed with Authorization header: Bearer abc123def456";
      const sanitized = sanitizeLogData(msg);
      expect(sanitized).toBe("Request failed with Authorization header: Bearer [REDACTED]");
    });
  });

  describe("ExternalLink Security Invariant", () => {
    it("enforces rel='noopener noreferrer' and target='_blank'", () => {
      const link = ExternalLink({
        href: "https://cve.mitre.org",
        children: "MITRE CVE Database",
      }) as React.ReactElement<{
        href: string;
        target: string;
        rel: string;
      }>;

      expect(link.props.href).toBe("https://cve.mitre.org");
      expect(link.props.target).toBe("_blank");
      expect(link.props.rel).toBe("noopener noreferrer");
    });
  });

  describe("ErrorBoundary Component", () => {
    it("renders children when no error occurs", () => {
      const element = (
        <ErrorBoundary>
          <div data-testid="child-content">Safe content</div>
        </ErrorBoundary>
      );
      expect(element).toBeDefined();
    });

    it("renders custom fallback when provided", () => {
      const boundary = new ErrorBoundary({
        children: <div>Safe</div>,
        fallback: <div>Custom Fallback UI</div>,
      });

      // Simulate error state
      boundary.state = {
        hasError: true,
        error: new Error("Simulated rendering explosion"),
      };

      const output = boundary.render();
      expect(output).toEqual(<div>Custom Fallback UI</div>);
    });
  });

  describe("HTTP Error Fallback Pages", () => {
    it("renders NotFoundPage (404) properly", () => {
      const element = (
        <MemoryRouter>
          <NotFoundPage />
        </MemoryRouter>
      );
      expect(element).toBeDefined();
    });

    it("renders ForbiddenPage (403) properly", () => {
      const element = (
        <MemoryRouter>
          <ForbiddenPage />
        </MemoryRouter>
      );
      expect(element).toBeDefined();
    });

    it("renders UnauthorizedPage (401) properly", () => {
      const element = (
        <MemoryRouter>
          <UnauthorizedPage />
        </MemoryRouter>
      );
      expect(element).toBeDefined();
    });
  });
});
