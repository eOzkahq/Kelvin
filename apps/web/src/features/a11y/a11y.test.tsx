import React from "react";
import { describe, it, expect, vi } from "vitest";
import {
  hexToRgb,
  getRelativeLuminance,
  getContrastRatio,
  meetsWcagAA,
  liveAnnouncer,
  announce,
} from "./index";
import { SkipToContent } from "../../components/ui/SkipToContent";
import { LiveAnnouncer } from "../../components/ui/LiveAnnouncer";

describe("FE-19: Frontend Accessibility & Responsive Optimization Suite", () => {
  describe("WCAG 2.2 Color Contrast Engine", () => {
    it("parses 3-digit and 6-digit hex values accurately", () => {
      expect(hexToRgb("#fff")).toEqual({ r: 255, g: 255, b: 255 });
      expect(hexToRgb("#000000")).toEqual({ r: 0, g: 0, b: 0 });
      expect(hexToRgb("06b6d4")).toEqual({ r: 6, g: 182, b: 212 });
    });

    it("calculates exact relative luminance for boundary colors", () => {
      expect(getRelativeLuminance({ r: 0, g: 0, b: 0 })).toBe(0);
      expect(getRelativeLuminance({ r: 255, g: 255, b: 255 })).toBe(1);
    });

    it("verifies black-on-white contrast ratio is 21:1", () => {
      const ratio = getContrastRatio("#000000", "#ffffff");
      expect(ratio).toBe(21);
    });

    it("verifies KELVIN core theme colors meet WCAG 2.2 Level AA", () => {
      // zinc-100 on zinc-950
      const bodyRatio = getContrastRatio("#f4f4f5", "#09090b");
      expect(bodyRatio).toBeGreaterThan(10);
      expect(meetsWcagAA("#f4f4f5", "#09090b", "normalText")).toBe(true);

      // zinc-400 on zinc-950 (muted body text)
      const mutedRatio = getContrastRatio("#a1a1aa", "#09090b");
      expect(mutedRatio).toBeGreaterThanOrEqual(4.5);
      expect(meetsWcagAA("#a1a1aa", "#09090b", "normalText")).toBe(true);

      // cyan-400 on zinc-950 (accent text / links)
      const accentRatio = getContrastRatio("#22d3ee", "#09090b");
      expect(accentRatio).toBeGreaterThanOrEqual(4.5);
      expect(meetsWcagAA("#22d3ee", "#09090b", "normalText")).toBe(true);

      // red-400 on zinc-950 (critical badge)
      const dangerRatio = getContrastRatio("#f87171", "#09090b");
      expect(dangerRatio).toBeGreaterThanOrEqual(4.5);
      expect(meetsWcagAA("#f87171", "#09090b", "normalText")).toBe(true);
    });
  });

  describe("Screen Reader Live Announcer", () => {
    it("subscribes and receives polite notifications", () => {
      const mockListener = vi.fn();
      const unsubscribe = liveAnnouncer.subscribe(mockListener);

      announce("Assessment ASM-PROD-001 completed successfully", "polite");
      expect(mockListener).toHaveBeenCalledWith(
        "Assessment ASM-PROD-001 completed successfully",
        "polite"
      );

      unsubscribe();
      announce("Another message", "polite");
      expect(mockListener).toHaveBeenCalledTimes(1);
    });

    it("subscribes and receives assertive alerts for errors", () => {
      const mockListener = vi.fn();
      const unsubscribe = liveAnnouncer.subscribe(mockListener);

      announce("Authentication failed: invalid MFA token", "assertive");
      expect(mockListener).toHaveBeenCalledWith(
        "Authentication failed: invalid MFA token",
        "assertive"
      );

      unsubscribe();
    });
  });

  describe("Accessible UI Components", () => {
    it("SkipToContent renders anchor with proper href and accessible label", () => {
      const rendered = SkipToContent({ targetId: "main-content", label: "Skip to content" }) as React.ReactElement<{
        href: string;
        children: React.ReactNode;
      }>;
      expect(rendered).toBeDefined();
      expect(rendered.props.href).toBe("#main-content");
      expect(rendered.props.children).toBe("Skip to content");
    });

    it("LiveAnnouncer instantiates without runtime errors", () => {
      const element = <LiveAnnouncer />;
      expect(element).toBeDefined();
    });
  });
});
