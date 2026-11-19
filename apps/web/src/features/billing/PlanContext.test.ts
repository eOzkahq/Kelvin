import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { createElement } from "react";
import {
  PLANS,
  VALID_FREE_COUPON,
  isFreeCouponCode,
  resolvePlansForCoupon,
  PlanProvider,
  usePlan,
} from "./PlanContext";
import { demoFindingsProvider } from "../findings/demoProvider";

describe("PlanContext & eozka100 coupon unlocking", () => {
  it("recognizes eozka100 case-insensitively with whitespace trimming", () => {
    expect(VALID_FREE_COUPON).toBe("EOZKA100");
    expect(isFreeCouponCode("eozka100")).toBe(true);
    expect(isFreeCouponCode("EOZKA100")).toBe(true);
    expect(isFreeCouponCode("  eOzKa100 ")).toBe(true);
    expect(isFreeCouponCode("KELVIN20")).toBe(false);
    expect(isFreeCouponCode("")).toBe(false);
  });

  it("keeps Pro and Enterprise locked without a valid coupon and unlocks all paid tiers with eozka100", () => {
    const lockedPlans = resolvePlansForCoupon(null);
    expect(lockedPlans).toHaveLength(PLANS.length);
    expect(lockedPlans.find((p) => p.id === "starter")?.isUnlocked).toBe(true);
    expect(lockedPlans.find((p) => p.id === "pro")?.isUnlocked).toBe(false);
    expect(lockedPlans.find((p) => p.id === "enterprise")?.isUnlocked).toBe(false);

    const unlockedPlans = resolvePlansForCoupon("eozka100");
    expect(unlockedPlans.every((p) => p.isUnlocked)).toBe(true);
    expect(unlockedPlans.find((p) => p.id === "pro")?.isUnlocked).toBe(true);
    expect(unlockedPlans.find((p) => p.id === "enterprise")?.isUnlocked).toBe(true);
  });

    it("defines distinct INR pricing (₹249 / ₹449), numeric quotas, scanners, and export entitlements per tier", () => {
      const [starter, pro, enterprise] = PLANS;
      expect(starter.priceMonthly).toBe(0);
      expect(pro.priceMonthly).toBe(249);
      expect(enterprise.priceMonthly).toBe(449);

      expect(starter.limits.maxTargets).toBe(3);
      expect(pro.limits.maxTargets).toBe(25);
      expect(enterprise.limits.maxTargets).toBeNull();

      expect(starter.limits.maxRps).toBeLessThan(pro.limits.maxRps);
      expect(pro.limits.maxRps).toBeLessThan(enterprise.limits.maxRps);

      expect(starter.limits.retentionDays).toBe(30);
      expect(pro.limits.retentionDays).toBe(90);
      expect(enterprise.limits.retentionDays).toBe(365);

      expect(starter.scanners).not.toEqual(pro.scanners);
      expect(pro.scanners).not.toEqual(enterprise.scanners);
    });

    it("scopes visible findings cleanly across Starter, Pro, and Enterprise tiers", async () => {
      const t1 = await demoFindingsProvider.fetchFindings({ maxTier: 1, limit: 50 });
      const t2 = await demoFindingsProvider.fetchFindings({ maxTier: 2, limit: 50 });
      const t3 = await demoFindingsProvider.fetchFindings({ maxTier: 3, limit: 50 });

      expect(t1.total).toBeGreaterThan(0);
      expect(t2.total).toBeGreaterThan(t1.total);
      expect(t3.total).toBeGreaterThan(t2.total);

      expect(t1.items.every((f) => (f.requiredTier ?? 1) <= 1)).toBe(true);
      expect(t1.lockedTierCounts?.pro).toBeGreaterThan(0);
      expect(t1.lockedTierCounts?.enterprise).toBeGreaterThan(0);

      expect(t2.items.some((f) => f.scanner === "Trivy" || f.scanner === "OWASP-ZAP")).toBe(true);
      expect(t2.lockedTierCounts?.pro).toBe(0);
      expect(t2.lockedTierCounts?.enterprise).toBeGreaterThan(0);

      expect(t3.items.some((f) => f.scanner === "Custom-Workers")).toBe(true);
      expect(t3.lockedTierCounts?.enterprise).toBe(0);
    });

    it("provides PlanProvider defaults cleanly when rendered in Node", () => {
      function Probe() {
        const { currentPlan, isAllTiersUnlocked } = usePlan();
        return createElement("span", null, `${currentPlan.id}:${String(isAllTiersUnlocked)}`);
      }

      const html = renderToStaticMarkup(createElement(PlanProvider, null, createElement(Probe)));
      expect(html).toContain("starter:false");
    });
  });

