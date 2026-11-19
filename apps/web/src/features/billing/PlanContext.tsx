import React, { createContext, useContext, useState, useCallback, useMemo } from "react";

export type PlanId = "starter" | "pro" | "enterprise";

export const VALID_FREE_COUPON = "EOZKA100";

export interface PlanLimits {
  maxTargets: number | null;
  maxTargetsLabel: string;
  concurrentScans: number;
  maxRps: number;
  maxTimeoutMinutes: number;
  retentionDays: number;
  workerIsolation: string;
  reportExports: string[];
  complianceFrameworks: string[];
  integrationsAndAuth: string;
  slaResponse: string;
}

export interface PlanDefinition {
  id: PlanId;
  tierNumber: number;
  name: string;
  priceMonthly: number;
  tagline: string;
  targetLimit: string;
  scanners: string[];
  features: string[];
  limits: PlanLimits;
  isUnlocked: boolean;
}

export const PLANS: PlanDefinition[] = [
  {
    id: "starter",
    tierNumber: 1,
    name: "Starter",
    priceMonthly: 0,
    tagline: "Core perimeter discovery & HTTP/TLS baseline checks for small teams",
    targetLimit: "Up to 3 verified targets",
    scanners: ["Nmap", "Nuclei"],
    features: [
      "Up to 3 verified domains (DNS TXT / HTTP Well-Known)",
      "Core port & CVE template engine (Nmap, Nuclei)",
      "Single concurrent scan up to 25 req/sec (30m cap)",
      "HTML Reader & raw JSON findings (30-day audit log)",
    ],
    limits: {
      maxTargets: 3,
      maxTargetsLabel: "3 targets max",
      concurrentScans: 1,
      maxRps: 25,
      maxTimeoutMinutes: 30,
      retentionDays: 30,
      workerIsolation: "Shared Standard Sandbox",
      reportExports: ["HTML Reader", "JSON Findings"],
      complianceFrameworks: ["Baseline HTTP & TLS"],
      integrationsAndAuth: "Email Sign-In · Manual Exports",
      slaResponse: "Community Support",
    },
    isUnlocked: true,
  },
  {
    id: "pro",
    tierNumber: 2,
    name: "Pro SecOps",
    priceMonthly: 249,
    tagline: "Active web DAST spidering, container SBOM auditing & SLA workflows",
    targetLimit: "Up to 25 verified targets",
    scanners: ["Nmap", "Nuclei", "Trivy", "OWASP ZAP"],
    features: [
      "Up to 25 verified targets across workspaces",
      "Full engine fleet: Nmap, Nuclei, Trivy SBOM & OWASP ZAP",
      "5 parallel scans up to 100 req/sec (90m scan window)",
      "SHA-256 sealed PDF reports, SARIF 2.1 & Slack/Jira SLA hooks",
    ],
    limits: {
      maxTargets: 25,
      maxTargetsLabel: "25 targets max",
      concurrentScans: 5,
      maxRps: 100,
      maxTimeoutMinutes: 90,
      retentionDays: 90,
      workerIsolation: "Dedicated Worker Pool",
      reportExports: ["SHA-256 PDF", "SARIF 2.1", "HTML", "JSON"],
      complianceFrameworks: ["OWASP ASVS v4", "CWE Top 25"],
      integrationsAndAuth: "Google SSO · Slack, Jira & PagerDuty",
      slaResponse: "4h SecOps Engineering SLA",
    },
    isUnlocked: false,
  },
  {
    id: "enterprise",
    tierNumber: 3,
    name: "Enterprise Perimeter",
    priceMonthly: 449,
    tagline: "Unlimited clusters, custom workers, SAML 2.0 SSO & compliance packs",
    targetLimit: "Unlimited targets & workspaces",
    scanners: ["Nmap", "Nuclei", "Trivy", "OWASP ZAP", "Custom Workers"],
    features: [
      "Unlimited verified targets, tenants & regional clusters",
      "All scanners + Custom Workers & multi-cluster DAST orchestration",
      "25+ concurrent scans up to 250 req/sec (180m deep window)",
      "SOC 2 / ISO 27001 / PCI compliance packs, Okta SAML & SIEM stream",
    ],
    limits: {
      maxTargets: null,
      maxTargetsLabel: "Unlimited targets",
      concurrentScans: 25,
      maxRps: 250,
      maxTimeoutMinutes: 180,
      retentionDays: 365,
      workerIsolation: "Isolated Multi-Cluster Dedicated Runners",
      reportExports: ["SHA-256 PDF", "Compliance Packs", "SARIF 2.1", "HTML", "JSON"],
      complianceFrameworks: ["SOC 2 CC6/CC7", "ISO 27001 A.12", "OWASP ASVS", "PCI-DSS"],
      integrationsAndAuth: "Okta / SAML 2.0 + OIDC · Live SIEM Webhooks",
      slaResponse: "24/7 Priority SLA (<1h)",
    },
    isUnlocked: false,
  },
];

const STORAGE_PLAN_KEY = "kelvin_active_plan";
const STORAGE_COUPON_KEY = "kelvin_active_coupon";

function readStoredPlanId(): PlanId {
  try {
    const val = sessionStorage.getItem(STORAGE_PLAN_KEY);
    if (val === "starter" || val === "pro" || val === "enterprise") return val;
  } catch {
    // ignore storage errors in restricted contexts
  }
  return "starter";
}

function readStoredCoupon(): string | null {
  try {
    const val = sessionStorage.getItem(STORAGE_COUPON_KEY);
    if (val && val.toUpperCase() === VALID_FREE_COUPON) return VALID_FREE_COUPON;
  } catch {
    // ignore storage errors in restricted contexts
  }
  return null;
}

export function isFreeCouponCode(code: string): boolean {
  return code.trim().toUpperCase() === VALID_FREE_COUPON;
}

/**
 * Returns tier catalog with unlock status resolved for the active coupon code.
 */
export function resolvePlansForCoupon(coupon: string | null): PlanDefinition[] {
  const unlocked = Boolean(coupon && isFreeCouponCode(coupon));
  return PLANS.map((plan) => ({
    ...plan,
    isUnlocked: plan.id === "starter" || unlocked,
  }));
}

export interface CouponRedeemResult {
  valid: boolean;
  message: string;
  activatedPlan?: PlanDefinition;
}

interface PaywallState {
  isOpen: boolean;
  requestedPlan: PlanDefinition;
  reason?: string;
}

interface PlanContextType {
  currentPlan: PlanDefinition;
  plans: PlanDefinition[];
  paywall: PaywallState;
  activeCoupon: string | null;
  isAllTiersUnlocked: boolean;
  selectPlan: (planId: PlanId, reason?: string) => boolean;
  redeemCoupon: (code: string, targetPlanId?: PlanId) => CouponRedeemResult;
  clearCoupon: () => void;
  openPaywall: (planId?: PlanId, reason?: string) => void;
  closePaywall: () => void;
}

const PlanContext = createContext<PlanContextType | undefined>(undefined);

export const PlanProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [activeCoupon, setActiveCoupon] = useState<string | null>(readStoredCoupon);
  const [currentPlanId, setCurrentPlanId] = useState<PlanId>(() => {
    const stored = readStoredPlanId();
    const hasCoupon = readStoredCoupon() === VALID_FREE_COUPON;
    return hasCoupon ? stored : "starter";
  });

  const isAllTiersUnlocked = activeCoupon === VALID_FREE_COUPON;

  const plans = useMemo<PlanDefinition[]>(
    () => resolvePlansForCoupon(activeCoupon),
    [activeCoupon],
  );

  const [paywall, setPaywall] = useState<PaywallState>({
    isOpen: false,
    requestedPlan: PLANS[1],
  });

  const currentPlan = useMemo(
    () => plans.find((p) => p.id === currentPlanId) ?? plans[0],
    [plans, currentPlanId],
  );

  const openPaywall = useCallback(
    (planId: PlanId = "pro", reason?: string) => {
      const targetPlan = plans.find((p) => p.id === planId && !p.isUnlocked) ?? plans[1];
      setPaywall({
        isOpen: true,
        requestedPlan: targetPlan,
        reason,
      });
    },
    [plans],
  );

  const closePaywall = useCallback(() => {
    setPaywall((prev) => ({ ...prev, isOpen: false }));
  }, []);

  const persistPlan = useCallback((planId: PlanId) => {
    setCurrentPlanId(planId);
    try {
      sessionStorage.setItem(STORAGE_PLAN_KEY, planId);
    } catch {
      // ignore storage errors
    }
  }, []);

  const selectPlan = useCallback(
    (planId: PlanId, reason?: string): boolean => {
      const target = plans.find((p) => p.id === planId);
      if (!target) return false;
      if (!target.isUnlocked) {
        openPaywall(planId, reason);
        return false;
      }
      persistPlan(planId);
      return true;
    },
    [plans, openPaywall, persistPlan],
  );

  const redeemCoupon = useCallback(
    (code: string, targetPlanId?: PlanId): CouponRedeemResult => {
      if (!isFreeCouponCode(code)) {
        return {
          valid: false,
          message: `Coupon "${code.trim() || "(empty)"}" is invalid. Enter eozka100 for 100% free access to all paid tiers.`,
        };
      }

      const nextPlanId: PlanId =
        targetPlanId === "pro" || targetPlanId === "enterprise" ? targetPlanId : "enterprise";

      setActiveCoupon(VALID_FREE_COUPON);
      persistPlan(nextPlanId);
      try {
        sessionStorage.setItem(STORAGE_COUPON_KEY, VALID_FREE_COUPON);
      } catch {
        // ignore storage errors
      }

      const activated = PLANS.find((p) => p.id === nextPlanId) ?? PLANS[2];
      return {
        valid: true,
        message: `Coupon EOZKA100 applied — Pro SecOps and Enterprise Perimeter unlocked free (₹0). Active tier: ${activated.name}.`,
        activatedPlan: { ...activated, isUnlocked: true },
      };
    },
    [persistPlan],
  );

  const clearCoupon = useCallback(() => {
    setActiveCoupon(null);
    persistPlan("starter");
    try {
      sessionStorage.removeItem(STORAGE_COUPON_KEY);
    } catch {
      // ignore storage errors
    }
  }, [persistPlan]);

  return (
    <PlanContext.Provider
      value={{
        currentPlan,
        plans,
        paywall,
        activeCoupon,
        isAllTiersUnlocked,
        selectPlan,
        redeemCoupon,
        clearCoupon,
        openPaywall,
        closePaywall,
      }}
    >
      {children}
    </PlanContext.Provider>
  );
};

export function usePlan(): PlanContextType {
  const ctx = useContext(PlanContext);
  if (!ctx) {
    throw new Error("usePlan must be used within a PlanProvider");
  }
  return ctx;
}

export function useOptionalPlan(): PlanContextType | undefined {
  return useContext(PlanContext);
}
