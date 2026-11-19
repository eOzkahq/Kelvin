import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Modal, Button, Input } from "../ui";
import { LockIcon, CheckCircleIcon, ArrowRightIcon } from "../ui/Icons";
import { usePlan, type PlanId } from "../../features/billing/PlanContext";

export const PaywallModal: React.FC = () => {
  const { paywall, plans, closePaywall, redeemCoupon } = usePlan();
  const navigate = useNavigate();

  const [selectedPlanId, setSelectedPlanId] = useState<PlanId>(paywall.requestedPlan.id);
  const [billingCycle, setBillingCycle] = useState<"monthly" | "annual">("monthly");
  const [couponInput, setCouponInput] = useState("");
  const [couponFeedback, setCouponFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    if (paywall.isOpen) {
      setSelectedPlanId(paywall.requestedPlan.id === "starter" ? "pro" : paywall.requestedPlan.id);
      setCouponFeedback(null);
    }
  }, [paywall.isOpen, paywall.requestedPlan.id]);

  const paidPlans = plans.filter((p) => p.tierNumber > 1);
  const activePlan = paidPlans.find((p) => p.id === selectedPlanId) ?? paidPlans[0];

  const monthlyRate =
    billingCycle === "annual"
      ? Math.round(activePlan.priceMonthly * 0.8)
      : activePlan.priceMonthly;

  const handleApplyCoupon = () => {
    const res = redeemCoupon(couponInput, activePlan.id);
    setCouponFeedback({ ok: res.valid, text: res.message });
    if (res.valid) {
      setTimeout(() => {
        closePaywall();
      }, 450);
    }
  };

  const handleProceedToCheckout = () => {
    const query = couponInput.trim()
      ? `?plan=${activePlan.id}&cycle=${billingCycle}&coupon=${encodeURIComponent(couponInput.trim())}`
      : `?plan=${activePlan.id}&cycle=${billingCycle}`;
    closePaywall();
    navigate(`/checkout${query}`);
  };

  return (
    <Modal
      isOpen={paywall.isOpen}
      onClose={closePaywall}
      title="Upgrade Plan or Unlock with Coupon"
      description="Plan 1 (Starter) is free. Activate Pro SecOps or Enterprise via checkout or apply coupon EOZKA100."
      maxWidth="lg"
    >
      <div className="space-y-5">
        {/* Reason Callout */}
        <div className="rounded-xl border border-[var(--brand-border)] bg-[var(--brand-bg)] p-4 flex items-start gap-3">
          <div className="h-9 w-9 rounded-lg bg-zinc-900 border border-zinc-800 flex items-center justify-center shrink-0 text-[var(--brand-text)]">
            <LockIcon size={16} />
          </div>
          <p className="text-[13px] text-zinc-200 leading-relaxed">
            {paywall.reason ||
              `Accessing ${activePlan.name} (Plan ${activePlan.tierNumber}) requires an active paid tier or a valid eOzka coupon code.`}
          </p>
        </div>

        {/* Instant Coupon Unlock Box */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 p-4 space-y-2.5">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-semibold text-zinc-200">
              Have an eOzka Access Coupon?
            </span>
            <span className="text-[11px] font-mono text-[var(--brand-text)]">
              100% off all paid tiers
            </span>
          </div>
          <div className="flex gap-2">
            <Input
              type="text"
              value={couponInput}
              onChange={(e) => {
                setCouponInput(e.target.value);
                if (couponFeedback) setCouponFeedback(null);
              }}
              placeholder="Enter coupon code (e.g. eozka100)"
              aria-label="Coupon code"
            />
            <Button
              type="button"
              variant="primary"
              size="sm"
              className="shrink-0 px-4"
              onClick={handleApplyCoupon}
            >
              Unlock Free
            </Button>
          </div>
          {couponFeedback && (
            <p
              className={`text-xs font-medium ${couponFeedback.ok ? "text-emerald-400" : "text-red-400"
                }`}
            >
              {couponFeedback.text}
            </p>
          )}
        </div>

        {/* Billing Cycle Toggle */}
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-zinc-300">Select Billing Cycle</span>
          <div className="inline-flex rounded-lg border border-zinc-800 bg-zinc-950 p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setBillingCycle("monthly")}
              className={`px-3 py-1 rounded-md transition-colors cursor-pointer ${billingCycle === "monthly"
                ? "bg-zinc-850 text-zinc-100 font-semibold"
                : "text-zinc-400 hover:text-zinc-200"
                }`}
            >
              Monthly
            </button>
            <button
              type="button"
              onClick={() => setBillingCycle("annual")}
              className={`px-3 py-1 rounded-md transition-colors cursor-pointer flex items-center gap-1.5 ${billingCycle === "annual"
                ? "bg-zinc-850 text-zinc-100 font-semibold"
                : "text-zinc-400 hover:text-zinc-200"
                }`}
            >
              <span>Annual</span>
              <span className="text-[11px] font-mono text-emerald-400">-20%</span>
            </button>
          </div>
        </div>

        {/* Paid Tier Switcher */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {paidPlans.map((p) => {
            const isSelected = p.id === activePlan.id;
            const displayPrice =
              billingCycle === "annual" ? Math.round(p.priceMonthly * 0.8) : p.priceMonthly;
            return (
              <button
                key={p.id}
                type="button"
                onClick={() => setSelectedPlanId(p.id)}
                className={`text-left rounded-xl border p-4 transition-all cursor-pointer ${isSelected
                  ? "border-[var(--brand-border)] bg-[var(--brand-bg)]"
                  : "border-zinc-800 bg-zinc-900 hover:border-zinc-700"
                  }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-400">
                    Plan {p.tierNumber}
                  </span>
                  <span className="stat-num text-lg text-zinc-100">
                    ₹{displayPrice}
                    <span className="text-xs font-mono text-zinc-400 font-normal">/mo</span>
                  </span>
                </div>
                <div className="text-sm font-semibold text-zinc-100 font-display mt-1">
                  {p.name}
                </div>
                <p className="text-xs text-zinc-300 mt-1">
                  {p.limits.maxTargetsLabel} · {p.limits.maxRps} req/sec · {p.limits.retentionDays}d logs
                </p>
                <p className="text-[11px] font-mono text-[var(--brand-text)] mt-1 truncate">
                  {p.scanners.join(" · ")}
                </p>
              </button>
            );
          })}
        </div>

        {/* Selected Plan Features */}
        <div className="rounded-xl border border-zinc-800/80 bg-zinc-950/60 p-4 space-y-2.5">
          <p className="text-[11px] font-mono uppercase tracking-wider text-zinc-400">
            Included with {activePlan.name} (₹{monthlyRate}/mo{billingCycle === "annual" ? " billed annually" : ""})
          </p>
          <ul className="space-y-1.5 text-[13px] text-zinc-200">
            {activePlan.features.map((feat) => (
              <li key={feat} className="flex items-center gap-2">
                <CheckCircleIcon size={14} className="text-emerald-400 shrink-0" />
                <span>{feat}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* Redirection & Checkout Actions */}
        <div className="flex flex-col-reverse sm:flex-row items-center justify-between gap-3 pt-3 border-t border-zinc-800">
          <Button type="button" variant="ghost" size="sm" onClick={closePaywall}>
            Stay on Plan 1 (Starter)
          </Button>
          <Button
            type="button"
            variant="primary"
            rightIcon={<ArrowRightIcon size={14} />}
            onClick={handleProceedToCheckout}
          >
            Continue to Payment Checkout (₹{monthlyRate}/mo)
          </Button>
        </div>
      </div>
    </Modal>
  );
};
