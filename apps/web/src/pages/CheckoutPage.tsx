import React, { useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Card, Button, Input, BrandMark } from "../components/ui";
import { LockIcon, CheckCircleIcon, ArrowRightIcon } from "../components/ui/Icons";
import {
  usePlan,
  isFreeCouponCode,
  VALID_FREE_COUPON,
  type PlanId,
} from "../features/billing/PlanContext";
import { useAuth } from "../features/auth/AuthContext";

type PaymentMethod = "card" | "upi" | "wire";

export default function CheckoutPage() {
  const { plans, activeCoupon, redeemCoupon } = usePlan();
  const { user } = useAuth();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const paramPlan = searchParams.get("plan") as PlanId | null;
  const paramCycle = searchParams.get("cycle") === "annual" ? "annual" : "monthly";
  const paramCoupon = searchParams.get("coupon") ?? "";

  const paidPlans = plans.filter((p) => p.tierNumber > 1);
  const [selectedPlanId, setSelectedPlanId] = useState<PlanId>(
    paramPlan === "enterprise" ? "enterprise" : "pro",
  );
  const [billingCycle, setBillingCycle] = useState<"monthly" | "annual">(paramCycle);
  const [paymentMethod, setPaymentMethod] = useState<PaymentMethod>("upi");

  // Payment fields
  const [billingEmail, setBillingEmail] = useState(user?.email ?? "operator@eozka.com");
  const [companyName, setCompanyName] = useState(
    (user as (typeof user & { organization?: string }) | null)?.organization ?? "Acme Defense Corp",
  );
  const [cardNumber, setCardNumber] = useState("");
  const [cardExpiry, setCardExpiry] = useState("");
  const [cardCvc, setCardCvc] = useState("");
  const [upiId, setUpiId] = useState("");
  const [poNumber, setPoNumber] = useState("");

  const initialCoupon = isFreeCouponCode(paramCoupon)
    ? VALID_FREE_COUPON
    : activeCoupon ?? "";
  const [promoCode, setPromoCode] = useState(initialCoupon);
  const [couponApplied, setCouponApplied] = useState(isFreeCouponCode(initialCoupon));
  const [promoError, setPromoError] = useState<string | null>(null);

  const [isProcessing, setIsProcessing] = useState(false);
  const [gatewayResult, setGatewayResult] = useState<{
    txnRef: string;
    method: PaymentMethod | "coupon";
    unlocked: boolean;
    planName: string;
    tierNumber: number;
  } | null>(null);

  const activePlan = paidPlans.find((p) => p.id === selectedPlanId) ?? paidPlans[0];
  const baseMonthlyInr = activePlan.priceMonthly;
  const cycleMonthly =
  billingCycle === "annual" ? Math.round(baseMonthlyInr * 0.8) : baseMonthlyInr;
  const subtotal = billingCycle === "annual" ? cycleMonthly * 12 : cycleMonthly;
  const discount = couponApplied ? subtotal : 0;
  const totalDue = subtotal - discount;
  const fmtAmount = (n: number) => `₹${n.toLocaleString("en-IN")}`;

  const formatCardNumber = (raw: string) => {
    const digits = raw.replace(/\D/g, "").slice(0, 16);
    return digits.replace(/(.{4})/g, "$1 ").trim();
  };

  const formatExpiry = (raw: string) => {
    const digits = raw.replace(/\D/g, "").slice(0, 4);
    if (digits.length >= 3) {
      return `${digits.slice(0, 2)}/${digits.slice(2)}`;
    }
    return digits;
  };

  const handleApplyPromo = () => {
    if (isFreeCouponCode(promoCode)) {
      setCouponApplied(true);
      setPromoError(null);
      return;
    }
    setCouponApplied(false);
    setPromoError("Invalid coupon code. Enter EOZKA100 for 100% free access to all paid tiers.");
  };

  const handleSubmitPayment = (e: React.FormEvent) => {
    e.preventDefault();
    setIsProcessing(true);

    if (couponApplied) {
      const res = redeemCoupon(promoCode || VALID_FREE_COUPON, activePlan.id);
      setTimeout(() => {
        setIsProcessing(false);
        if (res.valid) {
          setGatewayResult({
            txnRef: `FREE-${VALID_FREE_COUPON}-${Date.now().toString().slice(-6)}`,
            method: "coupon",
            unlocked: true,
            planName: activePlan.name,
            tierNumber: activePlan.tierNumber,
          });
        }
      }, 300);
      return;
    }

    setTimeout(() => {
      setIsProcessing(false);
      setGatewayResult({
        txnRef: `TXN-KLV-${Date.now().toString().slice(-6)}`,
        method: paymentMethod,
        unlocked: false,
        planName: activePlan.name,
        tierNumber: activePlan.tierNumber,
      });
    }, 550);
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6 py-2">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-zinc-800/80">
        <div>
          <BrandMark variant="inline" className="mb-1.5" />
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100 font-display">
            Complete Plan Upgrade
          </h1>
        </div>
        <Link to="/plans">
          <Button variant="ghost" size="sm">
            &larr; Back to Plans
          </Button>
        </Link>
      </div>

      {gatewayResult ? (
        <Card className="p-7 max-w-2xl mx-auto space-y-5">
          <div className="flex items-start gap-4">
            <div
              className={`h-11 w-11 rounded-xl border flex items-center justify-center shrink-0 ${gatewayResult.unlocked
                ? "border-emerald-700/70 bg-emerald-950/60 text-emerald-300"
                : "border-[var(--brand-border)] bg-[var(--brand-bg)] text-[var(--brand-text)]"
                }`}
            >
              {gatewayResult.unlocked ? <CheckCircleIcon size={21} /> : <LockIcon size={20} />}
            </div>
            <div className="space-y-1.5">
              <span
                className={`text-xs font-mono uppercase tracking-wider ${gatewayResult.unlocked ? "text-emerald-400" : "text-amber-400"
                  }`}
              >
                {gatewayResult.unlocked
                  ? `Coupon ${VALID_FREE_COUPON} Redeemed · All Paid Tiers Unlocked`
                  : "Temporary Paywall Active · Preview Checkout Gate"}
              </span>
              <h2 className="text-lg font-bold text-zinc-100 font-display">
                {gatewayResult.unlocked
                  ? `Plan ${gatewayResult.tierNumber}: ${gatewayResult.planName} Activated (${gatewayResult.txnRef})`
                  : `Payment Authorization Held (${gatewayResult.txnRef})`}
              </h2>
              <p className="text-sm text-zinc-300 leading-relaxed">
                {gatewayResult.unlocked ? (
                  <>
                    <strong>{gatewayResult.planName}</strong> (and all paid Kelvin tiers) are now unlocked for free (₹0) across your workspace session.
                  </>
                ) : (
                  <>
                    No charge was captured. Enter coupon code{" "}
                    <code className="font-mono text-[var(--brand-text)] font-semibold">eozka100</code>{" "}
                    under Promo Code to unlock Plan 2 and Plan 3 immediately at {fmtAmount(0)}.
                  </>
                )}
              </p>
            </div>
          </div>

          <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-4 grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
            <div>
              <span className="text-[11px] text-zinc-500 block">SELECTED PLAN</span>
              <span className="text-zinc-100">{gatewayResult.planName}</span>
            </div>
            <div>
              <span className="text-[11px] text-zinc-500 block">CYCLE</span>
              <span className="text-zinc-100 capitalize">{billingCycle}</span>
            </div>
            <div>
              <span className="text-[11px] text-zinc-500 block">METHOD</span>
              <span className="text-zinc-100 uppercase">{gatewayResult.method}</span>
            </div>
            <div>
              <span className="text-[11px] text-zinc-500 block">ACTIVE TIER</span>
              <span className={gatewayResult.unlocked ? "text-emerald-400" : "text-amber-300"}>
                {gatewayResult.unlocked
                  ? `Plan ${gatewayResult.tierNumber} (${gatewayResult.planName})`
                  : "Plan 1 (Starter)"}
              </span>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-end gap-3 pt-2 border-t border-zinc-800">
            <Button variant="secondary" size="sm" onClick={() => setGatewayResult(null)}>
              Modify Details
            </Button>
            <Button
              variant="primary"
              size="sm"
              rightIcon={<ArrowRightIcon size={13} />}
              onClick={() => navigate(gatewayResult.unlocked ? "/plans" : "/dashboard")}
            >
              {gatewayResult.unlocked ? "View Unlocked Plans" : "Continue on Plan 1 (Starter)"}
            </Button>
          </div>
        </Card>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left: Payment & Billing Form */}
          <Card className="lg:col-span-7 p-6">
            <form onSubmit={handleSubmitPayment} className="space-y-5">
              {/* Step 1: Account & Company */}
              <div className="space-y-3">
                <h2 className="text-base font-semibold text-zinc-100 font-display">
                  Billing Information
                </h2>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <Input
                    label="Billing Email"
                    type="email"
                    value={billingEmail}
                    onChange={(e) => setBillingEmail(e.target.value)}
                    placeholder="billing@company.com"
                    required={!couponApplied}
                  />
                  <Input
                    label="Organization / Legal Name"
                    type="text"
                    value={companyName}
                    onChange={(e) => setCompanyName(e.target.value)}
                    placeholder="Acme Defense Corp"
                    required={!couponApplied}
                  />
                </div>
              </div>

              {/* Step 2: Payment Method Selector (waived when EOZKA100 applied) */}
              {couponApplied ? (
                <div className="pt-4 border-t border-zinc-800/80">
                  <div className="rounded-xl border border-emerald-700/60 bg-emerald-950/35 p-4 flex items-start gap-3">
                    <CheckCircleIcon size={18} className="text-emerald-400 shrink-0 mt-0.5" />
                    <div className="space-y-1">
                      <p className="text-sm font-semibold text-zinc-100">
                        100% Covered by Coupon {VALID_FREE_COUPON}
                      </p>
                      <p className="text-xs text-zinc-300 leading-relaxed">
                        Total due is {fmtAmount(0)}. No card, UPI mandate, or invoice is required to activate{" "}
                        <strong>{activePlan.name}</strong> and unlock all paid tiers.
                      </p>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="space-y-3 pt-4 border-t border-zinc-800/80">
                  <div className="flex items-center justify-between gap-2">
                    <h2 className="text-base font-semibold text-zinc-100 font-display">
                      Recurring Payment Method
                    </h2>
                    <span className="text-[11px] font-mono text-zinc-400">
                      Gateway: Razorpay / Paytm Subscriptions
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-2">
                    {[
                      { id: "upi" as PaymentMethod, label: "UPI AutoPay (Paytm)" },
                      { id: "card" as PaymentMethod, label: "Card (e-Mandate)" },
                      { id: "wire" as PaymentMethod, label: "PO / NetBanking" },
                    ].map((m) => (
                      <button
                        key={m.id}
                        type="button"
                        onClick={() => setPaymentMethod(m.id)}
                        className={`rounded-lg border px-2.5 py-2.5 text-xs font-medium transition-colors cursor-pointer ${paymentMethod === m.id
                            ? "border-[var(--brand-border)] bg-[var(--brand-bg)] text-[var(--brand-text)]"
                            : "border-zinc-800 bg-zinc-900 text-zinc-300 hover:border-zinc-700"
                          }`}
                      >
                        {m.label}
                      </button>
                    ))}
                  </div>

                  {paymentMethod === "card" && (
                    <div className="space-y-3 pt-2">
                      <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-xs text-zinc-300">
                        Card billing routes through a PCI-DSS Level 1 gateway (Razorpay / Paytm / Stripe) to handle RBI AFA 3DS consent and Card-on-File tokenization.
                      </div>
                      <Input
                        label="Card Number"
                        type="text"
                        inputMode="numeric"
                        value={cardNumber}
                        onChange={(e) => setCardNumber(formatCardNumber(e.target.value))}
                        placeholder="4242 4242 4242 4242"
                        required
                      />
                      <div className="grid grid-cols-2 gap-3">
                        <Input
                          label="Expiration (MM/YY)"
                          type="text"
                          inputMode="numeric"
                          value={cardExpiry}
                          onChange={(e) => setCardExpiry(formatExpiry(e.target.value))}
                          placeholder="08/29"
                          required
                        />
                        <Input
                          label="Security Code (CVC)"
                          type="password"
                          inputMode="numeric"
                          maxLength={4}
                          value={cardCvc}
                          onChange={(e) => setCardCvc(e.target.value.replace(/\D/g, ""))}
                          placeholder="•••"
                          required
                        />
                      </div>
                    </div>
                  )}

                  {paymentMethod === "upi" && (
                    <div className="space-y-2 pt-2">
                      <Input
                        label="UPI ID for Recurring AutoPay (Paytm / GPay / PhonePe)"
                        type="text"
                        value={upiId}
                        onChange={(e) => setUpiId(e.target.value)}
                        placeholder="operator@paytm or finance@okaxis"
                        required
                      />
                      <p className="text-xs text-zinc-400">
                        Recommended in India: prompts a 1-tap UPI AutoPay e-mandate on your Paytm/UPI app for monthly renewals.
                      </p>
                    </div>
                  )}

                  {paymentMethod === "wire" && (
                    <div className="space-y-2 pt-2">
                      <Input
                        label="Purchase Order (PO) / Tax Reference"
                        type="text"
                        value={poNumber}
                        onChange={(e) => setPoNumber(e.target.value)}
                        placeholder="PO-2026-SEC-884"
                        required
                      />
                      <p className="text-xs text-zinc-400">
                        Net-30 invoice with ACH / SWIFT wire instructions issued to{" "}
                        {billingEmail || "billing contact"}.
                      </p>
                    </div>
                  )}
                </div>
              )}

              <div className="pt-4 border-t border-zinc-800/80 space-y-2.5">
                <Button
                  type="submit"
                  variant="primary"
                  className="w-full justify-center"
                  isLoading={isProcessing}
                >
                  {couponApplied
                    ? `Unlock ${activePlan.name} Free (${fmtAmount(0)}) with ${VALID_FREE_COUPON}`
                    : `Authorize ${fmtAmount(totalDue)}/${billingCycle === "annual" ? "yr" : "mo"} Recurring & Activate`}
                </Button>
                <p className="text-xs text-center text-zinc-400">
                  {couponApplied
                    ? "Coupon validated: both Pro SecOps and Enterprise Perimeter unlock immediately."
                    : "Or apply coupon eozka100 on the right for 100% free paid tier access."}
                </p>
              </div>
            </form>
          </Card>

          {/* Right: Order Summary */}
          <Card variant="elevated" className="lg:col-span-5 p-6 space-y-5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-base font-semibold text-zinc-100 font-display">
                Subscription Summary
              </h2>
              <div className="flex items-center gap-1.5">
                <span className="rounded-lg border border-zinc-800 bg-zinc-950 px-2.5 py-1 text-xs font-mono text-zinc-200">
                  ₹ INR
                </span>
                <div className="inline-flex rounded-lg border border-zinc-800 bg-zinc-950 p-0.5 text-xs">
                  <button
                    type="button"
                    onClick={() => setBillingCycle("monthly")}
                    className={`px-2 py-1 rounded cursor-pointer ${billingCycle === "monthly"
                      ? "bg-zinc-850 text-zinc-100 font-medium"
                      : "text-zinc-400"
                      }`}
                  >
                    Monthly
                  </button>
                  <button
                    type="button"
                    onClick={() => setBillingCycle("annual")}
                    className={`px-2 py-1 rounded cursor-pointer ${billingCycle === "annual"
                      ? "bg-zinc-850 text-zinc-100 font-medium"
                      : "text-zinc-400"
                      }`}
                  >
                    Annual -20%
                  </button>
                </div>
              </div>
            </div>

            {/* Plan Picker */}
            <div className="space-y-2">
              {paidPlans.map((p) => {
                const selected = p.id === activePlan.id;
                const unitPrice =
                billingCycle === "annual" ? Math.round(p.priceMonthly * 0.8) : p.priceMonthly;
                return (
                  <button
                    key={p.id}
                    type="button"
                    onClick={() => setSelectedPlanId(p.id)}
                    className={`w-full flex items-center justify-between rounded-xl border p-3.5 text-left text-xs transition-colors cursor-pointer ${selected
                      ? "border-[var(--brand-border)] bg-[var(--brand-bg)] text-zinc-100"
                      : "border-zinc-800 bg-zinc-900 text-zinc-300 hover:border-zinc-700"
                      }`}
                  >
                    <div>
                      <div className="font-semibold text-sm">{p.name}</div>
                      <div className="text-xs text-zinc-400">{p.targetLimit}</div>
                    </div>
                    <span className="font-mono font-semibold text-zinc-100">
                      {couponApplied ? (
                        <span className="text-emerald-400">{fmtAmount(0)}/mo</span>
                      ) : (
                        `${fmtAmount(unitPrice)}/mo`
                      )}
                    </span>
                  </button>
                );
              })}
            </div>

            {/* Coupon Code */}
            <div className="space-y-1.5">
              <div className="flex gap-2">
                <Input
                  type="text"
                  value={promoCode}
                  onChange={(e) => {
                    setPromoCode(e.target.value);
                    if (promoError) setPromoError(null);
                  }}
                  placeholder="Coupon code (try eozka100)"
                  aria-label="Coupon code"
                />
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  className="shrink-0"
                  onClick={handleApplyPromo}
                >
                  Apply
                </Button>
              </div>
              {promoError && <p className="text-xs text-red-400">{promoError}</p>}
              {couponApplied && (
                <p className="text-xs text-emerald-400 font-medium">
                  Coupon {VALID_FREE_COUPON} applied — 100% discount across all paid tiers.
                </p>
              )}
            </div>

            {/* Breakdown */}
            <div className="space-y-2 pt-3 border-t border-zinc-800/80 text-[13px]">
              <div className="flex justify-between text-zinc-300">
                <span>
                  {activePlan.name} (Recurring {billingCycle})
                </span>
                <span className="font-mono text-zinc-100">{fmtAmount(subtotal)}</span>
              </div>
              {couponApplied && (
                <div className="flex justify-between text-emerald-400">
                  <span>Coupon Discount ({VALID_FREE_COUPON} · 100%)</span>
                  <span className="font-mono">-{fmtAmount(discount)}</span>
                </div>
              )}
              <div className="flex justify-between text-zinc-400">
                <span>Renewal Cadence</span>
                <span className="font-mono text-zinc-200">
                  Auto-renews every {billingCycle === "annual" ? "12 mos" : "30 days"}
                </span>
              </div>
              <div className="flex justify-between pt-3 border-t border-zinc-800 text-sm font-semibold text-zinc-100">
                <span>Total Due Today</span>
                <span className="stat-num text-2xl">{fmtAmount(totalDue)}</span>
              </div>
            </div>

            <ul className="space-y-1.5 text-xs text-zinc-300 pt-2 border-t border-zinc-800/70">
              {activePlan.features.map((f) => (
                <li key={f} className="flex items-center gap-2">
                  <CheckCircleIcon size={13} className="text-emerald-400 shrink-0" />
                  <span>{f}</span>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      )}
    </div>
  );
}
