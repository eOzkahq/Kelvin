import { useState } from "react";
import { Card, Button, Input, BrandMark } from "../components/ui";
import { CheckCircleIcon, LockIcon } from "../components/ui/Icons";
import { usePlan } from "../features/billing/PlanContext";

export default function PlansBillingPage() {
  const {
    plans,
    currentPlan,
    activeCoupon,
    isAllTiersUnlocked,
    selectPlan,
    redeemCoupon,
    clearCoupon,
  } = usePlan();

  const [couponInput, setCouponInput] = useState(activeCoupon ?? "");
  const [couponNotice, setCouponNotice] = useState<{ ok: boolean; text: string } | null>(null);

  const handleApplyCoupon = (e: React.FormEvent) => {
    e.preventDefault();
    const result = redeemCoupon(
      couponInput,
      currentPlan.id === "starter" ? "enterprise" : currentPlan.id,
    );
    setCouponNotice({ ok: result.valid, text: result.message });
  };

  const comparisonRows = [
    { label: "Verified Target Quota", getVal: (p: (typeof plans)[number]) => p.limits.maxTargetsLabel },
    { label: "Concurrent Scans", getVal: (p: (typeof plans)[number]) => `${p.limits.concurrentScans} parallel` },
    { label: "Max Scan Throughput", getVal: (p: (typeof plans)[number]) => `${p.limits.maxRps} req/sec` },
    { label: "Max Execution Window", getVal: (p: (typeof plans)[number]) => `${p.limits.maxTimeoutMinutes} mins` },
    { label: "Scanner Engines", getVal: (p: (typeof plans)[number]) => p.scanners.join(", ") },
    { label: "Worker Isolation", getVal: (p: (typeof plans)[number]) => p.limits.workerIsolation },
    { label: "Report Exports", getVal: (p: (typeof plans)[number]) => p.limits.reportExports.join(", ") },
    { label: "Compliance Mapping", getVal: (p: (typeof plans)[number]) => p.limits.complianceFrameworks.join(", ") },
    { label: "Audit Log Retention", getVal: (p: (typeof plans)[number]) => `${p.limits.retentionDays} days` },
    { label: "SSO & Alert Integrations", getVal: (p: (typeof plans)[number]) => p.limits.integrationsAndAuth },
    { label: "Engineering SLA", getVal: (p: (typeof plans)[number]) => p.limits.slaResponse },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-zinc-800/80">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100 font-display">
            Plans &amp; Billing
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            Active plan:{" "}
            <strong className="text-zinc-100">
              Plan {currentPlan.tierNumber} · {currentPlan.name}
            </strong>
            {" — "}
            {currentPlan.limits.maxTargetsLabel}, {currentPlan.limits.maxRps} req/sec cap,{" "}
            {currentPlan.scanners.length} scanner engines active.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2.5">
          {activeCoupon && (
            <span className="inline-flex items-center gap-1.5 rounded-lg border border-emerald-700/60 bg-emerald-950/50 px-3 py-1.5 text-xs font-mono font-semibold text-emerald-300">
              <CheckCircleIcon size={13} />
              COUPON {activeCoupon} (100% OFF)
            </span>
          )}
          <span className="inline-flex items-center gap-2 rounded-lg border border-[var(--brand-border)] bg-[var(--brand-bg)] px-3.5 py-1.5 text-xs font-mono text-[var(--brand-text)]">
            <span>Active Tier:</span>
            <strong>
              Plan {currentPlan.tierNumber} ({currentPlan.name})
            </strong>
          </span>
        </div>
      </div>

      {/* eOzka Coupon Redemption Card */}
      <Card variant="elevated" className="p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <BrandMark variant="inline" />
            <h2 className="text-base font-semibold text-zinc-100 font-display">
              Redeem Access Coupon for Free Paid Tiers
            </h2>
            <p className="text-xs text-zinc-400">
              Apply coupon{" "}
              <code className="font-mono text-[var(--brand-text)] font-semibold">eozka100</code>{" "}
              to waive 100% of fees across Pro SecOps (₹249/mo) and Enterprise Perimeter (₹449/mo). Switching tiers updates live quotas, scanners, and report entitlements across the platform.
            </p>
          </div>

          <form
            onSubmit={handleApplyCoupon}
            className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5 lg:min-w-[400px]"
          >
            <Input
              type="text"
              value={couponInput}
              onChange={(e) => {
                setCouponInput(e.target.value);
                if (couponNotice) setCouponNotice(null);
              }}
              placeholder="Enter coupon code (eozka100)"
              aria-label="Coupon code"
              className="min-w-[200px]"
            />
              <Button type="submit" variant="primary" size="md" className="shrink-0 whitespace-nowrap">
                Apply Coupon
              </Button>
              {isAllTiersUnlocked && (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="shrink-0"
                  onClick={() => {
                    clearCoupon();
                    setCouponInput("");
                    setCouponNotice({
                      ok: true,
                      text: "Coupon removed. Returned to Plan 1 (Starter).",
                    });
                  }}
                >
                  Reset
                </Button>
              )}
          </form>
        </div>

        {
          couponNotice && (
            <p
              className={`mt-3 text-xs font-medium ${couponNotice.ok ? "text-emerald-400" : "text-red-400"
                }`}
            >
              {couponNotice.text}
            </p>
          )
        }
      </Card >

      {/* Pricing Cards with Differentiated Numeric Quotas */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {plans.map((plan) => {
          const isCurrent = plan.id === currentPlan.id;
          const isFreeViaCoupon = plan.tierNumber > 1 && plan.isUnlocked && isAllTiersUnlocked;

          return (
            <Card
              key={plan.id}
              variant={isCurrent ? "accent" : "default"}
              className="flex flex-col justify-between p-6"
            >
              <div className="space-y-4">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-400">
                      Plan {plan.tierNumber}
                    </span>
                    <h2 className="text-lg font-bold text-zinc-100 font-display mt-0.5">
                      {plan.name}
                    </h2>
                  </div>
                  {isCurrent ? (
                    <span className="inline-flex items-center gap-1 rounded-full border border-emerald-700/70 bg-emerald-950/60 px-2.5 py-0.5 text-[11px] font-mono text-emerald-300">
                      <CheckCircleIcon size={12} />
                      Active
                    </span>
                  ) : plan.isUnlocked ? (
                    <span className="inline-flex items-center gap-1 rounded-full border border-[var(--brand-border)] bg-[var(--brand-bg)] px-2.5 py-0.5 text-[11px] font-mono text-[var(--brand-text)]">
                      <CheckCircleIcon size={12} />
                      Unlocked
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 rounded-full border border-zinc-700 bg-zinc-850 px-2.5 py-0.5 text-[11px] font-mono text-zinc-400">
                      <LockIcon size={11} />
                      Locked
                    </span>
                  )}
                </div>

                  <div className="flex items-baseline gap-2 flex-wrap">
                    {isFreeViaCoupon ? (
                      <>
                        <span className="stat-num text-3xl text-emerald-400">₹0</span>
                        <span className="text-sm font-mono text-zinc-500 line-through">
                          ₹{plan.priceMonthly}
                        </span>
                        <span className="text-xs text-emerald-400 font-mono font-medium">
                          / month · Free via EOZKA100
                        </span>
                      </>
                    ) : (
                      <>
                        <span className="stat-num text-3xl text-zinc-100">₹{plan.priceMonthly}</span>
                        <span className="text-xs text-zinc-400 font-mono">/ month</span>
                      </>
                    )}
                  </div>

                  <p className="text-[13px] text-zinc-400 leading-relaxed">{plan.tagline}</p>

                  {/* Concrete Numeric Quota Grid */}
                  <div className="grid grid-cols-2 gap-2 rounded-xl border border-zinc-800/80 bg-zinc-950/60 p-3 text-xs">
                    <div>
                      <span className="text-[10px] font-mono uppercase text-zinc-500 block">
                        Target Quota
                      </span>
                      <span className="font-semibold text-zinc-100">{plan.limits.maxTargetsLabel}</span>
                    </div>
                    <div>
                      <span className="text-[10px] font-mono uppercase text-zinc-500 block">
                        Max Speed
                      </span>
                      <span className="font-semibold text-zinc-100">
                        {plan.limits.maxRps} req/sec
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] font-mono uppercase text-zinc-500 block">
                        Concurrency
                      </span>
                      <span className="font-semibold text-zinc-100">
                        {plan.limits.concurrentScans} parallel
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] font-mono uppercase text-zinc-500 block">
                        Audit History
                      </span>
                      <span className="font-semibold text-zinc-100">
                        {plan.limits.retentionDays} days
                      </span>
                    </div>
                  </div>

                  <div className="border-t border-zinc-800/80 pt-4 space-y-2.5">
                    <p className="text-xs font-mono text-zinc-400 uppercase tracking-wider">
                      Included Capabilities
                    </p>
                    <ul className="space-y-2 text-[13px] text-zinc-200">
                      {plan.features.map((feat) => (
                        <li key={feat} className="flex items-start gap-2">
                          <CheckCircleIcon
                            size={15}
                            className={`mt-0.5 shrink-0 ${isCurrent || plan.isUnlocked ? "text-emerald-400" : "text-zinc-500"
                              }`}
                          />
                          <span>{feat}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div className="pt-6 mt-6 border-t border-zinc-800/80">
                  {isCurrent ? (
                    <Button variant="secondary" className="w-full justify-center" disabled>
                      Current Active Plan
                    </Button>
                  ) : plan.isUnlocked ? (
                    <Button
                      variant="primary"
                      className="w-full justify-center"
                      onClick={() => selectPlan(plan.id)}
                    >
                      Switch to {plan.name}
                    </Button>
                  ) : (
                    <Button
                      variant="outline"
                      className="w-full justify-center"
                      leftIcon={<LockIcon size={13} />}
                      onClick={() =>
                        selectPlan(
                          plan.id,
                          `Activate ${plan.name} (Plan ${plan.tierNumber}) via checkout or unlock all paid tiers free with coupon eozka100.`,
                        )
                      }
                    >
                      Upgrade to {plan.name}
                    </Button>
                  )}
                </div>
            </Card >
          );
        })
        }
      </div >

      {/* Full Side-by-Side Specification Comparison Matrix */}
      < Card className="p-6" >
        <div className="pb-4 border-b border-zinc-800/80 mb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-lg font-bold text-zinc-100 font-display">
              Tier Specification &amp; Capability Matrix
            </h2>
            <p className="text-xs text-zinc-400 mt-0.5">
              Exact scanner fleet, throughput, retention, and enterprise security controls per tier.
            </p>
          </div>
          <span className="text-xs font-mono text-[var(--brand-text)]">
            Active: Plan {currentPlan.tierNumber} · {currentPlan.name}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-zinc-800 text-[11px] font-mono uppercase tracking-wider text-zinc-400">
                <th className="py-3 pr-4">Capability</th>
                {plans.map((p) => (
                  <th
                    key={p.id}
                    className={`py-3 px-4 ${p.id === currentPlan.id ? "text-[var(--brand-text)] font-semibold" : ""
                      }`}
                  >
                    Plan {p.tierNumber}: {p.name}
                    {p.id === currentPlan.id ? " (Active)" : ""}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/70">
              {comparisonRows.map((row) => (
                <tr key={row.label} className="hover:bg-zinc-900/50 transition-colors">
                  <td className="py-3 pr-4 font-semibold text-zinc-200 whitespace-nowrap">
                    {row.label}
                  </td>
                  {plans.map((p) => {
                    const activeCol = p.id === currentPlan.id;
                    return (
                      <td
                        key={p.id}
                        className={`py-3 px-4 ${activeCol ? "text-zinc-100 font-medium bg-[var(--brand-bg)]/40" : "text-zinc-400"
                          }`}
                      >
                        {row.getVal(p)}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card >
    </div >
  );
}
