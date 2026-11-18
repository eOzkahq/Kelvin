import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, Button, Input } from "../components/ui";
import { CheckCircleIcon, LockIcon, ArrowRightIcon } from "../components/ui/Icons";
import { useAuth } from "../features/auth/AuthContext";
import { usePlan, type PlanId } from "../features/billing/PlanContext";

const STEPS = [
  { id: 1, title: "Workspace", desc: "Organization & region" },
  { id: 2, title: "Plan", desc: "Select tier" },
  { id: 3, title: "Verify Target", desc: "Ownership challenge" },
  { id: 4, title: "Baseline", desc: "Starter scanners" },
];

export default function OnboardingPage() {
  const { user, completeOnboarding } = useAuth();
  const { plans, currentPlan, selectPlan, redeemCoupon, isAllTiersUnlocked, openPaywall } = usePlan();
  const navigate = useNavigate();

  const [step, setStep] = useState(1);
  const [orgName, setOrgName] = useState(
    (user as (typeof user & { organization?: string }) | null)?.organization || "Northstar Cloud",
  );
  const [region, setRegion] = useState("us-east-1");
  const [teamRole, setTeamRole] = useState("Security Engineering");
  const [selectedPlanId, setSelectedPlanId] = useState<PlanId>(currentPlan.id);
  const [couponInput, setCouponInput] = useState("");
  const [couponFeedback, setCouponFeedback] = useState<{ ok: boolean; text: string } | null>(null);

  const [domain, setDomain] = useState("api.staging.northstar-sec.io");
  const [verified, setVerified] = useState(false);

  const [selectedScanners, setSelectedScanners] = useState<string[]>(["nmap", "nuclei"]);

  const handlePlanClick = (planId: PlanId) => {
    const ok = selectPlan(
      planId,
      `Paid tiers require billing activation or coupon eozka100 for free access.`,
    );
    if (ok) {
      setSelectedPlanId(planId);
    }
  };

  const handleApplyCoupon = () => {
    const res = redeemCoupon(couponInput, "pro");
    setCouponFeedback({ ok: res.valid, text: res.message });
    if (res.valid && res.activatedPlan) {
      setSelectedPlanId(res.activatedPlan.id);
    }
  };

  const toggleScanner = (id: string, isProOnly: boolean) => {
    if (isProOnly && !isAllTiersUnlocked && currentPlan.tierNumber === 1) {
      openPaywall(
        "pro",
        `The ${id.toUpperCase()} scanner engine is included on Plan 2 (Pro SecOps). Apply coupon eozka100 to unlock free or continue on Starter.`,
      );
      return;
    }
    setSelectedScanners((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id],
    );
  };

  const handleFinish = () => {
    completeOnboarding({ organization: orgName });
    navigate("/dashboard", { replace: true });
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 py-2">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-zinc-800/80">
        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-[var(--brand-text)]">
            Workspace Setup
          </span>
          <h1 className="text-xl font-bold tracking-tight text-zinc-100 font-display mt-0.5">
            Welcome, {user?.name || "Operator"}
          </h1>
          <p className="text-xs text-zinc-500 mt-0.5">
            Complete these steps to verify your first target and launch your workspace.
          </p>
        </div>
        <Button variant="ghost" size="sm" onClick={handleFinish}>
          Skip to Dashboard
        </Button>
      </div>

      {/* Connected Stepper */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {STEPS.map((s) => {
          const isCurrent = step === s.id;
          const isDone = step > s.id;
          return (
            <button
              key={s.id}
              type="button"
              onClick={() => setStep(s.id)}
              className={`text-left rounded-xl p-3 border transition-all cursor-pointer ${isCurrent
                ? "border-[var(--brand-border)] bg-[var(--brand-bg)]"
                : isDone
                  ? "border-emerald-800/60 bg-emerald-950/30"
                  : "border-zinc-800 bg-zinc-900 hover:border-zinc-700"
                }`}
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono uppercase tracking-wider text-zinc-500">
                  Step {s.id}
                </span>
                {isDone && <CheckCircleIcon size={13} className="text-emerald-400" />}
              </div>
              <p className="text-xs font-semibold text-zinc-100 mt-1">{s.title}</p>
              <p className="text-[11px] text-zinc-500">{s.desc}</p>
            </button>
          );
        })}
      </div>

      {/* Step Content */}
      <Card className="p-6">
        {step === 1 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-base font-semibold text-zinc-100 font-display">
                1. Configure Workspace Identity
              </h2>
              <p className="text-xs text-zinc-400 mt-1">
                Name your organization tenant and select your isolated worker region.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Input
                label="Organization Name"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="e.g. Acme Defense Corp"
              />
              <Input
                label="Team / Function"
                value={teamRole}
                onChange={(e) => setTeamRole(e.target.value)}
                placeholder="Security Operations"
              />
            </div>

            <div className="space-y-2">
              <label className="block text-xs font-medium text-zinc-300">
                Worker Execution Region
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {[
                  { id: "us-east-1", label: "US East (Virginia)" },
                  { id: "eu-central-1", label: "EU Central (Frankfurt)" },
                  { id: "ap-south-1", label: "AP South (Mumbai)" },
                ].map((r) => (
                  <button
                    key={r.id}
                    type="button"
                    onClick={() => setRegion(r.id)}
                    className={`rounded-xl border p-3 text-left text-xs transition-colors cursor-pointer ${region === r.id
                      ? "border-[var(--brand-border)] bg-[var(--brand-bg)] text-[var(--brand-text)] font-medium"
                      : "border-zinc-800 bg-zinc-900 text-zinc-300 hover:border-zinc-700"
                      }`}
                  >
                    <div className="font-mono text-[10px] text-zinc-500">{r.id}</div>
                    <div className="mt-0.5">{r.label}</div>
                  </button>
                ))}
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-zinc-800/80">
              <Button variant="primary" size="sm" rightIcon={<ArrowRightIcon size={13} />} onClick={() => setStep(2)}>
                Continue to Plan Selection
              </Button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-base font-semibold text-zinc-100 font-display">
                2. Select Your Workspace Plan
              </h2>
              <p className="text-xs text-zinc-400 mt-1">
                Plan 1 (Starter) is free. Apply coupon <code className="font-mono text-[var(--brand-text)]">eozka100</code> below to unlock Pro SecOps and Enterprise Perimeter for free.
              </p>
            </div>

            <div className="rounded-xl border border-zinc-800 bg-zinc-950/70 p-3.5 space-y-2">
              <div className="flex flex-col sm:flex-row gap-2">
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
                <Button type="button" variant="secondary" size="sm" className="shrink-0" onClick={handleApplyCoupon}>
                  Apply Coupon
                </Button>
              </div>
              {couponFeedback && (
                <p className={`text-xs font-medium ${couponFeedback.ok ? "text-emerald-400" : "text-red-400"}`}>
                  {couponFeedback.text}
                </p>
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {plans.map((p) => {
                const isSelected = selectedPlanId === p.id;
                const isFreeViaCoupon = p.tierNumber > 1 && p.isUnlocked && isAllTiersUnlocked;
                return (
                  <div
                    key={p.id}
                    onClick={() => handlePlanClick(p.id)}
                    className={`rounded-xl border p-4 flex flex-col justify-between transition-all cursor-pointer ${isSelected
                        ? "border-[var(--brand-border)] bg-[var(--brand-bg)]"
                        : "border-zinc-800 bg-zinc-900 hover:border-zinc-700"
                      }`}
                  >
                    <div className="space-y-2.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[11px] font-mono uppercase text-zinc-400">
                          Plan {p.tierNumber}
                        </span>
                        {p.isUnlocked ? (
                          <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/60 px-2 py-0.5 rounded-full">
                            Unlocked
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[11px] font-mono text-zinc-400 bg-zinc-850 border border-zinc-700 px-2 py-0.5 rounded-full">
                            <LockIcon size={10} />
                            Paywall
                          </span>
                        )}
                      </div>
                      <div>
                        <h3 className="text-sm font-bold text-zinc-100 font-display">{p.name}</h3>
                        <p className="stat-num text-xl text-zinc-100 mt-1">
                          {isFreeViaCoupon ? (
                            <>
                              <span className="text-emerald-400">₹0</span>{" "}
                              <span className="text-xs font-mono text-zinc-500 line-through">₹{p.priceMonthly}</span>
                            </>
                          ) : (
                            <>
                              ₹{p.priceMonthly}
                              <span className="text-xs font-mono text-zinc-400 font-normal">/mo</span>
                            </>
                          )}
                        </p>
                      </div>
                      <ul className="space-y-1.5 text-xs text-zinc-300 pt-2 border-t border-zinc-800/70">
                        {p.features.slice(0, 3).map((f) => (
                          <li key={f} className="flex items-start gap-1.5">
                            <span className="text-emerald-400">•</span>
                            <span>{f}</span>
                          </li>
                        ))}
                      </ul>
                    </div>

                    <div className="mt-4 pt-3 border-t border-zinc-800/60">
                      <span
                        className={`block w-full text-center text-xs py-1.5 rounded-lg font-medium ${isSelected
                            ? "bg-[var(--brand-btn-from)] text-[var(--brand-btn-fg)]"
                            : "bg-zinc-850 text-zinc-200 border border-zinc-700"
                          }`}
                      >
                        {isSelected ? "Selected (Active)" : p.isUnlocked ? "Select Free Plan" : "Try Selecting Plan"}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-zinc-800/80">
              <Button variant="ghost" size="sm" onClick={() => setStep(1)}>
                Back
              </Button>
              <Button variant="primary" size="sm" rightIcon={<ArrowRightIcon size={13} />} onClick={() => setStep(3)}>
                Continue with {currentPlan.name}
              </Button>
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-base font-semibold text-zinc-100 font-display">
                3. Verify Domain Ownership
              </h2>
              <p className="text-xs text-zinc-400 mt-1">
                Kelvin requires cryptographic ownership proof before allowing external scans.
              </p>
            </div>

            <Input
              label="Primary Target Domain"
              value={domain}
              onChange={(e) => {
                setDomain(e.target.value);
                setVerified(false);
              }}
              placeholder="api.yourdomain.com"
            />

            <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-4 space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between text-zinc-500">
                <span>DNS TXT Record</span>
                <span>TTL 300</span>
              </div>
              <div className="text-zinc-300 break-all">
                _kelvin-challenge.{domain || "example.com"} &rarr;{" "}
                <span className="text-[var(--brand-text)]">kelvin-verify=8f3c91a20e7b</span>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <Button
                variant={verified ? "secondary" : "outline"}
                size="sm"
                onClick={() => setVerified(true)}
              >
                {verified ? "Ownership Verified" : "Run DNS Verification Check"}
              </Button>
              {verified && (
                <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400 font-mono">
                  <CheckCircleIcon size={14} />
                  TXT record matched
                </span>
              )}
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-zinc-800/80">
              <Button variant="ghost" size="sm" onClick={() => setStep(2)}>
                Back
              </Button>
              <Button variant="primary" size="sm" rightIcon={<ArrowRightIcon size={13} />} onClick={() => setStep(4)}>
                Next: Baseline Scanners
              </Button>
            </div>
          </div>
        )}

        {step === 4 && (
          <div className="space-y-5">
            <div>
              <h2 className="text-base font-semibold text-zinc-100 font-display">
                4. Enable Baseline Scanners
              </h2>
              <p className="text-xs text-zinc-400 mt-1">
                Select scanners to include in your initial assessment profile.
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {[
                { id: "nmap", name: "Nmap", desc: "Service discovery & port baseline", proOnly: false },
                { id: "nuclei", name: "Nuclei", desc: "CVE & template vulnerability checks", proOnly: false },
                { id: "trivy", name: "Trivy", desc: "Container image & SBOM auditing", proOnly: true },
                { id: "zap", name: "OWASP ZAP", desc: "Active web DAST spidering", proOnly: true },
              ].map((sc) => {
                const active = selectedScanners.includes(sc.id);
                const locked = sc.proOnly && !isAllTiersUnlocked && currentPlan.tierNumber === 1;
                return (
                  <button
                    key={sc.id}
                    type="button"
                    onClick={() => toggleScanner(sc.id, sc.proOnly)}
                    className={`rounded-xl border p-3.5 text-left transition-colors cursor-pointer flex items-start justify-between gap-3 ${active
                      ? "border-[var(--brand-border)] bg-[var(--brand-bg)]"
                      : "border-zinc-800 bg-zinc-900 hover:border-zinc-700"
                      }`}
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-zinc-100">{sc.name}</span>
                        {locked && (
                          <span className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-mono border border-zinc-700 text-zinc-400">
                            <LockIcon size={9} />
                            Pro
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-zinc-400 mt-1">{sc.desc}</p>
                    </div>
                    <span className="text-xs font-mono text-[var(--brand-text)]">
                      {active ? "Enabled" : locked ? "Locked" : "Off"}
                    </span>
                  </button>
                );
              })}
            </div>

            <div className="flex items-center justify-between pt-3 border-t border-zinc-800/80">
              <Button variant="ghost" size="sm" onClick={() => setStep(3)}>
                Back
              </Button>
              <Button variant="primary" size="sm" onClick={handleFinish}>
                Finish Setup &amp; Open Dashboard
              </Button>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}

