import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  fetchTargets,
  fetchProfiles,
  createAssessment,
  type TargetOption,
  type ScanProfile,
} from "../features/assessments";
import { demoAssessmentProvider } from "../features/assessments/demoProvider";
import { ensureReportForAssessment } from "../features/reports/reportsApi";
import { runLiveWebsiteProbe, saveLiveScanResult } from "../features/reports/liveScanStore";
import { isDemoMode } from "../config/env";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  Button,
  Input,
  Modal,
  SkeletonLoader,
} from "../components/ui";
import { AlertTriangleIcon, CheckCircleIcon, LockIcon, RadarIcon, ShieldIcon } from "../components/ui/Icons";
import { useOptionalPlan, PLANS } from "../features/billing/PlanContext";

const STEPS = [
  "1. Target",
  "2. Profile",
  "3. Scanners",
  "4. Options",
  "5. Authorization",
  "6. Summary",
  "7. Launch",
];

export default function AssessmentWizardPage() {
  const navigate = useNavigate();
  const planCtx = useOptionalPlan();
  const activePlan = planCtx?.currentPlan ?? PLANS[0];
  const openPaywall = planCtx?.openPaywall;

  const [currentStep, setCurrentStep] = useState(1);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Form State
  const [assessmentName, setAssessmentName] = useState("");
  const [targetInputMode, setTargetInputMode] = useState<"custom" | "verified">("custom");
  const [customWebsiteUrl, setCustomWebsiteUrl] = useState("");
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [selectedProfileId, setSelectedProfileId] = useState("prof-web-baseline");
  const [rateLimit, setRateLimit] = useState(Math.min(50, activePlan.limits.maxRps));
  const [timeoutMinutes, setTimeoutMinutes] = useState(Math.min(30, activePlan.limits.maxTimeoutMinutes));
  const [scopeConfirmed, setScopeConfirmed] = useState(false);
  const [idempotencyKey] = useState(() => `idem-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`);
  const [completedInfo, setCompletedInfo] = useState<{
    assessmentId: string;
    reportId: string;
    targetHost: string;
    findingsCount: number;
    countdown: number;
  } | null>(null);

  useEffect(() => {
    if (!completedInfo) return;
    if (completedInfo.countdown <= 0) {
      navigate(
        `/reports?open=${encodeURIComponent(completedInfo.reportId)}&fromAssessment=${encodeURIComponent(completedInfo.assessmentId)}`,
        { replace: true },
      );
      return;
    }
    const timer = setTimeout(() => {
      setCompletedInfo((prev) => (prev ? { ...prev, countdown: prev.countdown - 1 } : null));
    }, 1000);
    return () => clearTimeout(timer);
  }, [completedInfo, navigate]);

  const { data: targets, isLoading: targetsLoading } = useQuery({
    queryKey: ["targets"],
    queryFn: fetchTargets,
  });

  const { data: profiles, isLoading: profilesLoading } = useQuery({
    queryKey: ["profiles"],
    queryFn: fetchProfiles,
  });

  const selectedTarget: TargetOption | undefined = targets?.find((t) => t.id === selectedTargetId);
  const effectiveTargetHost =
    targetInputMode === "custom" ? customWebsiteUrl.trim() : selectedTarget?.address ?? "";
  const selectedProfile: ScanProfile | undefined = profiles?.find((p) => p.id === selectedProfileId);

  const canAdvance = () => {
    switch (currentStep) {
      case 1:
        return Boolean(effectiveTargetHost && assessmentName.trim());
      case 2:
        return Boolean(selectedProfileId);
      case 3:
        return true;
      case 4:
        return rateLimit > 0 && timeoutMinutes > 0;
      case 5:
        return scopeConfirmed;
      case 6:
        return true;
      case 7:
        return true;
      default:
        return false;
    }
  };

  const handleNext = () => {
    if (canAdvance() && currentStep < 7) {
      setCurrentStep(currentStep + 1);
    }
  };

  const handleBack = () => {
    if (currentStep > 1) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleDispatch = async () => {
    if (isSubmitting) return;
    setIsSubmitting(true);
    setErrorMessage(null);

    try {
      const targetId = targetInputMode === "custom" ? `custom-${Date.now().toString(36)}` : selectedTargetId;
      const res = await createAssessment({
        name: assessmentName,
        targetId,
        targets: [{ host: effectiveTargetHost }],
        profileId: selectedProfileId,
        rateLimit,
        timeoutMinutes,
        authorizedScopeConfirmed: scopeConfirmed,
        idempotencyKey,
      });

      if (isDemoMode() && effectiveTargetHost) {
        let findingsCount = 0;
        try {
          const probe = await runLiveWebsiteProbe(
            effectiveTargetHost,
            (activePlan.tierNumber as 1 | 2 | 3) || 1,
          );
          saveLiveScanResult(res.id, probe);
          demoAssessmentProvider.attachLiveProbe(res.id, probe);
          findingsCount = probe.findings.length;
        } catch {
          // Live probe unreachable or non-dev environment — still auto-create assessment report
        }

        const report = await ensureReportForAssessment(res.id, effectiveTargetHost, assessmentName);
        setIsSubmitting(false);
        setCompletedInfo({
          assessmentId: res.id,
          reportId: report.id,
          targetHost: effectiveTargetHost,
          findingsCount,
          countdown: 3,
        });
        return;
      }

      navigate(`/assessments/${res.id || "asmt-new"}`);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to dispatch assessment");
      setIsSubmitting(false);
    }
  };

  if (targetsLoading || profilesLoading) {
    return (
      <div className="max-w-4xl mx-auto space-y-4">
        <SkeletonLoader lines={2} className="w-48" />
        <SkeletonLoader lines={8} className="h-96" />
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Wizard Header */}
      <div className="flex items-end justify-between pb-4 border-b border-zinc-800/80">
        <div>
          <span className="text-[10px] font-mono uppercase tracking-[0.16em] text-[#d4c9a8]">
            Pre-Flight Configuration
          </span>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100 font-display mt-1">
            Assessment Creation Wizard
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5 font-mono">
            Step {currentStep} of 7 • {STEPS[currentStep - 1]}
          </p>
        </div>

        <Link to="/assessments">
          <Button variant="ghost" size="sm">
            Cancel
          </Button>
        </Link>
      </div>

      {/* Connected Stepper Bar */}
      <div className="grid grid-cols-7 gap-1.5">
        {STEPS.map((step, idx) => {
          const stepNumber = idx + 1;
          const isActive = stepNumber === currentStep;
          const isDone = stepNumber < currentStep;

          return (
            <div
              key={step}
              className={`flex flex-col gap-1.5 p-2 rounded-lg border text-center transition-all ${isActive
                ? "bg-[#d4c9a8]/12 border-[#d4c9a8]/50 text-[#f0eeea] shadow-[0_0_16px_rgba(212,201,168,0.1)]"
                : isDone
                  ? "bg-emerald-950/30 border-emerald-800/50 text-emerald-300"
                  : "bg-zinc-900/50 border-zinc-800/70 text-zinc-500"
                }`}
            >
              <div className="flex items-center justify-center gap-1 text-[10px] font-mono font-semibold">
                <span>{isDone ? "✓" : `0${stepNumber}`}</span>
              </div>
              <span className="hidden sm:block text-[10px] font-medium truncate">
                {step.split(". ")[1]}
              </span>
            </div>
          );
        })}
      </div>

      {errorMessage && (
        <div className="rounded-lg border border-red-800 bg-red-950/50 p-3 text-xs text-red-300">
          {errorMessage}
        </div>
      )}

      {/* Step Contents */}
      <Card variant="elevated" className="p-6">
        {/* Step 1: Target Selection */}
        {currentStep === 1 && (
          <div className="space-y-5">
            <CardHeader>
              <div>
                <CardTitle>Select Assessment Target</CardTitle>
                <CardDescription>
                  Choose a verified host or enterprise API boundary within approved scope.
                </CardDescription>
              </div>
            </CardHeader>

            <Input
              label="Assessment Run Name"
              placeholder="e.g., Q4 Perimeter Security Scan"
              value={assessmentName}
              onChange={(e) => setAssessmentName(e.target.value)}
              required
            />

            {/* Target Mode Switcher */}
            <div className="space-y-3 pt-1">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="inline-flex rounded-lg border border-zinc-800 bg-zinc-950 p-0.5 text-xs">
                  <button
                    type="button"
                    onClick={() => setTargetInputMode("custom")}
                    className={`px-3 py-1.5 rounded-md transition-colors cursor-pointer ${targetInputMode === "custom"
                      ? "bg-[var(--brand-bg)] text-[var(--brand-text)] font-medium"
                      : "text-zinc-400 hover:text-zinc-200"
                      }`}
                  >
                    Enter Website URL Directly
                  </button>
                  <button
                    type="button"
                    onClick={() => setTargetInputMode("verified")}
                    className={`px-3 py-1.5 rounded-md transition-colors cursor-pointer ${targetInputMode === "verified"
                      ? "bg-[var(--brand-bg)] text-[var(--brand-text)] font-medium"
                      : "text-zinc-400 hover:text-zinc-200"
                      }`}
                  >
                    Select Verified Target ({targets?.length ?? 0})
                  </button>
                </div>

                <Link
                  to="/targets"
                  className="text-[11px] font-mono text-[var(--brand-text)] hover:underline"
                >
                  Manage Verified Targets &rarr;
                </Link>
              </div>

              {targetInputMode === "custom" ? (
                <div className="space-y-2 rounded-xl border border-zinc-800/90 bg-zinc-950/60 p-4">
                  <Input
                    label="Target Website URL or Domain"
                    placeholder="https://example.com or api.yourdomain.com"
                    value={customWebsiteUrl}
                    onChange={(e) => setCustomWebsiteUrl(e.target.value)}
                    helperText="Runs a live DNS, TLS certificate, and HTTP security headers probe directly from the local workspace."
                    required
                  />
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="grid grid-cols-1 gap-2.5">
                    {targets?.map((tgt) => {
                      const selected = selectedTargetId === tgt.id;
                      return (
                        <button
                          key={tgt.id}
                          type="button"
                          onClick={() => setSelectedTargetId(tgt.id)}
                          className={`flex items-center justify-between p-3.5 rounded-xl border text-left transition-all cursor-pointer ${selected
                            ? "border-[var(--brand-border)] bg-[var(--brand-bg)] text-zinc-100"
                            : "border-zinc-800/90 bg-zinc-950/50 hover:border-zinc-700 text-zinc-300"
                            }`}
                        >
                          <div className="flex items-center gap-3">
                            <span
                              className={`h-4 w-4 rounded-full border flex items-center justify-center ${selected ? "border-[var(--brand)]" : "border-zinc-600"
                                }`}
                            >
                              {selected && <span className="h-2 w-2 rounded-full bg-[var(--brand)]" />}
                            </span>
                            <div>
                              <p className="font-semibold text-xs text-zinc-100">{tgt.name}</p>
                              <p className="font-mono text-[11px] text-zinc-400">{tgt.address}</p>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-zinc-900 text-zinc-400 border border-zinc-800">
                              {tgt.environment}
                            </span>
                            {selected && <span className="text-[var(--brand-text)] font-bold text-xs">✓</span>}
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          </div>
        )
        }

        {/* Step 2: Profile Selection */}
        {
          currentStep === 2 && (
            <div className="space-y-5">
              <CardHeader>
                <div>
                  <CardTitle>Select Scan Profile</CardTitle>
                  <CardDescription>
                    Define the audit depth, testing scope, and vulnerability signature baseline.
                  </CardDescription>
                </div>
              </CardHeader>

              <div className="space-y-3">
                {profiles?.map((prof) => {
                  const selected = selectedProfileId === prof.id;
                  const requiredTier = prof.id === "prof-web-baseline" ? 1 : prof.id === "prof-api-security" ? 2 : 3;
                  const tierLocked = activePlan.tierNumber < requiredTier;
                  const tierLabel =
                    requiredTier === 1
                      ? "Plan 1+"
                      : requiredTier === 2
                        ? "Plan 2+ · Pro"
                        : "Plan 3 · Enterprise";

                  return (
                    <button
                      key={prof.id}
                      type="button"
                      onClick={() => {
                        if (tierLocked && openPaywall) {
                          openPaywall(
                            requiredTier === 3 ? "enterprise" : "pro",
                            `${prof.name} requires ${requiredTier === 3 ? "Enterprise Perimeter" : "Pro SecOps"}. Apply coupon eozka100 to unlock free.`,
                          );
                          return;
                        }
                        setSelectedProfileId(prof.id);
                      }}
                      className={`w-full flex flex-col p-4 rounded-xl border text-left transition-all cursor-pointer ${selected
                          ? "border-[var(--brand-border)] bg-[var(--brand-bg)] text-zinc-100"
                          : tierLocked
                            ? "border-zinc-800/70 bg-zinc-950/35 text-zinc-400 hover:border-zinc-700"
                            : "border-zinc-800/90 bg-zinc-950/50 hover:border-zinc-700 text-zinc-200"
                        }`}
                    >
                        <div className="flex items-center justify-between w-full gap-2">
                          <span className="font-semibold text-sm text-zinc-100 font-display">{prof.name}</span>
                          <div className="flex items-center gap-2">
                            <span
                              className={`inline-flex items-center gap-1 text-[10px] uppercase font-mono px-2 py-0.5 rounded-full border ${tierLocked
                                  ? "bg-zinc-900 text-zinc-400 border-zinc-700"
                                  : "bg-[var(--brand-bg)] text-[var(--brand-text)] border-[var(--brand-border)]"
                                }`}
                            >
                              {tierLocked && <LockIcon size={10} />}
                              {tierLabel}
                            </span>
                            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded-full bg-zinc-900 text-zinc-200 border border-zinc-700">
                              Risk: {prof.riskLevel}
                            </span>
                          </div>
                        </div>
                        <p className="text-xs text-zinc-400 mt-1.5 leading-relaxed">{prof.description}</p>
                        <div className="flex flex-wrap items-center gap-1.5 mt-3">
                          {prof.scanners.map((s) => (
                            <span
                              key={s}
                              className="text-[11px] font-mono px-2 py-0.5 rounded bg-zinc-900 text-[var(--brand-text)] border border-zinc-800"
                            >
                              {s}
                            </span>
                          ))}
                        </div>
                    </button>
                  );
                })}
              </div>
            </div>
          )
        }

        {/* Step 3: Scanner Inspection */}
        {
          currentStep === 3 && (
            <div className="space-y-4">
              <CardHeader>
                <div>
                  <CardTitle>Review Enabled Scanner Engines</CardTitle>
                  <CardDescription>
                    Allocated isolation tier: <strong className="text-zinc-200">{activePlan.limits.workerIsolation}</strong> (Plan {activePlan.tierNumber}: {activePlan.name}).
                  </CardDescription>
                </div>
              </CardHeader>

              <div className="space-y-3 text-xs">
                    {selectedProfile?.scanners.map((scanner) => {
                      const needsPro = scanner === "Trivy" || scanner === "ZAP";
                      const locked = needsPro && activePlan.tierNumber < 2;
                      return (
                        <div
                          key={scanner}
                          className="flex items-center justify-between p-4 rounded-xl border border-zinc-800/90 bg-zinc-950/60"
                        >
                          <div className="flex items-center gap-3">
                            <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-[var(--brand-border)] bg-[var(--brand-bg)] text-[var(--brand-text)]">
                              <RadarIcon size={15} />
                            </span>
                            <div>
                              <span className="font-semibold text-zinc-100 block">{scanner} Engine</span>
                              <span className="text-[11px] font-mono text-zinc-400">
                                {activePlan.limits.workerIsolation} · Egress boundary enforced
                              </span>
                            </div>
                          </div>
                          <span
                            className={`px-2.5 py-0.5 rounded-full text-[10px] font-mono uppercase border ${locked
                                ? "bg-zinc-900 text-zinc-400 border-zinc-700"
                                : "bg-emerald-950/60 text-emerald-300 border-emerald-800/70"
                              }`}
                          >
                            {locked ? "Pro Plan" : "Ready"}
                          </span>
                        </div>
                      );
                    })}

                    {activePlan.tierNumber >= 3 && (
                      <div className="flex items-center justify-between p-4 rounded-xl border border-[var(--brand-border)] bg-[var(--brand-bg)]">
                        <div className="flex items-center gap-3">
                            <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-[var(--brand-border)] bg-zinc-900 text-[var(--brand-text)]">
                              <ShieldIcon size={15} />
                            </span>
                            <div>
                                <span className="font-semibold text-zinc-100 block">
                                  Custom Workers &amp; Multi-Cluster Runner Fleet
                                </span>
                                <span className="text-[11px] font-mono text-zinc-300">
                                  Enterprise Perimeter active · {activePlan.limits.concurrentScans} parallel scan slots
                                </span>
                            </div>
                        </div>
                        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono uppercase bg-emerald-950/60 text-emerald-300 border border-emerald-800/70">
                          Enterprise Active
                        </span>
                      </div>
                )}
                  </div>
            </div>
              )
        }

              {/* Step 4: Permitted Options */}
              {
                currentStep === 4 && (
                  <div className="space-y-4">
                    <CardHeader>
                      <div>
                        <CardTitle>Execution Options &amp; Guardrails</CardTitle>
                        <CardDescription>
                          Tier limits for Plan {activePlan.tierNumber} ({activePlan.name}): up to {activePlan.limits.maxRps} req/sec and {activePlan.limits.maxTimeoutMinutes} mins.
                        </CardDescription>
                      </div>
                    </CardHeader>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <Input
                        label={`Maximum Rate Limit (req/sec · Max ${activePlan.limits.maxRps})`}
                        type="number"
                        min={1}
                        max={activePlan.limits.maxRps}
                        value={Math.min(rateLimit, activePlan.limits.maxRps)}
                        onChange={(e) => setRateLimit(Math.min(Number(e.target.value), activePlan.limits.maxRps))}
                        helperText={`Capped at ${activePlan.limits.maxRps} req/sec under ${activePlan.name}.`}
                        required
                      />

                      <Input
                        label={`Timeout Deadline (Minutes · Max ${activePlan.limits.maxTimeoutMinutes})`}
                        type="number"
                        min={5}
                        max={activePlan.limits.maxTimeoutMinutes}
                        value={Math.min(timeoutMinutes, activePlan.limits.maxTimeoutMinutes)}
                        onChange={(e) =>
                          setTimeoutMinutes(Math.min(Number(e.target.value), activePlan.limits.maxTimeoutMinutes))
                        }
                        helperText={`Maximum execution window: ${activePlan.limits.maxTimeoutMinutes} mins.`}
                        required
                      />
                    </div>
                  </div>
                )
              }

              {/* Step 5: Scope & Authorization */}
              {
                currentStep === 5 && (
                  <div className="space-y-4">
                    <CardHeader>
                      <div>
                        <CardTitle>Scope &amp; Legal Authorization Confirmation</CardTitle>
                        <CardDescription>
                          Strict adherence to rules of engagement is required before dispatching scans.
                        </CardDescription>
                      </div>
                    </CardHeader>

                    <div className="rounded-xl border border-amber-800/60 bg-amber-950/25 p-4 text-xs text-amber-200 space-y-2 flex items-start gap-3">
                      <AlertTriangleIcon size={18} className="text-amber-400 mt-0.5" />
                      <div className="space-y-1">
                        <p className="font-semibold">Legal Authorization Required</p>
                        <p className="text-amber-200/80 leading-relaxed">
                          Scanning target <span className="font-mono text-zinc-100 underline decoration-[var(--brand-border)]">{effectiveTargetHost}</span> must be explicitly authorized by your organization or customer engagement terms.
                        </p>
                      </div>
                    </div>

                    <label className="flex items-start gap-3 p-4 rounded-xl border border-zinc-800 bg-zinc-950/60 cursor-pointer hover:border-[#d4c9a8]/40 transition-colors">
                      <input
                        type="checkbox"
                        checked={scopeConfirmed}
                        onChange={(e) => setScopeConfirmed(e.target.checked)}
                        className="mt-0.5 h-4 w-4 rounded border-zinc-700 bg-zinc-800"
                      />
                      <span className="text-xs text-zinc-300 leading-relaxed">
                        I formally confirm that I possess verified authorization to execute security assessment tools against this target.
                      </span>
                    </label>
                  </div>
                )
              }

              {/* Step 6: Summary Review */}
              {
                currentStep === 6 && (
                  <div className="space-y-4">
                    <CardHeader>
                      <div>
                        <CardTitle>Pre-Flight Assessment Manifest</CardTitle>
                        <CardDescription>
                          Verify execution configuration before submitting to the worker cluster.
                        </CardDescription>
                      </div>
                    </CardHeader>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 text-xs">
                      <div className="p-3.5 rounded-xl border border-zinc-800 bg-zinc-950/60">
                        <span className="text-[10px] font-mono uppercase text-zinc-500 block">Assessment Name</span>
                        <span className="font-semibold text-zinc-100 mt-1 block">{assessmentName}</span>
                      </div>
                      <div className="p-3.5 rounded-xl border border-zinc-800 bg-zinc-950/60">
                        <span className="text-[10px] font-mono uppercase text-zinc-500 block">Target Asset</span>
                        <span className="font-mono text-[var(--brand-text)] mt-1 block">{effectiveTargetHost}</span>
                      </div>
                      <div className="p-3.5 rounded-xl border border-zinc-800 bg-zinc-950/60">
                        <span className="text-[10px] font-mono uppercase text-zinc-500 block">Profile Selected</span>
                        <span className="font-medium text-zinc-100 mt-1 block">{selectedProfile?.name}</span>
                      </div>
                      <div className="p-3.5 rounded-xl border border-zinc-800 bg-zinc-950/60">
                        <span className="text-[10px] font-mono uppercase text-zinc-500 block">Rate &amp; Timeout</span>
                        <span className="font-mono text-zinc-200 mt-1 block">{rateLimit} req/s • {timeoutMinutes} min</span>
                      </div>
                    </div>

                    <div className="rounded-xl border border-zinc-800/80 bg-zinc-950/80 p-3 flex items-center justify-between text-[11px] font-mono text-zinc-400">
                      <span>Idempotency Dispatch Key</span>
                      <code className="text-[#d4c9a8]">{idempotencyKey}</code>
                    </div>
                  </div>
                )
              }

              {/* Step 7: Launch Confirmation */}
              {
                currentStep === 7 && (
                  <div className="space-y-5 text-center py-8">
                    <div className="inline-flex h-16 w-16 items-center justify-center rounded-2xl bg-[#d4c9a8]/12 border border-[#d4c9a8]/45 text-[#d4c9a8] shadow-[0_0_30px_rgba(212,201,168,0.16)]">
                      <ShieldIcon size={28} />
                    </div>
                    <div className="space-y-1.5">
                      <h3 className="text-lg font-semibold text-zinc-100 font-display">
                        Ready to Dispatch Assessment
                      </h3>
                      <p className="text-xs text-zinc-400 max-w-md mx-auto leading-relaxed">
                        Confirming transmits an idempotent dispatch command to the rootless OCI worker task queue.
                      </p>
                    </div>

                    <div className="pt-2">
                      <Button
                        variant="primary"
                        size="lg"
                        onClick={handleDispatch}
                        isLoading={isSubmitting}
                        className="w-full sm:w-auto"
                      >
                        Confirm &amp; Launch Assessment
                      </Button>
                    </div>
                  </div>
                )
              }

              {/* Navigation Buttons */}
              <div className="flex items-center justify-between pt-5 border-t border-zinc-800/80 mt-6">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={handleBack}
                  disabled={currentStep === 1 || isSubmitting}
                >
                  &larr; Previous
                </Button>

                {currentStep < 7 && (
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={handleNext}
                    disabled={!canAdvance()}
                  >
                    Continue &rarr;
                  </Button>
                )}
              </div>
            </Card >

      {/* Assessment Completed Popup -> Auto-Redirect to Auto-Generated Report */}
        {completedInfo && (
          <Modal
            isOpen={Boolean(completedInfo)}
            onClose={() => {
              const aid = completedInfo.assessmentId;
              setCompletedInfo(null);
              navigate(`/assessments/${aid}`, { replace: true });
            }}
            title="Assessment Completed"
            description={`Security report automatically generated for ${completedInfo.targetHost}.`}
            maxWidth="md"
          >
            <div className="space-y-4">
              <div className="rounded-xl border border-emerald-800/60 bg-emerald-950/35 p-4 flex items-start gap-3">
                <CheckCircleIcon size={18} className="text-emerald-400 shrink-0 mt-0.5" />
                <div className="space-y-1 text-xs">
                  <p className="font-semibold text-zinc-100">
                    Scan Finished ({completedInfo.findingsCount} finding{completedInfo.findingsCount === 1 ? "" : "s"} identified)
                  </p>
                  <p className="text-zinc-400">
                    Report <code className="font-mono text-[var(--brand-text)]">{completedInfo.reportId}</code> is ready. Opening Report Center in{" "}
                    <strong className="font-mono text-zinc-100">{completedInfo.countdown}s</strong>…
                  </p>
                </div>
              </div>

              <div className="flex flex-col gap-2">
                <Button
                  variant="primary"
                  className="w-full justify-center"
                  onClick={() =>
                    navigate(
                      `/reports?open=${encodeURIComponent(completedInfo.reportId)}&fromAssessment=${encodeURIComponent(completedInfo.assessmentId)}`,
                      { replace: true },
                    )
                  }
                >
                  Open Security Report Now &rarr;
                </Button>
                <div className="grid grid-cols-2 gap-2">
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => {
                      const aid = completedInfo.assessmentId;
                      setCompletedInfo(null);
                      navigate(`/assessments/${aid}`, { replace: true });
                    }}
                  >
                    Inspect Telemetry Logs
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => {
                      setCompletedInfo(null);
                      navigate("/findings", { replace: true });
                    }}
                  >
                    Explore Findings
                  </Button>
                </div>
              </div>
            </div>
          </Modal>
        )}
    </div >
  );
}
