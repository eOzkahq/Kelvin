import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  fetchTargets,
  fetchProfiles,
  createAssessment,
  type TargetOption,
  type ScanProfile,
} from "../features/assessments";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  Button,
  Input,
  SkeletonLoader,
} from "../components/ui";

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
  const [currentStep, setCurrentStep] = useState(1);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Form State
  const [assessmentName, setAssessmentName] = useState("");
  const [targetMode, setTargetMode] = useState<"preconfigured" | "custom">("preconfigured");
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [customTargetUrl, setCustomTargetUrl] = useState("");
  const [selectedProfileId, setSelectedProfileId] = useState("");
  const [rateLimit, setRateLimit] = useState(50);
  const [timeoutMinutes, setTimeoutMinutes] = useState(30);
  const [scopeConfirmed, setScopeConfirmed] = useState(false);
  const [idempotencyKey] = useState(() => `idem-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`);

  const { data: targets, isLoading: targetsLoading } = useQuery({
    queryKey: ["targets"],
    queryFn: fetchTargets,
  });

  const { data: profiles, isLoading: profilesLoading } = useQuery({
    queryKey: ["profiles"],
    queryFn: fetchProfiles,
  });

  const selectedTarget: TargetOption | undefined =
    targetMode === "custom"
      ? {
          id: "custom",
          name: "Custom Lab Target",
          address: customTargetUrl.trim(),
          verified: false,
          environment: "STAGING",
        }
      : targets?.find((t) => t.id === selectedTargetId);
  const selectedProfile: ScanProfile | undefined = profiles?.find((p) => p.id === selectedProfileId);

  const canAdvance = () => {
    switch (currentStep) {
      case 1:
        return Boolean(
          (targetMode === "custom" ? customTargetUrl.trim() : selectedTargetId) && assessmentName.trim()
        );
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
      const res = await createAssessment({
        name: assessmentName,
        targetId: targetMode === "preconfigured" ? selectedTargetId : undefined,
        targetAddress: targetMode === "custom" ? customTargetUrl.trim() : selectedTarget?.address,
        targets: targetMode === "custom" && customTargetUrl.trim() ? [{ host: customTargetUrl.trim() }] : undefined,
        profileId: selectedProfileId,
        rateLimit,
        timeoutMinutes,
        authorizedScopeConfirmed: scopeConfirmed,
        idempotencyKey,
      });

      navigate(`/assessments/${res.id || "asmt-new"}`);
    } catch (err: unknown) {
      setErrorMessage(err instanceof Error ? err.message : "Failed to dispatch assessment");
      setIsSubmitting(false);
    }
  };

  if (targetsLoading || profilesLoading) {
    return (
      <div className="max-w-3xl mx-auto space-y-4">
        <SkeletonLoader lines={2} className="w-48" />
        <SkeletonLoader lines={8} className="h-96" />
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6">
      {/* Wizard Header */}
      <div className="flex items-center justify-between pb-2 border-b border-zinc-800">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-zinc-100">
            Assessment Creation Wizard
          </h1>
          <p className="text-xs text-zinc-400 mt-0.5">
            Step {currentStep} of 7: {STEPS[currentStep - 1]}
          </p>
        </div>

        <Link to="/assessments">
          <Button variant="ghost" size="sm">
            Cancel
          </Button>
        </Link>
      </div>

      {/* Linear Step Bar */}
      <div className="flex items-center justify-between gap-1 border-b border-zinc-800 pb-3 text-xs">
        {STEPS.map((step, idx) => {
          const stepNumber = idx + 1;
          const isActive = stepNumber === currentStep;
          const isDone = stepNumber < currentStep;

          return (
            <div
              key={step}
              className={`flex items-center gap-1.5 px-2 py-1 rounded text-[11px] font-medium transition-colors ${
                isActive
                  ? "bg-cyan-950 text-cyan-300 border border-cyan-800/60"
                  : isDone
                  ? "text-emerald-400"
                  : "text-zinc-600"
              }`}
            >
              <span>{isDone ? "✓" : stepNumber}.</span>
              <span className="hidden sm:inline">{step.split(". ")[1]}</span>
            </div>
          );
        })}
      </div>

      {errorMessage && (
        <div className="rounded border border-red-800 bg-red-950/50 p-3 text-xs text-red-300">
          {errorMessage}
        </div>
      )}

      {/* Step Contents */}
      <Card>
        {/* Step 1: Target Selection */}
        {currentStep === 1 && (
          <div className="space-y-4">
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

            <div className="space-y-3 pt-2">
              <div className="flex items-center gap-2 border-b border-zinc-800 pb-2">
                <button
                  type="button"
                  onClick={() => setTargetMode("preconfigured")}
                  className={`text-xs font-medium px-2.5 py-1 rounded transition-colors ${
                    targetMode === "preconfigured"
                      ? "bg-cyan-950 text-cyan-300 border border-cyan-800"
                      : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  Verified Targets ({targets?.length ?? 0})
                </button>
                <button
                  type="button"
                  onClick={() => setTargetMode("custom")}
                  className={`text-xs font-medium px-2.5 py-1 rounded transition-colors ${
                    targetMode === "custom"
                      ? "bg-cyan-950 text-cyan-300 border border-cyan-800"
                      : "text-zinc-400 hover:text-zinc-200"
                  }`}
                >
                  Custom Target URL
                </button>
              </div>

              {targetMode === "preconfigured" ? (
                <div className="grid grid-cols-1 gap-2">
                  {targets?.map((tgt) => (
                    <button
                      key={tgt.id}
                      type="button"
                      onClick={() => setSelectedTargetId(tgt.id)}
                      className={`flex items-center justify-between p-3 rounded-lg border text-left transition-all ${
                        selectedTargetId === tgt.id
                          ? "border-cyan-500 bg-cyan-950/40 text-cyan-100"
                          : "border-zinc-800 bg-zinc-900/60 hover:border-zinc-700 text-zinc-300"
                      }`}
                    >
                      <div>
                        <p className="font-semibold text-xs text-zinc-100">{tgt.name}</p>
                        <p className="font-mono text-[11px] text-zinc-400">{tgt.address}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700">
                          {tgt.environment}
                        </span>
                        {selectedTargetId === tgt.id && <span className="text-cyan-400">✓</span>}
                      </div>
                    </button>
                  ))}
                </div>
              ) : (
                <div className="space-y-2 p-3 rounded-lg border border-zinc-800 bg-zinc-900/40">
                  <Input
                    label="Custom Target Address / URL"
                    placeholder="e.g., https://juice-shop.herokuapp.com or http://127.0.0.1:8080"
                    value={customTargetUrl}
                    onChange={(e) => setCustomTargetUrl(e.target.value)}
                    helperText="Specify the authorized domain or HTTP/HTTPS endpoint for this assessment run."
                    required
                  />
                </div>
              )}
            </div>
          </div>
        )}

        {/* Step 2: Profile Selection */}
        {currentStep === 2 && (
          <div className="space-y-4">
            <CardHeader>
              <div>
                <CardTitle>Select Scan Profile</CardTitle>
                <CardDescription>
                  Define the audit depth, testing scope, and vulnerability signature baseline.
                </CardDescription>
              </div>
            </CardHeader>

            <div className="space-y-2">
              {profiles?.map((prof) => (
                <button
                  key={prof.id}
                  type="button"
                  onClick={() => setSelectedProfileId(prof.id)}
                  className={`w-full flex flex-col p-4 rounded-lg border text-left transition-all ${
                    selectedProfileId === prof.id
                      ? "border-cyan-500 bg-cyan-950/40 text-cyan-100"
                      : "border-zinc-800 bg-zinc-900/60 hover:border-zinc-700 text-zinc-300"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-xs text-zinc-100">{prof.name}</span>
                    <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700">
                      Risk: {prof.riskLevel}
                    </span>
                  </div>
                  <p className="text-xs text-zinc-400 mt-1">{prof.description}</p>
                  <div className="flex items-center gap-1.5 mt-2">
                    {prof.scanners.map((s) => (
                      <span
                        key={s}
                        className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-cyan-300 border border-zinc-700"
                      >
                        {s}
                      </span>
                    ))}
                  </div>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Step 3: Scanner Inspection */}
        {currentStep === 3 && (
          <div className="space-y-4">
            <CardHeader>
              <div>
                <CardTitle>Review Enabled Scanner Engines</CardTitle>
                <CardDescription>
                  Worker sandboxes and execution capabilities allocated for profile &quot;{selectedProfile?.name}&quot;.
                </CardDescription>
              </div>
            </CardHeader>

            <div className="space-y-3 text-xs">
              {selectedProfile?.scanners.map((scanner) => (
                <div
                  key={scanner}
                  className="flex items-center justify-between p-3 rounded-lg border border-zinc-800 bg-zinc-900/50"
                >
                  <div>
                    <span className="font-semibold text-zinc-200 block">{scanner} Engine</span>
                    <span className="text-[11px] text-zinc-400">
                      Non-root container sandbox • Egress boundary enforced
                    </span>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-emerald-950 text-emerald-300 border border-emerald-800">
                    Ready
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Step 4: Permitted Options */}
        {currentStep === 4 && (
          <div className="space-y-4">
            <CardHeader>
              <div>
                <CardTitle>Execution Options & Guardrails</CardTitle>
                <CardDescription>
                  Configure safe request pacing and execution deadlines. Unsanitized flags are blocked.
                </CardDescription>
              </div>
            </CardHeader>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Input
                label="Maximum Rate Limit (req/sec)"
                type="number"
                min={1}
                max={200}
                value={rateLimit}
                onChange={(e) => setRateLimit(Number(e.target.value))}
                helperText="Pacing enforced across worker cluster."
                required
              />

              <Input
                label="Timeout Deadline (Minutes)"
                type="number"
                min={5}
                max={180}
                value={timeoutMinutes}
                onChange={(e) => setTimeoutMinutes(Number(e.target.value))}
                helperText="Job automatically terminated after duration."
                required
              />
            </div>
          </div>
        )}

        {/* Step 5: Scope & Authorization */}
        {currentStep === 5 && (
          <div className="space-y-4">
            <CardHeader>
              <div>
                <CardTitle>Scope & Legal Authorization Confirmation</CardTitle>
                <CardDescription>
                  Strict adherence to rules of engagement is required before dispatching scans.
                </CardDescription>
              </div>
            </CardHeader>

            <div className="rounded-lg border border-amber-900/40 bg-amber-950/20 p-4 text-xs text-amber-200 space-y-2">
              <p className="font-semibold">⚠️ Legal Authorization Required</p>
              <p>
                Scanning target <span className="font-mono text-zinc-100">{selectedTarget?.address}</span> must be explicitly authorized by your organization or customer engagement terms.
              </p>
            </div>

            <label className="flex items-start gap-3 p-3 rounded-lg border border-zinc-800 bg-zinc-900/60 cursor-pointer">
              <input
                type="checkbox"
                checked={scopeConfirmed}
                onChange={(e) => setScopeConfirmed(e.target.checked)}
                className="mt-1 rounded border-zinc-700 bg-zinc-800 text-cyan-500"
              />
              <span className="text-xs text-zinc-300">
                I formally confirm that I possess verified authorization to execute security assessment tools against this target.
              </span>
            </label>
          </div>
        )}

        {/* Step 6: Summary Review */}
        {currentStep === 6 && (
          <div className="space-y-4">
            <CardHeader>
              <div>
                <CardTitle>Pre-Flight Assessment Summary</CardTitle>
                <CardDescription>
                  Verify execution configuration before submitting to the worker cluster.
                </CardDescription>
              </div>
            </CardHeader>

            <div className="grid grid-cols-2 gap-4 text-xs">
              <div className="p-3 rounded border border-zinc-800 bg-zinc-900/40">
                <span className="text-zinc-500 block">Assessment Name</span>
                <span className="font-semibold text-zinc-200">{assessmentName}</span>
              </div>
              <div className="p-3 rounded border border-zinc-800 bg-zinc-900/40">
                <span className="text-zinc-500 block">Target Asset</span>
                <span className="font-mono text-cyan-300">{selectedTarget?.address}</span>
              </div>
              <div className="p-3 rounded border border-zinc-800 bg-zinc-900/40">
                <span className="text-zinc-500 block">Profile Selected</span>
                <span className="font-medium text-zinc-200">{selectedProfile?.name}</span>
              </div>
              <div className="p-3 rounded border border-zinc-800 bg-zinc-900/40">
                <span className="text-zinc-500 block">Rate & Timeout</span>
                <span className="font-mono text-zinc-300">{rateLimit} req/s • {timeoutMinutes} min</span>
              </div>
            </div>
          </div>
        )}

        {/* Step 7: Launch Confirmation */}
        {currentStep === 7 && (
          <div className="space-y-4 text-center py-6">
            <div className="inline-flex h-14 w-14 items-center justify-center rounded-full bg-cyan-950 border border-cyan-800/80 text-2xl">
              🚀
            </div>
            <h3 className="text-base font-semibold text-zinc-100">
              Ready to Dispatch Assessment
            </h3>
            <p className="text-xs text-zinc-400 max-w-md mx-auto">
              Clicking below transmits an idempotent dispatch command to the worker task queue.
            </p>

            <div className="pt-4">
              <Button
                variant="primary"
                size="lg"
                onClick={handleDispatch}
                isLoading={isSubmitting}
                className="w-full sm:w-auto"
              >
                Confirm & Launch Assessment
              </Button>
            </div>
          </div>
        )}

        {/* Navigation Buttons */}
        <div className="flex items-center justify-between pt-4 border-t border-zinc-800 mt-6">
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
      </Card>
    </div>
  );
}
