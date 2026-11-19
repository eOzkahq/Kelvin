import React, { useEffect, useState, useCallback } from "react";
import {
  fetchPlatformSettings,
  updatePlatformSettings,
  purgeExpiredEvidence,
  type PlatformWorkspaceSettings,
} from "../features/settings";
import {
  Button,
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  Input,
  Modal,
  SkeletonLoader,
} from "../components/ui";

type ActiveTab = "general" | "assessment" | "retention" | "scanners" | "quotas";

export default function PlatformSettingsPage() {
  const [settings, setSettings] = useState<PlatformWorkspaceSettings | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<ActiveTab>("general");
  const [notification, setNotification] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);

  // Form states
  const [wsName, setWsName] = useState("");
  const [wsTimezone, setWsTimezone] = useState("UTC");
  const [wsContact, setWsContact] = useState("");

  const [rps, setRps] = useState(50);
  const [timeoutMins, setTimeoutMins] = useState(60);
  const [concurrency, setConcurrency] = useState(5);
  const [retries, setRetries] = useState(2);

  const [retentionDays, setRetentionDays] = useState<30 | 90 | 180 | 365>(90);
  const [autoRedact, setAutoRedact] = useState(true);
  const [hardDelete, setHardDelete] = useState(true);

  // Purge Modal State
  const [isPurgeModalOpen, setIsPurgeModalOpen] = useState(false);
  const [purgeConfirmText, setPurgeConfirmText] = useState("");
  const [isPurging, setIsPurging] = useState(false);

  const loadSettings = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await fetchPlatformSettings();
      setSettings(data);
      setWsName(data.general.workspaceName);
      setWsTimezone(data.general.timezone);
      setWsContact(data.general.contactEmail);

      setRps(data.assessmentDefaults.maxRequestsPerSecond);
      setTimeoutMins(data.assessmentDefaults.timeoutMinutes);
      setConcurrency(data.assessmentDefaults.maxConcurrency);
      setRetries(data.assessmentDefaults.maxRetries);

      setRetentionDays(data.retention.retentionDays);
      setAutoRedact(data.retention.autoRedactionEnabled);
      setHardDelete(data.retention.hardDeleteAfterExpiry);
    } catch (err) {
      console.error("Failed to load settings:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  const handleSaveGeneral = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    try {
      const updated = await updatePlatformSettings({
        general: {
          workspaceName: wsName,
          slug: settings?.general.slug || "primary-core",
          timezone: wsTimezone,
          contactEmail: wsContact,
        },
      });
      setSettings(updated);
      setNotification("General workspace settings saved.");
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Save failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsSaving(false);
    }
  };

  const handleSaveAssessments = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    try {
      const updated = await updatePlatformSettings({
        assessmentDefaults: {
          maxRequestsPerSecond: Number(rps),
          timeoutMinutes: Number(timeoutMins),
          maxConcurrency: Number(concurrency),
          maxRetries: Number(retries),
        },
      });
      setSettings(updated);
      setNotification("Assessment defaults saved.");
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Save failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsSaving(false);
    }
  };

  const handleSaveRetention = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    try {
      const updated = await updatePlatformSettings({
        retention: {
          retentionDays,
          autoRedactionEnabled: autoRedact,
          hardDeleteAfterExpiry: hardDelete,
        },
      });
      setSettings(updated);
      setNotification("Data retention policy updated.");
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Save failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsSaving(false);
    }
  };

  const handleToggleScanner = async (scannerId: string) => {
    if (!settings) return;
    const nextScanners = settings.scanners.map((s) =>
      s.id === scannerId ? { ...s, enabled: !s.enabled } : s
    );
    try {
      const updated = await updatePlatformSettings({ scanners: nextScanners });
      setSettings(updated);
      setNotification("Scanner engine availability updated.");
      setTimeout(() => setNotification(null), 2500);
    } catch (err) {
      alert(`Update failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handlePurgeSubmit = async () => {
    if (purgeConfirmText !== "PURGE EXPIRED EVIDENCE") {
      alert('Please type "PURGE EXPIRED EVIDENCE" to confirm.');
      return;
    }
    setIsPurging(true);
    try {
      const result = await purgeExpiredEvidence();
      setIsPurgeModalOpen(false);
      setPurgeConfirmText("");
      loadSettings();
      setNotification(
        `Purged ${result.purgedCount} expired evidence records (Freed ${Math.round(
          result.freedBytes / (1024 * 1024)
        )} MB).`
      );
      setTimeout(() => setNotification(null), 4000);
    } catch (err) {
      alert(`Purge failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsPurging(false);
    }
  };

  if (isLoading || !settings) {
    return (
      <div className="space-y-6">
        <div className="h-6 w-32 bg-zinc-800 animate-pulse rounded" />
        <Card className="p-6">
          <SkeletonLoader lines={6} />
        </Card>
      </div>
    );
  }

  const { quotas } = settings;
  const assessmentPct = Math.round(
    (quotas.monthlyAssessmentsUsed / quotas.monthlyAssessmentsLimit) * 100
  );
  const concurrencyPct = Math.round(
    (quotas.concurrencySlotsUsed / quotas.concurrencySlotsLimit) * 100
  );
  const storagePct = Math.round(
    (quotas.storageUsedBytes / quotas.storageLimitBytes) * 100
  );

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between pb-4 border-b border-zinc-800/80">
        <div>
          <span className="text-[10px] font-mono uppercase tracking-[0.16em] text-[#d4c9a8]">
            Workspace Controls &amp; Quotas
          </span>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100 font-display mt-1">
            Workspace &amp; Platform Settings
          </h1>
          <p className="mt-0.5 text-xs text-zinc-400">
            Workspace defaults, assessment pacing, evidence retention, scanner profiles, and quota metering.
          </p>
        </div>
        {notification && (
          <span className="rounded bg-emerald-950/60 border border-emerald-800 px-3 py-1 text-xs text-emerald-400 animate-in fade-in">
            {notification}
          </span>
        )}
      </div>

      {/* Tab Navigation */}
      <div className="flex border-b border-zinc-800/80 gap-2 overflow-x-auto">
        {(
          [
            { id: "general", label: "General Settings" },
            { id: "assessment", label: "Assessment Defaults" },
            { id: "retention", label: "Data Retention & Privacy" },
            { id: "scanners", label: "Scanner Engines" },
            { id: "quotas", label: "Quota & Usage Metering" },
          ] as { id: ActiveTab; label: string }[]
        ).map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`whitespace-nowrap px-4 py-2 text-xs font-semibold border-b-2 transition-colors cursor-pointer ${
              activeTab === tab.id
                ? "border-[#d4c9a8] text-[#e8debe]"
                : "border-transparent text-zinc-400 hover:text-zinc-200"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab 1: General Settings */}
      {activeTab === "general" && (
        <Card className="p-6 max-w-2xl">
          <CardHeader>
            <CardTitle>General Workspace Identity</CardTitle>
            <CardDescription>Configure workspace display name and timezone preferences</CardDescription>
          </CardHeader>

          <form onSubmit={handleSaveGeneral} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Workspace Display Name
              </label>
              <Input
                type="text"
                value={wsName}
                onChange={(e) => setWsName(e.target.value)}
                required
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Workspace Slug Identifier
              </label>
              <Input type="text" value={settings.general.slug} disabled className="opacity-60" />
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Primary Reporting Timezone
              </label>
              <select
                value={wsTimezone}
                onChange={(e) => setWsTimezone(e.target.value)}
                className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none"
              >
                <option value="UTC">UTC (Universal Coordinated Time)</option>
                <option value="America/New_York">EST (Eastern Standard Time)</option>
                <option value="America/Los_Angeles">PST (Pacific Standard Time)</option>
                <option value="Europe/London">GMT / BST (London)</option>
                <option value="Asia/Tokyo">JST (Tokyo)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Security Contact Email
              </label>
              <Input
                type="email"
                value={wsContact}
                onChange={(e) => setWsContact(e.target.value)}
                required
              />
            </div>

            <div className="pt-2">
              <Button variant="primary" type="submit" isLoading={isSaving}>
                Save Workspace Settings
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* Tab 2: Assessment Defaults */}
      {activeTab === "assessment" && (
        <Card className="p-6 max-w-2xl">
          <CardHeader>
            <CardTitle>Assessment Execution Defaults</CardTitle>
            <CardDescription>
              Guardrails and limits automatically inherited by new assessment creation wizards
            </CardDescription>
          </CardHeader>

          <form onSubmit={handleSaveAssessments} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Default Request Pacing (Max requests per second)
              </label>
              <Input
                type="number"
                min={1}
                max={500}
                value={rps}
                onChange={(e) => setRps(Number(e.target.value))}
                required
              />
              <p className="text-[11px] text-zinc-500 mt-1">Prevents accidental denial of service against sensitive targets.</p>
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Execution Timeout Deadline (Minutes)
              </label>
              <Input
                type="number"
                min={5}
                max={240}
                value={timeoutMins}
                onChange={(e) => setTimeoutMins(Number(e.target.value))}
                required
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Concurrent Scanner Worker Slots
              </label>
              <Input
                type="number"
                min={1}
                max={10}
                value={concurrency}
                onChange={(e) => setConcurrency(Number(e.target.value))}
                required
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Safe Retry Attempts for Transient Failures
              </label>
              <Input
                type="number"
                min={0}
                max={5}
                value={retries}
                onChange={(e) => setRetries(Number(e.target.value))}
                required
              />
            </div>

            <div className="pt-2">
              <Button variant="primary" type="submit" isLoading={isSaving}>
                Save Assessment Defaults
              </Button>
            </div>
          </form>
        </Card>
      )}

      {/* Tab 3: Data Retention & Privacy */}
      {activeTab === "retention" && (
        <div className="space-y-6 max-w-2xl">
          <Card className="p-6">
            <CardHeader>
              <CardTitle>Evidence Retention &amp; Privacy Policies</CardTitle>
              <CardDescription>
                Configure automated lifecycle retention for scanner raw output and proof-of-concept payloads
              </CardDescription>
            </CardHeader>

            <form onSubmit={handleSaveRetention} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1">
                  Evidence Retention Period
                </label>
                <select
                  value={retentionDays}
                  onChange={(e) => setRetentionDays(Number(e.target.value) as any)}
                  className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none"
                >
                  <option value={30}>30 Days (Fast rotation / Staging)</option>
                  <option value={90}>90 Days (Recommended standard)</option>
                  <option value={180}>180 Days (Semi-annual compliance)</option>
                  <option value={365}>365 Days (Annual enterprise audit)</option>
                </select>
              </div>

              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-4 flex items-center justify-between">
                <div>
                  <span className="text-sm font-semibold text-zinc-200">
                    Automatic Secret Redaction (ADR-0005)
                  </span>
                  <p className="text-xs text-zinc-400">
                    Always sanitize passwords, Bearer tokens, and session cookies prior to storage
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={autoRedact}
                  onChange={(e) => setAutoRedact(e.target.checked)}
                  className="h-4 w-4 rounded border-zinc-700 bg-zinc-800 text-cyan-500"
                />
              </div>

              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-4 flex items-center justify-between">
                <div>
                  <span className="text-sm font-semibold text-zinc-200">
                    Cryptographic Hard Delete After Expiry
                  </span>
                  <p className="text-xs text-zinc-400">
                    Permanently overwrite and zero out expired evidence payloads
                  </p>
                </div>
                <input
                  type="checkbox"
                  checked={hardDelete}
                  onChange={(e) => setHardDelete(e.target.checked)}
                  className="h-4 w-4 rounded border-zinc-700 bg-zinc-800 text-cyan-500"
                />
              </div>

              <div className="pt-2">
                <Button variant="primary" type="submit" isLoading={isSaving}>
                  Update Retention Policy
                </Button>
              </div>
            </form>
          </Card>

          {/* Danger Zone: Manual Purge */}
          <Card className="p-6 border-red-900/40 bg-red-950/10 space-y-3">
            <h3 className="text-sm font-bold text-red-400 uppercase tracking-wide">
              Danger Zone — Immediate Evidence Purge
            </h3>
            <p className="text-xs text-zinc-400">
              Immediately purge all historical evidence records older than your configured retention threshold ({retentionDays} days).
            </p>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setIsPurgeModalOpen(true)}
              className="text-red-400 border-red-800/80 hover:bg-red-950/40"
            >
              Purge Expired Records Now...
            </Button>
          </Card>
        </div>
      )}

      {/* Tab 4: Scanner Engines */}
      {activeTab === "scanners" && (
        <Card className="p-6 space-y-4 max-w-3xl">
          <CardHeader>
            <CardTitle>Scanner Engine Availability</CardTitle>
            <CardDescription>
              Toggle specific vulnerability detection engines available to analysts in this workspace
            </CardDescription>
          </CardHeader>

          <div className="space-y-3">
            {settings.scanners.map((scanner) => (
              <div
                key={scanner.id}
                className="rounded-lg border border-zinc-800 bg-zinc-950 p-4 flex items-center justify-between"
              >
                <div>
                  <span className="font-semibold text-sm text-zinc-100">{scanner.name}</span>
                  <p className="text-xs text-zinc-400 mt-0.5">{scanner.description}</p>
                </div>
                <label className="flex items-center gap-2 cursor-pointer">
                  <span className="text-xs text-zinc-500">
                    {scanner.enabled ? "Enabled" : "Disabled"}
                  </span>
                  <input
                    type="checkbox"
                    checked={scanner.enabled}
                    onChange={() => handleToggleScanner(scanner.id)}
                    className="h-4 w-4 rounded border-zinc-700 bg-zinc-800 text-cyan-500"
                  />
                </label>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Tab 5: Quota & Usage Metering */}
      {activeTab === "quotas" && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-4xl">
          <Card className="p-5 space-y-3">
            <div className="flex items-center justify-between text-xs font-semibold uppercase text-zinc-400">
              <span>Monthly Assessments</span>
              <span className="font-mono text-zinc-200">
                {quotas.monthlyAssessmentsUsed} / {quotas.monthlyAssessmentsLimit}
              </span>
            </div>
            <div className="h-2.5 w-full rounded-full bg-zinc-800 overflow-hidden">
              <div
                className={`h-full rounded-full ${
                  assessmentPct >= 90
                    ? "bg-red-500"
                    : assessmentPct >= 70
                    ? "bg-amber-500"
                    : "bg-cyan-500"
                }`}
                style={{ width: `${assessmentPct}%` }}
              />
            </div>
            <p className="text-xs text-zinc-400">{assessmentPct}% quota consumed this billing cycle</p>
          </Card>

          <Card className="p-5 space-y-3">
            <div className="flex items-center justify-between text-xs font-semibold uppercase text-zinc-400">
              <span>Concurrent Worker Slots</span>
              <span className="font-mono text-zinc-200">
                {quotas.concurrencySlotsUsed} / {quotas.concurrencySlotsLimit}
              </span>
            </div>
            <div className="h-2.5 w-full rounded-full bg-zinc-800 overflow-hidden">
              <div
                className={`h-full rounded-full ${
                  concurrencyPct >= 90
                    ? "bg-red-500"
                    : concurrencyPct >= 70
                    ? "bg-amber-500"
                    : "bg-cyan-500"
                }`}
                style={{ width: `${concurrencyPct}%` }}
              />
            </div>
            <p className="text-xs text-zinc-400">{concurrencyPct}% active scanner concurrency</p>
          </Card>

          <Card className="p-5 space-y-3">
            <div className="flex items-center justify-between text-xs font-semibold uppercase text-zinc-400">
              <span>Evidence Storage</span>
              <span className="font-mono text-zinc-200">
                {(quotas.storageUsedBytes / 1e9).toFixed(1)} GB /{" "}
                {(quotas.storageLimitBytes / 1e9).toFixed(1)} GB
              </span>
            </div>
            <div className="h-2.5 w-full rounded-full bg-zinc-800 overflow-hidden">
              <div
                className={`h-full rounded-full ${
                  storagePct >= 90
                    ? "bg-red-500"
                    : storagePct >= 70
                    ? "bg-amber-500"
                    : "bg-emerald-500"
                }`}
                style={{ width: `${storagePct}%` }}
              />
            </div>
            <p className="text-xs text-zinc-400">{storagePct}% allocated storage used</p>
          </Card>
        </div>
      )}

      {/* Purge Modal */}
      <Modal
        isOpen={isPurgeModalOpen}
        onClose={() => setIsPurgeModalOpen(false)}
        title="Confirm Evidence Purge"
      >
        <div className="space-y-4">
          <p className="text-sm text-zinc-300">
            This will permanently erase all raw request/response evidence older than {retentionDays} days from storage. This action cannot be undone.
          </p>

          <div>
            <label className="block text-xs font-medium text-zinc-400 mb-1">
              Type <strong className="text-red-400 select-all">PURGE EXPIRED EVIDENCE</strong> to confirm:
            </label>
            <Input
              type="text"
              value={purgeConfirmText}
              onChange={(e) => setPurgeConfirmText(e.target.value)}
              placeholder="PURGE EXPIRED EVIDENCE"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => setIsPurgeModalOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handlePurgeSubmit}
              isLoading={isPurging}
              className="bg-red-600 hover:bg-red-500"
            >
              Confirm Purge
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
