import React, { useEffect, useState, useCallback } from "react";
import {
  fetchTargets,
  registerTarget,
  verifyTargetOwnership,
  updateTargetScope,
  deleteTarget,
  type TargetAsset,
  type TargetEnvironment,
  type TargetType,
  type TargetCriticality,
  type TargetScopeConfig,
} from "../features/targets";
import {
  Button,
  Card,
  EmptyState,
  Input,
  Modal,
  SkeletonLoader,
} from "../components/ui";

export default function TargetsManagementPage() {
  const [targets, setTargets] = useState<TargetAsset[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [envFilter, setEnvFilter] = useState<TargetEnvironment | "">("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [criticalityFilter, setCriticalityFilter] = useState<TargetCriticality | "">("");

  // Modals
  const [isRegisterOpen, setIsRegisterOpen] = useState(false);
  const [isVerifyOpen, setIsVerifyOpen] = useState(false);
  const [isScopeOpen, setIsScopeOpen] = useState(false);
  const [activeTarget, setActiveTarget] = useState<TargetAsset | null>(null);

  // Registration Form State
  const [regName, setRegName] = useState("");
  const [regHost, setRegHost] = useState("");
  const [regType, setRegType] = useState<TargetType>("DOMAIN");
  const [regEnv, setRegEnv] = useState<TargetEnvironment>("STAGING");
  const [regCriticality, setRegCriticality] = useState<TargetCriticality>("TIER_1");
  const [regPorts, setRegPorts] = useState("80, 443");
  const [regExcludedPaths, setRegExcludedPaths] = useState("/logout, /api/v1/admin/terminate");
  const [regRps, setRegRps] = useState(25);
  const [regError, setRegError] = useState<string | null>(null);
  const [isRegistering, setIsRegistering] = useState(false);

  // Scope Form State
  const [scopePorts, setScopePorts] = useState("");
  const [scopeExcluded, setScopeExcluded] = useState("");
  const [scopeRps, setScopeRps] = useState(20);
  const [isSavingScope, setIsSavingScope] = useState(false);

  // Verification state
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyMessage, setVerifyMessage] = useState<string | null>(null);
  const [notification, setNotification] = useState<string | null>(null);

  const loadTargets = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await fetchTargets({
        search: searchQuery || undefined,
        environment: envFilter || undefined,
        verificationStatus: (statusFilter as any) || undefined,
        criticality: criticalityFilter || undefined,
      });
      setTargets(data);
    } catch (err) {
      console.error("Failed to load targets:", err);
    } finally {
      setIsLoading(false);
    }
  }, [searchQuery, envFilter, statusFilter, criticalityFilter]);

  useEffect(() => {
    loadTargets();
  }, [loadTargets]);

  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setRegError(null);
    setIsRegistering(true);

    try {
      const excludedArray = regExcludedPaths
        .split(",")
        .map((p) => p.trim())
        .filter(Boolean);

      const created = await registerTarget({
        name: regName,
        host: regHost,
        type: regType,
        environment: regEnv,
        criticality: regCriticality,
        allowedPorts: regPorts,
        excludedPaths: excludedArray,
        maxRequestsPerSecond: Number(regRps),
      });

      setTargets((prev) => [created, ...prev]);
      setIsRegisterOpen(false);
      setRegName("");
      setRegHost("");
      setNotification(`Target "${created.name}" registered successfully.`);
      setTimeout(() => setNotification(null), 4000);
    } catch (err) {
      setRegError(err instanceof Error ? err.message : String(err));
    } finally {
      setIsRegistering(false);
    }
  };

  const handleCheckVerification = async () => {
    if (!activeTarget) return;
    setIsVerifying(true);
    setVerifyMessage(null);

    try {
      const result = await verifyTargetOwnership(activeTarget.id);
      if (result.verified) {
        setTargets((prev) =>
          prev.map((t) => (t.id === activeTarget.id ? { ...t, verificationStatus: "VERIFIED" } : t))
        );
        setActiveTarget((prev) => (prev ? { ...prev, verificationStatus: "VERIFIED" } : null));
        setVerifyMessage(result.message);
        setTimeout(() => setIsVerifyOpen(false), 2000);
      } else {
        setVerifyMessage(result.message);
      }
    } catch (err) {
      setVerifyMessage(`Verification check failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsVerifying(false);
    }
  };

  const handleSaveScope = async () => {
    if (!activeTarget) return;
    setIsSavingScope(true);

    try {
      const excludedArray = scopeExcluded
        .split(",")
        .map((p) => p.trim())
        .filter(Boolean);

      const newScope: TargetScopeConfig = {
        allowedPorts: scopePorts,
        excludedPaths: excludedArray,
        maxRequestsPerSecond: scopeRps,
      };

      const updated = await updateTargetScope(activeTarget.id, newScope);
      setTargets((prev) => prev.map((t) => (t.id === updated.id ? updated : t)));
      setIsScopeOpen(false);
      setNotification(`Scope configuration updated for ${updated.name}.`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Scope update failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsSavingScope(false);
    }
  };

  const handleDelete = async (targetId: string, name: string) => {
    if (!confirm(`Are you sure you want to remove target "${name}"?`)) return;
    try {
      await deleteTarget(targetId);
      setTargets((prev) => prev.filter((t) => t.id !== targetId));
      setNotification(`Target "${name}" removed.`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Failed to delete target: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const openScopeModal = (target: TargetAsset) => {
    setActiveTarget(target);
    setScopePorts(target.scopeConfig.allowedPorts);
    setScopeExcluded(target.scopeConfig.excludedPaths.join(", "));
    setScopeRps(target.scopeConfig.maxRequestsPerSecond);
    setIsScopeOpen(true);
  };

  const openVerifyModal = (target: TargetAsset) => {
    setActiveTarget(target);
    setVerifyMessage(null);
    setIsVerifyOpen(true);
  };

  // Metrics
  const totalCount = targets.length;
  const verifiedCount = targets.filter((t) => t.verificationStatus === "VERIFIED").length;
  const pendingCount = targets.filter((t) => t.verificationStatus === "PENDING_VERIFICATION").length;
  const tier1Count = targets.filter((t) => t.criticality === "TIER_1").length;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
            Targets & Asset Scope Management
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            Authorized attack surface inventory, domain ownership verification, and scanning guardrails.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {notification && (
            <span className="rounded bg-emerald-950/60 border border-emerald-800 px-3 py-1 text-xs text-emerald-400 animate-in fade-in">
              {notification}
            </span>
          )}
          <Button variant="primary" onClick={() => setIsRegisterOpen(true)}>
            + Register New Target
          </Button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-3">
          <span className="text-xs text-zinc-400 font-medium">Total Registered Targets</span>
          <p className="mt-1 text-2xl font-bold text-zinc-100">{totalCount}</p>
        </div>
        <div className="rounded-lg border border-emerald-900/40 bg-emerald-950/20 p-3">
          <span className="text-xs text-emerald-400 font-medium">Ownership Verified</span>
          <p className="mt-1 text-2xl font-bold text-emerald-400">{verifiedCount}</p>
        </div>
        <div className="rounded-lg border border-amber-900/40 bg-amber-950/20 p-3">
          <span className="text-xs text-amber-400 font-medium">Pending Verification</span>
          <p className="mt-1 text-2xl font-bold text-amber-400">{pendingCount}</p>
        </div>
        <div className="rounded-lg border border-red-900/40 bg-red-950/20 p-3">
          <span className="text-xs text-red-400 font-medium">Tier-1 Mission Critical</span>
          <p className="mt-1 text-2xl font-bold text-red-400">{tier1Count}</p>
        </div>
      </div>

      {/* Filter Bar */}
      <Card className="p-4 space-y-3">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-12">
          <div className="md:col-span-4">
            <Input
              type="text"
              placeholder="Search targets by name or hostname..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div className="md:col-span-3">
            <select
              value={envFilter}
              onChange={(e) => setEnvFilter(e.target.value as TargetEnvironment)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Environments</option>
              <option value="PRODUCTION">Production</option>
              <option value="STAGING">Staging</option>
              <option value="DEVELOPMENT">Development</option>
            </select>
          </div>

          <div className="md:col-span-3">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Ownership Statuses</option>
              <option value="VERIFIED">Verified Only</option>
              <option value="PENDING_VERIFICATION">Pending Verification</option>
            </select>
          </div>

          <div className="md:col-span-2 flex items-center justify-end">
            {(searchQuery || envFilter || statusFilter || criticalityFilter) && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setSearchQuery("");
                  setEnvFilter("");
                  setStatusFilter("");
                  setCriticalityFilter("");
                }}
              >
                Reset Filters
              </Button>
            )}
          </div>
        </div>
      </Card>

      {/* Targets Table */}
      <div className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-900/60">
        <table className="w-full text-left text-sm text-zinc-300">
          <thead className="border-b border-zinc-800 bg-zinc-900 text-xs uppercase text-zinc-400">
            <tr>
              <th className="px-4 py-3">Target Asset</th>
              <th className="px-4 py-3">Type</th>
              <th className="px-4 py-3">Environment</th>
              <th className="px-4 py-3">Criticality</th>
              <th className="px-4 py-3">Ownership Verification</th>
              <th className="px-4 py-3">Scope Rules</th>
              <th className="px-4 py-3">Open Findings</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/60">
            {isLoading ? (
              <tr>
                <td colSpan={8} className="p-4">
                  <SkeletonLoader lines={5} />
                </td>
              </tr>
            ) : targets.length === 0 ? (
              <tr>
                <td colSpan={8} className="p-8">
                  <EmptyState
                    title="No Targets Found"
                    description="No target assets match your search criteria. Add an asset to begin assessments."
                    actionLabel="Register Target"
                    onAction={() => setIsRegisterOpen(true)}
                  />
                </td>
              </tr>
            ) : (
              targets.map((tgt) => (
                <tr key={tgt.id} className="hover:bg-zinc-800/30">
                  <td className="px-4 py-3">
                    <div className="font-semibold text-zinc-100">{tgt.name}</div>
                    <code className="text-xs font-mono text-zinc-400">{tgt.host}</code>
                  </td>
                  <td className="px-4 py-3">
                    <span className="rounded bg-zinc-800 px-2 py-0.5 text-[11px] font-mono text-zinc-300">
                      {tgt.type}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`rounded px-2 py-0.5 text-xs font-medium ${
                        tgt.environment === "PRODUCTION"
                          ? "bg-red-950/40 text-red-300 border border-red-800/40"
                          : tgt.environment === "STAGING"
                          ? "bg-cyan-950/40 text-cyan-300 border border-cyan-800/40"
                          : "bg-zinc-800 text-zinc-400"
                      }`}
                    >
                      {tgt.environment}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs font-mono font-medium text-zinc-300">
                      {tgt.criticality.replace("_", " ")}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {tgt.verificationStatus === "VERIFIED" ? (
                      <span className="inline-flex items-center gap-1 rounded bg-emerald-950/60 border border-emerald-800 px-2 py-0.5 text-xs text-emerald-400 font-medium">
                        ✓ Verified
                      </span>
                    ) : (
                      <button
                        onClick={() => openVerifyModal(tgt)}
                        className="inline-flex items-center gap-1 rounded bg-amber-950/60 border border-amber-800 px-2 py-0.5 text-xs text-amber-300 hover:bg-amber-900/60"
                      >
                        ⚠ Verify Ownership &rarr;
                      </button>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs text-zinc-400 font-mono">
                    <div>Ports: {tgt.scopeConfig.allowedPorts}</div>
                    <div className="text-[11px] text-zinc-500">Max {tgt.scopeConfig.maxRequestsPerSecond} rps</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className="rounded bg-zinc-800 px-2 py-0.5 text-xs font-mono text-zinc-300">
                      {tgt.openFindingsCount}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <Button size="sm" variant="outline" onClick={() => openScopeModal(tgt)}>
                        Scope
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleDelete(tgt.id, tgt.name)}
                        className="text-zinc-500 hover:text-red-400"
                      >
                        Delete
                      </Button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Target Registration Modal */}
      <Modal
        isOpen={isRegisterOpen}
        onClose={() => setIsRegisterOpen(false)}
        title="Register Authorized Assessment Target"
      >
        <form onSubmit={handleRegisterSubmit} className="space-y-4 max-h-[75vh] overflow-y-auto pr-1">
          {regError && (
            <div className="rounded border border-red-800 bg-red-950/40 p-3 text-xs text-red-300">
              {regError}
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Asset Display Name <span className="text-red-400">*</span>
            </label>
            <Input
              type="text"
              placeholder="e.g. Production Payment Gateway"
              value={regName}
              onChange={(e) => setRegName(e.target.value)}
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Target Host / URL / CIDR <span className="text-red-400">*</span>
              </label>
              <Input
                type="text"
                placeholder="e.g. api.kelvin.io or 192.168.1.0/24"
                value={regHost}
                onChange={(e) => setRegHost(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">Target Type</label>
              <select
                value={regType}
                onChange={(e) => setRegType(e.target.value as TargetType)}
                className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none"
              >
                <option value="DOMAIN">Domain / FQDN</option>
                <option value="IP">Static IP</option>
                <option value="CIDR">CIDR Subnet</option>
                <option value="URL">Specific Web URL</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">Environment</label>
              <select
                value={regEnv}
                onChange={(e) => setRegEnv(e.target.value as TargetEnvironment)}
                className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none"
              >
                <option value="STAGING">Staging Environment</option>
                <option value="PRODUCTION">Production Environment</option>
                <option value="DEVELOPMENT">Development Environment</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">Asset Criticality</label>
              <select
                value={regCriticality}
                onChange={(e) => setRegCriticality(e.target.value as TargetCriticality)}
                className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none"
              >
                <option value="TIER_1">Tier 1 (Mission Critical)</option>
                <option value="TIER_2">Tier 2 (High Business Value)</option>
                <option value="TIER_3">Tier 3 (Medium)</option>
                <option value="TIER_4">Tier 4 (Low / Ephemeral)</option>
              </select>
            </div>
          </div>

          <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 space-y-3">
            <h4 className="text-xs font-semibold uppercase text-zinc-400">
              Default Scope Boundaries
            </h4>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-zinc-400 mb-1">Allowed Ports</label>
                <Input
                  type="text"
                  placeholder="e.g. 80, 443, 8443"
                  value={regPorts}
                  onChange={(e) => setRegPorts(e.target.value)}
                />
              </div>
              <div>
                <label className="block text-xs text-zinc-400 mb-1">Max Requests/sec</label>
                <Input
                  type="number"
                  value={regRps}
                  onChange={(e) => setRegRps(Number(e.target.value))}
                />
              </div>
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Excluded Subpaths (comma-separated)</label>
              <Input
                type="text"
                placeholder="/logout, /delete, /admin"
                value={regExcludedPaths}
                onChange={(e) => setRegExcludedPaths(e.target.value)}
              />
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => setIsRegisterOpen(false)} type="button">
              Cancel
            </Button>
            <Button variant="primary" type="submit" isLoading={isRegistering}>
              Register Asset
            </Button>
          </div>
        </form>
      </Modal>

      {/* Ownership Verification Modal */}
      {activeTarget && (
        <Modal
          isOpen={isVerifyOpen}
          onClose={() => setIsVerifyOpen(false)}
          title={`Verify Ownership: ${activeTarget.name}`}
        >
          <div className="space-y-4">
            <p className="text-sm text-zinc-400">
              Before security assessment traffic can target this asset, prove administrative authority over the domain.
            </p>

            <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-4 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="text-zinc-500">Method:</span>
                <span className="text-zinc-300 font-semibold">{activeTarget.verificationChallenge.type}</span>
              </div>
              <div>
                <span className="text-zinc-500">Record Hostname:</span>
                <p className="text-cyan-300 mt-1 select-all">{activeTarget.verificationChallenge.recordName}</p>
              </div>
              <div>
                <span className="text-zinc-500">Challenge TXT Value:</span>
                <div className="mt-1 flex items-center justify-between rounded bg-zinc-900 p-2 text-zinc-200">
                  <code className="select-all">{activeTarget.verificationChallenge.token}</code>
                </div>
              </div>
            </div>

            {verifyMessage && (
              <div
                className={`rounded p-3 text-xs ${
                  verifyMessage.includes("verified")
                    ? "bg-emerald-950/60 border border-emerald-800 text-emerald-300"
                    : "bg-red-950/60 border border-red-800 text-red-300"
                }`}
              >
                {verifyMessage}
              </div>
            )}

            <div className="flex justify-end gap-2 pt-2">
              <Button variant="secondary" onClick={() => setIsVerifyOpen(false)}>
                Close
              </Button>
              <Button
                variant="primary"
                onClick={handleCheckVerification}
                isLoading={isVerifying}
              >
                Check DNS Verification
              </Button>
            </div>
          </div>
        </Modal>
      )}

      {/* Scope Editor Modal */}
      {activeTarget && (
        <Modal
          isOpen={isScopeOpen}
          onClose={() => setIsScopeOpen(false)}
          title={`Scope Boundaries: ${activeTarget.name}`}
        >
          <div className="space-y-4">
            <p className="text-sm text-zinc-400">
              Configure scanner execution boundaries, allowed ports, and sensitive subpath exclusions.
            </p>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Allowed Port Ranges
              </label>
              <Input
                type="text"
                placeholder="e.g. 80, 443, 8000-8080"
                value={scopePorts}
                onChange={(e) => setScopePorts(e.target.value)}
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Excluded Subpaths &amp; URLs (comma-separated)
              </label>
              <Input
                type="text"
                placeholder="e.g. /auth/logout, /api/v1/delete, /billing"
                value={scopeExcluded}
                onChange={(e) => setScopeExcluded(e.target.value)}
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-300 mb-1">
                Max Requests per Second
              </label>
              <Input
                type="number"
                value={scopeRps}
                onChange={(e) => setScopeRps(Number(e.target.value))}
              />
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <Button variant="secondary" onClick={() => setIsScopeOpen(false)}>
                Cancel
              </Button>
              <Button variant="primary" onClick={handleSaveScope} isLoading={isSavingScope}>
                Save Scope Configuration
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
