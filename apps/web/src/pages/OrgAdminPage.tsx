import React, { useEffect, useState, useCallback } from "react";
import {
  fetchOrganizationProfile,
  updateOrganizationProfile,
  provisionWorkspace,
  type OrganizationProfile,
} from "../features/organization";
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

export default function OrgAdminPage() {
  const [profile, setProfile] = useState<OrganizationProfile | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Workspace Provisioning State
  const [isProvisionOpen, setIsProvisionOpen] = useState(false);
  const [wsName, setWsName] = useState("");
  const [wsSlug, setWsSlug] = useState("");
  const [wsDesc, setWsDesc] = useState("");
  const [isProvisioning, setIsProvisioning] = useState(false);

  // Settings update state
  const [enforce2FA, setEnforce2FA] = useState(true);
  const [primaryDomain, setPrimaryDomain] = useState("");
  const [isSavingSettings, setIsSavingSettings] = useState(false);
  const [notification, setNotification] = useState<string | null>(null);

  const loadOrg = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await fetchOrganizationProfile();
      setProfile(data);
      setEnforce2FA(data.enforce2FA);
      setPrimaryDomain(data.primaryDomain);
    } catch (err) {
      console.error("Failed to load organization profile:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadOrg();
  }, [loadOrg]);

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingSettings(true);
    try {
      const updated = await updateOrganizationProfile({
        primaryDomain,
        enforce2FA,
      });
      setProfile(updated);
      setNotification("Organization settings updated successfully.");
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Settings update failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsSavingSettings(false);
    }
  };

  const handleProvisionSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!wsName.trim() || !wsSlug.trim()) return;

    setIsProvisioning(true);
    try {
      const created = await provisionWorkspace({
        name: wsName,
        slug: wsSlug,
        description: wsDesc,
      });
      setProfile((prev) =>
        prev ? { ...prev, workspaces: [...prev.workspaces, created] } : null
      );
      setIsProvisionOpen(false);
      setWsName("");
      setWsSlug("");
      setWsDesc("");
      setNotification(`Workspace "${created.name}" provisioned.`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Workspace provisioning failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsProvisioning(false);
    }
  };

  if (isLoading || !profile) {
    return (
      <div className="space-y-6">
        <div className="h-6 w-32 bg-zinc-800 animate-pulse rounded" />
        <Card className="p-6">
          <SkeletonLoader lines={6} />
        </Card>
      </div>
    );
  }

  const seatPct = Math.round((profile.seatsUsed / profile.seatLimit) * 100);

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
            Organization Administration
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            Enterprise organization identity, global security policies, and workspace isolation boundaries.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {notification && (
            <span className="rounded bg-emerald-950/60 border border-emerald-800 px-3 py-1 text-xs text-emerald-400 animate-in fade-in">
              {notification}
            </span>
          )}
          <Button variant="primary" onClick={() => setIsProvisionOpen(true)}>
            + Provision Workspace
          </Button>
        </div>
      </div>

      {/* Overview & Subscription Strip */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="p-5">
          <span className="text-xs font-medium text-zinc-500 uppercase tracking-wide">
            Enterprise Tenant
          </span>
          <p className="mt-2 text-xl font-bold text-zinc-100">{profile.name}</p>
          <p className="text-xs text-zinc-400 font-mono mt-0.5">slug: {profile.slug}</p>
        </Card>

        <Card className="p-5">
          <span className="text-xs font-medium text-zinc-500 uppercase tracking-wide">
            Plan &amp; License
          </span>
          <div className="flex items-center gap-2 mt-2">
            <span className="rounded bg-cyan-950/60 border border-cyan-800 px-2 py-0.5 text-xs font-bold text-cyan-300">
              {profile.tier} TIER
            </span>
            <span className="text-xs text-zinc-400">Active License</span>
          </div>
          <p className="text-xs text-zinc-500 mt-2">Annual enterprise security contract</p>
        </Card>

        <Card className="p-5">
          <div className="flex items-center justify-between text-xs font-medium text-zinc-500 uppercase">
            <span>Seat Utilization</span>
            <span className="font-mono text-zinc-300">{profile.seatsUsed} / {profile.seatLimit}</span>
          </div>
          <div className="mt-3 h-2 w-full rounded-full bg-zinc-800 overflow-hidden">
            <div
              className={`h-full rounded-full ${
                seatPct >= 90 ? "bg-red-500" : seatPct >= 70 ? "bg-amber-500" : "bg-cyan-500"
              }`}
              style={{ width: `${seatPct}%` }}
            />
          </div>
          <p className="text-xs text-zinc-400 mt-2">{seatPct}% licenses assigned</p>
        </Card>
      </div>

      {/* Workspaces Inventory */}
      <Card className="p-6 space-y-4">
        <CardHeader>
          <CardTitle>Isolated Security Workspaces ({profile.workspaces.length})</CardTitle>
          <CardDescription>
            Workspaces provide multi-tenant isolation for distinct environments and compliance boundaries.
          </CardDescription>
        </CardHeader>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {profile.workspaces.map((ws) => (
            <div
              key={ws.id}
              className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 space-y-3 hover:border-zinc-700 transition-colors"
            >
              <div className="flex items-center justify-between">
                <span className="font-bold text-sm text-zinc-200">{ws.name}</span>
                {ws.isDefault && (
                  <span className="rounded bg-zinc-800 border border-zinc-700 px-1.5 py-0.5 text-[10px] text-zinc-300 font-mono">
                    DEFAULT
                  </span>
                )}
              </div>
              <p className="text-xs text-zinc-400 line-clamp-2">{ws.description}</p>
              <div className="pt-2 border-t border-zinc-800/80 flex items-center justify-between text-[11px] text-zinc-500 font-mono">
                <span>{ws.activeAssessmentsCount} Scans Active</span>
                <span>{ws.totalFindingsCount} Findings</span>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Security Policies & Domain Configuration */}
      <Card className="p-6">
        <CardHeader>
          <CardTitle>Organization Security Policies</CardTitle>
          <CardDescription>
            Global access controls enforced across all member identities and workspaces
          </CardDescription>
        </CardHeader>

        <form onSubmit={handleSaveSettings} className="space-y-4 max-w-xl">
          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Primary Corporate Domain
            </label>
            <Input
              type="text"
              value={primaryDomain}
              onChange={(e) => setPrimaryDomain(e.target.value)}
              placeholder="e.g. kelvin-sec.internal"
              required
            />
          </div>

          <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-4 flex items-center justify-between">
            <div>
              <span className="text-sm font-semibold text-zinc-200">
                Enforce Multi-Factor Authentication (2FA)
              </span>
              <p className="text-xs text-zinc-400">
                Require all analysts and engineers to bind hardware security keys or TOTP tokens
              </p>
            </div>
            <input
              type="checkbox"
              checked={enforce2FA}
              onChange={(e) => setEnforce2FA(e.target.checked)}
              className="h-4 w-4 rounded border-zinc-700 bg-zinc-800 text-cyan-500 focus:ring-cyan-500"
            />
          </div>

          <div className="pt-2">
            <Button variant="primary" type="submit" isLoading={isSavingSettings}>
              Save Security Policies
            </Button>
          </div>
        </form>
      </Card>

      {/* Provision Workspace Modal */}
      <Modal
        isOpen={isProvisionOpen}
        onClose={() => setIsProvisionOpen(false)}
        title="Provision New Isolated Workspace"
      >
        <form onSubmit={handleProvisionSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Workspace Display Name <span className="text-red-400">*</span>
            </label>
            <Input
              type="text"
              placeholder="e.g. APAC Cloud Services"
              value={wsName}
              onChange={(e) => {
                setWsName(e.target.value);
                if (!wsSlug) {
                  setWsSlug(e.target.value.toLowerCase().replace(/[^a-z0-9]+/g, "-"));
                }
              }}
              required
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Workspace Slug Identifier <span className="text-red-400">*</span>
            </label>
            <Input
              type="text"
              placeholder="e.g. apac-cloud"
              value={wsSlug}
              onChange={(e) => setWsSlug(e.target.value)}
              required
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Workspace Description
            </label>
            <textarea
              rows={3}
              placeholder="Purpose and scope of this security workspace..."
              value={wsDesc}
              onChange={(e) => setWsDesc(e.target.value)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 p-2.5 text-sm text-zinc-200 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => setIsProvisionOpen(false)} type="button">
              Cancel
            </Button>
            <Button variant="primary" type="submit" isLoading={isProvisioning}>
              Provision Workspace
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
