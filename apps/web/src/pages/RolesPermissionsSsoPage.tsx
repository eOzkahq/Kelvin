import React, { useEffect, useState, useCallback } from "react";
import {
  fetchIamConfig,
  createCustomRole,
  updateSamlConfig,
  updateOidcConfig,
  updateMfaPolicy,
  rotateScimToken,
  PERMISSION_CATALOG,
  type IamConfiguration,
  type MfaPolicy,
  type PermissionAction,
  type RoleDefinition,
} from "../features/iam";
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

type ActiveTab = "matrix" | "sso" | "scim_mfa";

export default function RolesPermissionsSsoPage() {
  const [iam, setIam] = useState<IamConfiguration | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<ActiveTab>("matrix");
  const [notification, setNotification] = useState<string | null>(null);

  // Custom Role Modal State
  const [isCustomRoleOpen, setIsCustomRoleOpen] = useState(false);
  const [newRoleName, setNewRoleName] = useState("");
  const [newRoleDesc, setNewRoleDesc] = useState("");
  const [selectedPermissions, setSelectedPermissions] = useState<Set<PermissionAction>>(new Set());
  const [isCreatingRole, setIsCreatingRole] = useState(false);

  // SAML Form State
  const [samlEnabled, setSamlEnabled] = useState(false);
  const [samlIdpEntityId, setSamlIdpEntityId] = useState("");
  const [samlIdpSsoUrl, setSamlIdpSsoUrl] = useState("");
  const [samlCert, setSamlCert] = useState("");
  const [isSavingSaml, setIsSavingSaml] = useState(false);

  // OIDC Form State
  const [oidcEnabled, setOidcEnabled] = useState(false);
  const [oidcIssuer, setOidcIssuer] = useState("");
  const [oidcClientId, setOidcClientId] = useState("");
  const [oidcClientSecret, setOidcClientSecret] = useState("");
  const [showOidcSecret, setShowOidcSecret] = useState(false);
  const [isSavingOidc, setIsSavingOidc] = useState(false);

  // MFA & SCIM State
  const [mfaPolicy, setMfaPolicy] = useState<MfaPolicy>("ADMINS_ONLY");
  const [isSavingMfa, setIsSavingMfa] = useState(false);
  const [isRotatingScim, setIsRotatingScim] = useState(false);

  const loadIam = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await fetchIamConfig();
      setIam(data);
      setSamlEnabled(data.saml.enabled);
      setSamlIdpEntityId(data.saml.idpEntityId);
      setSamlIdpSsoUrl(data.saml.idpSsoUrl);
      setSamlCert(data.saml.x509Certificate);

      setOidcEnabled(data.oidc.enabled);
      setOidcIssuer(data.oidc.issuerUrl);
      setOidcClientId(data.oidc.clientId);
      setOidcClientSecret(data.oidc.clientSecret);

      setMfaPolicy(data.mfaPolicy);
    } catch (err) {
      console.error("Failed to load IAM config:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadIam();
  }, [loadIam]);

  const handleCreateRoleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRoleName.trim() || selectedPermissions.size === 0) return;

    setIsCreatingRole(true);
    try {
      const created = await createCustomRole({
        name: newRoleName,
        description: newRoleDesc,
        permissions: Array.from(selectedPermissions),
      });
      setIam((prev) => (prev ? { ...prev, roles: [...prev.roles, created] } : null));
      setIsCustomRoleOpen(false);
      setNewRoleName("");
      setNewRoleDesc("");
      setSelectedPermissions(new Set());
      setNotification(`Custom role "${created.name}" created successfully.`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Role creation failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsCreatingRole(false);
    }
  };

  const handleSaveSaml = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingSaml(true);
    try {
      const updated = await updateSamlConfig({
        enabled: samlEnabled,
        idpEntityId: samlIdpEntityId,
        idpSsoUrl: samlIdpSsoUrl,
        x509Certificate: samlCert,
      });
      setIam((prev) => (prev ? { ...prev, saml: updated } : null));
      setNotification("SAML 2.0 configuration updated.");
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Failed to save SAML config: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsSavingSaml(false);
    }
  };

  const handleSaveOidc = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSavingOidc(true);
    try {
      const updated = await updateOidcConfig({
        enabled: oidcEnabled,
        issuerUrl: oidcIssuer,
        clientId: oidcClientId,
        clientSecret: oidcClientSecret,
      });
      setIam((prev) => (prev ? { ...prev, oidc: updated } : null));
      setNotification("OpenID Connect (OIDC) configuration updated.");
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Failed to save OIDC config: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsSavingOidc(false);
    }
  };

  const handleSaveMfa = async () => {
    setIsSavingMfa(true);
    try {
      const updated = await updateMfaPolicy(mfaPolicy);
      setIam((prev) => (prev ? { ...prev, mfaPolicy: updated } : null));
      setNotification(`MFA Policy updated to: ${updated}`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Failed to update MFA policy: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsSavingMfa(false);
    }
  };

  const handleRotateScim = async () => {
    if (!confirm("Rotating the SCIM token will invalidate existing IdP integration until updated in Okta / Azure AD. Continue?")) return;
    setIsRotatingScim(true);
    try {
      const result = await rotateScimToken();
      setIam((prev) =>
        prev ? { ...prev, scim: { ...prev.scim, bearerToken: result.bearerToken } } : null
      );
      setNotification("SCIM token successfully rotated.");
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Failed to rotate SCIM token: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsRotatingScim(false);
    }
  };

  const togglePermission = (action: PermissionAction) => {
    const next = new Set(selectedPermissions);
    if (next.has(action)) {
      next.delete(action);
    } else {
      next.add(action);
    }
    setSelectedPermissions(next);
  };

  if (isLoading || !iam) {
    return (
      <div className="space-y-6">
        <div className="h-6 w-32 bg-zinc-800 animate-pulse rounded" />
        <Card className="p-6">
          <SkeletonLoader lines={6} />
        </Card>
      </div>
    );
  }

  const categories = ["Assessments", "Findings", "Targets", "Administration"] as const;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
            Roles, Permissions &amp; Single Sign-On (SSO)
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            Fine-grained RBAC matrix, custom role composer, SAML 2.0 / OIDC federation, and SCIM directory sync.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {notification && (
            <span className="rounded bg-emerald-950/60 border border-emerald-800 px-3 py-1 text-xs text-emerald-400 animate-in fade-in">
              {notification}
            </span>
          )}
          {activeTab === "matrix" && (
            <Button variant="primary" onClick={() => setIsCustomRoleOpen(true)}>
              + Create Custom Role
            </Button>
          )}
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex border-b border-zinc-800 gap-2">
        <button
          onClick={() => setActiveTab("matrix")}
          className={`px-4 py-2 text-xs font-semibold border-b-2 transition-colors ${
            activeTab === "matrix"
              ? "border-cyan-500 text-cyan-400"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          Permissions Matrix &amp; Custom Roles ({iam.roles.length})
        </button>
        <button
          onClick={() => setActiveTab("sso")}
          className={`px-4 py-2 text-xs font-semibold border-b-2 transition-colors ${
            activeTab === "sso"
              ? "border-cyan-500 text-cyan-400"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          Single Sign-On (SAML / OIDC)
        </button>
        <button
          onClick={() => setActiveTab("scim_mfa")}
          className={`px-4 py-2 text-xs font-semibold border-b-2 transition-colors ${
            activeTab === "scim_mfa"
              ? "border-cyan-500 text-cyan-400"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          SCIM Directory Sync &amp; MFA
        </button>
      </div>

      {/* Tab 1: Permissions Matrix */}
      {activeTab === "matrix" && (
        <div className="space-y-6">
          <div className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-900/60">
            <table className="w-full text-left text-sm text-zinc-300">
              <thead className="border-b border-zinc-800 bg-zinc-900 text-xs uppercase text-zinc-400">
                <tr>
                  <th className="px-4 py-3 min-w-[260px]">Action &amp; Capability</th>
                  {iam.roles.map((role: RoleDefinition) => (
                    <th key={role.id} className="px-3 py-3 text-center min-w-[120px]">
                      <div className="font-semibold text-zinc-200">{role.name}</div>
                      <span className="text-[10px] text-zinc-500 font-mono">
                        {role.isSystem ? "SYSTEM" : "CUSTOM"}
                      </span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60">
                {categories.map((cat) => (
                  <React.Fragment key={cat}>
                    <tr className="bg-zinc-950/80 font-bold text-xs uppercase tracking-wide text-cyan-400">
                      <td colSpan={iam.roles.length + 1} className="px-4 py-2">
                        {cat}
                      </td>
                    </tr>
                    {PERMISSION_CATALOG.filter((p) => p.category === cat).map((perm) => (
                      <tr key={perm.action} className="hover:bg-zinc-800/20">
                        <td className="px-4 py-2.5">
                          <div className="font-medium text-zinc-200 text-xs">{perm.label}</div>
                          <div className="text-[11px] font-mono text-zinc-500">{perm.action}</div>
                        </td>
                        {iam.roles.map((role: RoleDefinition) => {
                          const hasPerm = role.permissions.includes(perm.action);
                          return (
                            <td key={role.id} className="px-3 py-2.5 text-center">
                              {hasPerm ? (
                                <span className="inline-block text-cyan-400 font-bold text-base">✓</span>
                              ) : (
                                <span className="inline-block text-zinc-700">—</span>
                              )}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 2: SSO Configuration */}
      {activeTab === "sso" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* SAML 2.0 Form */}
          <Card className="p-6 space-y-4">
            <CardHeader>
              <div className="flex items-center justify-between w-full">
                <CardTitle>SAML 2.0 Identity Federation</CardTitle>
                <label className="flex items-center gap-2 cursor-pointer">
                  <span className="text-xs text-zinc-400">Enable SAML</span>
                  <input
                    type="checkbox"
                    checked={samlEnabled}
                    onChange={(e) => setSamlEnabled(e.target.checked)}
                    className="h-4 w-4 rounded border-zinc-700 bg-zinc-800 text-cyan-500"
                  />
                </label>
              </div>
              <CardDescription>
                Authenticate members via Okta, Microsoft Entra ID (Azure AD), PingFederate, or Google Workspace SAML.
              </CardDescription>
            </CardHeader>

            <form onSubmit={handleSaveSaml} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1">
                  Identity Provider Entity ID (Issuer)
                </label>
                <Input
                  type="text"
                  placeholder="e.g. http://www.okta.com/exk..."
                  value={samlIdpEntityId}
                  onChange={(e) => setSamlIdpEntityId(e.target.value)}
                  required={samlEnabled}
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1">
                  Single Sign-On Service URL (SSO Endpoint)
                </label>
                <Input
                  type="url"
                  placeholder="https://identity.company.com/sso/saml"
                  value={samlIdpSsoUrl}
                  onChange={(e) => setSamlIdpSsoUrl(e.target.value)}
                  required={samlEnabled}
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1">
                  IdP X.509 Public Certificate (PEM)
                </label>
                <textarea
                  rows={4}
                  placeholder="-----BEGIN CERTIFICATE-----..."
                  value={samlCert}
                  onChange={(e) => setSamlCert(e.target.value)}
                  className="w-full rounded-md border border-zinc-700 bg-zinc-900 p-2 text-xs font-mono text-zinc-200 focus:border-cyan-500 focus:outline-none"
                  required={samlEnabled}
                />
              </div>

              {/* Service Provider Metadata Box */}
              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-xs space-y-2">
                <span className="text-[10px] font-semibold uppercase text-zinc-400">
                  KELVIN Service Provider (SP) Metadata
                </span>
                <div>
                  <span className="text-zinc-500">SP Entity ID: </span>
                  <code className="text-cyan-300 select-all">{iam.saml.spEntityId}</code>
                </div>
                <div>
                  <span className="text-zinc-500">Assertion Consumer Service (ACS) URL: </span>
                  <code className="text-cyan-300 select-all">{iam.saml.spAcsUrl}</code>
                </div>
              </div>

              <div className="flex justify-end pt-2">
                <Button variant="primary" type="submit" isLoading={isSavingSaml}>
                  Save SAML 2.0 Configuration
                </Button>
              </div>
            </form>
          </Card>

          {/* OIDC Form */}
          <Card className="p-6 space-y-4">
            <CardHeader>
              <div className="flex items-center justify-between w-full">
                <CardTitle>OpenID Connect (OIDC) Federation</CardTitle>
                <label className="flex items-center gap-2 cursor-pointer">
                  <span className="text-xs text-zinc-400">Enable OIDC</span>
                  <input
                    type="checkbox"
                    checked={oidcEnabled}
                    onChange={(e) => setOidcEnabled(e.target.checked)}
                    className="h-4 w-4 rounded border-zinc-700 bg-zinc-800 text-cyan-500"
                  />
                </label>
              </div>
              <CardDescription>
                OIDC discovery integration for Google Cloud Identity, Auth0, Keycloak, or AWS Cognito.
              </CardDescription>
            </CardHeader>

            <form onSubmit={handleSaveOidc} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1">
                  OIDC Issuer Discovery URL
                </label>
                <Input
                  type="url"
                  placeholder="https://accounts.google.com"
                  value={oidcIssuer}
                  onChange={(e) => setOidcIssuer(e.target.value)}
                  required={oidcEnabled}
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1">
                  OAuth 2.0 Client ID
                </label>
                <Input
                  type="text"
                  placeholder="e.g. 123456789-kelvin.apps.googleusercontent.com"
                  value={oidcClientId}
                  onChange={(e) => setOidcClientId(e.target.value)}
                  required={oidcEnabled}
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1">
                  Client Secret
                </label>
                <div className="relative">
                  <Input
                    type={showOidcSecret ? "text" : "password"}
                    value={oidcClientSecret}
                    onChange={(e) => setOidcClientSecret(e.target.value)}
                    required={oidcEnabled}
                  />
                  <button
                    type="button"
                    onClick={() => setShowOidcSecret(!showOidcSecret)}
                    className="absolute right-2.5 top-2.5 text-xs text-zinc-400 hover:text-zinc-200"
                  >
                    {showOidcSecret ? "Hide" : "Reveal"}
                  </button>
                </div>
              </div>

              <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3 text-xs space-y-1">
                <span className="text-[10px] font-semibold uppercase text-zinc-400">
                  Redirect Callback URI
                </span>
                <p className="text-cyan-300 font-mono select-all">
                  https://kelvin-sec.internal/services/kelvin/auth/callback/oidc
                </p>
              </div>

              <div className="flex justify-end pt-2">
                <Button variant="primary" type="submit" isLoading={isSavingOidc}>
                  Save OIDC Configuration
                </Button>
              </div>
            </form>
          </Card>
        </div>
      )}

      {/* Tab 3: SCIM & MFA */}
      {activeTab === "scim_mfa" && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* SCIM 2.0 Directory Sync */}
          <Card className="p-6 space-y-4">
            <CardHeader>
              <CardTitle>SCIM 2.0 Provisioning Directory</CardTitle>
              <CardDescription>
                Automated user provisioning and de-provisioning from Okta or Entra ID SCIM connectors.
              </CardDescription>
            </CardHeader>

            <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-4 space-y-3 text-xs font-mono">
              <div>
                <span className="text-zinc-500">SCIM Endpoint URL: </span>
                <p className="text-cyan-300 mt-1 select-all">{iam.scim.endpointUrl}</p>
              </div>
              <div>
                <span className="text-zinc-500">Bearer Token: </span>
                <p className="text-zinc-300 mt-1 select-all">{iam.scim.bearerToken}</p>
              </div>
              <div className="flex items-center justify-between pt-2 border-t border-zinc-800 text-zinc-400 font-sans">
                <span>Active Synced Groups: <strong className="text-zinc-200">{iam.scim.syncedGroupsCount}</strong></span>
                <span>Last Synced: {iam.scim.lastSyncAt ? new Date(iam.scim.lastSyncAt).toLocaleString() : "Never"}</span>
              </div>
            </div>

            <Button
              variant="secondary"
              onClick={handleRotateScim}
              isLoading={isRotatingScim}
              className="w-full text-amber-400 hover:text-amber-300"
            >
              Rotate SCIM Bearer Token
            </Button>
          </Card>

          {/* MFA Enforcement Policy */}
          <Card className="p-6 space-y-4">
            <CardHeader>
              <CardTitle>Multi-Factor Authentication (MFA) Policy</CardTitle>
              <CardDescription>
                Define mandatory hardware token (FIDO2/WebAuthn) or TOTP policies for enterprise users.
              </CardDescription>
            </CardHeader>

            <div className="space-y-3">
              {[
                {
                  id: "OPTIONAL",
                  title: "Optional Enrollment",
                  desc: "Users decide whether to enable 2FA on their individual accounts.",
                },
                {
                  id: "ADMINS_ONLY",
                  title: "Mandatory for Administrators",
                  desc: "Enforced for OrgAdmin and WorkspaceAdmin identities. Optional for analysts and members.",
                },
                {
                  id: "ALL_MEMBERS",
                  title: "Mandatory for All Members (Zero Trust)",
                  desc: "Enforces 2FA enrollment upon next login for every user across all workspaces.",
                },
              ].map((policy) => (
                <label
                  key={policy.id}
                  className={`flex items-start gap-3 rounded-lg border p-3 cursor-pointer transition-colors ${
                    mfaPolicy === policy.id
                      ? "border-cyan-500 bg-cyan-950/20"
                      : "border-zinc-800 bg-zinc-950/40 hover:border-zinc-700"
                  }`}
                >
                  <input
                    type="radio"
                    name="mfaPolicy"
                    value={policy.id}
                    checked={mfaPolicy === policy.id}
                    onChange={(e) => setMfaPolicy(e.target.value as MfaPolicy)}
                    className="mt-1 h-4 w-4 text-cyan-500"
                  />
                  <div>
                    <span className="text-sm font-semibold text-zinc-200">{policy.title}</span>
                    <p className="text-xs text-zinc-400 mt-0.5">{policy.desc}</p>
                  </div>
                </label>
              ))}
            </div>

            <div className="flex justify-end pt-2">
              <Button variant="primary" onClick={handleSaveMfa} isLoading={isSavingMfa}>
                Apply MFA Policy
              </Button>
            </div>
          </Card>
        </div>
      )}

      {/* Custom Role Composer Modal */}
      <Modal
        isOpen={isCustomRoleOpen}
        onClose={() => setIsCustomRoleOpen(false)}
        title="Compose Custom Security Role"
      >
        <form onSubmit={handleCreateRoleSubmit} className="space-y-4 max-h-[75vh] overflow-y-auto pr-1">
          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Role Name <span className="text-red-400">*</span>
            </label>
            <Input
              type="text"
              placeholder="e.g. Third-Party Penetration Tester"
              value={newRoleName}
              onChange={(e) => setNewRoleName(e.target.value)}
              required
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Description
            </label>
            <Input
              type="text"
              placeholder="Describe access privileges and intended personas..."
              value={newRoleDesc}
              onChange={(e) => setNewRoleDesc(e.target.value)}
            />
          </div>

          <div className="space-y-3">
            <span className="text-xs font-semibold uppercase text-zinc-400">
              Select Granted Permissions ({selectedPermissions.size})
            </span>
            <div className="space-y-2 border border-zinc-800 rounded-lg p-3 bg-zinc-950 max-h-56 overflow-y-auto">
              {PERMISSION_CATALOG.map((perm) => {
                const isSelected = selectedPermissions.has(perm.action);
                return (
                  <label
                    key={perm.action}
                    className="flex items-center justify-between p-2 rounded hover:bg-zinc-900 cursor-pointer text-xs"
                  >
                    <div>
                      <span className="font-medium text-zinc-200">{perm.label}</span>
                      <span className="text-zinc-500 ml-2 font-mono text-[11px]">{perm.action}</span>
                    </div>
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => togglePermission(perm.action)}
                      className="rounded border-zinc-700 bg-zinc-800 text-cyan-500"
                    />
                  </label>
                );
              })}
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => setIsCustomRoleOpen(false)} type="button">
              Cancel
            </Button>
            <Button variant="primary" type="submit" isLoading={isCreatingRole}>
              Create Role
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
