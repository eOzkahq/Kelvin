import { request } from "../../services/api";
import type {
  CreateCustomRolePayload,
  IamConfiguration,
  MfaPolicy,
  OidcConfig,
  PermissionDefinition,
  RoleDefinition,
  SamlConfig,
} from "./types";

export const PERMISSION_CATALOG: PermissionDefinition[] = [
  { action: "assessments:create", category: "Assessments", label: "Launch Assessments", description: "Schedule and execute security assessment sweeps" },
  { action: "assessments:read", category: "Assessments", label: "View Assessments", description: "Inspect assessment progress and terminal logs" },
  { action: "assessments:cancel", category: "Assessments", label: "Cancel Assessments", description: "Dispatch cancellation SIGTERM to running worker jobs" },
  { action: "assessments:delete", category: "Assessments", label: "Delete Assessments", description: "Permanently delete historical scan manifests" },

  { action: "findings:read", category: "Findings", label: "View Findings", description: "Explore findings catalog and raw evidence payloads" },
  { action: "findings:triage", category: "Findings", label: "Triage & Resolve", description: "Transition vulnerability lifecycle states and assign owners" },
  { action: "findings:suppress", category: "Findings", label: "Accept Risk / Suppress", description: "Flag vulnerabilities as False Positive or Accepted Risk" },
  { action: "findings:export", category: "Findings", label: "Export Findings", description: "Download CSV, JSON, and PDF audit reports" },

  { action: "targets:create", category: "Targets", label: "Register Targets", description: "Onboard new domains, IPs, URLs, and CIDR ranges" },
  { action: "targets:read", category: "Targets", label: "View Target Assets", description: "Inspect attack surface inventory" },
  { action: "targets:edit_scope", category: "Targets", label: "Edit Scope Rules", description: "Configure allowed ports and excluded subpath guardrails" },
  { action: "targets:delete", category: "Targets", label: "Delete Targets", description: "Remove targets from attack surface inventory" },

  { action: "users:invite", category: "Administration", label: "Invite Members", description: "Send invitations to join organization workspaces" },
  { action: "users:manage_roles", category: "Administration", label: "Manage Roles & SSO", description: "Configure RBAC permissions and identity providers" },
  { action: "settings:update", category: "Administration", label: "Platform Settings", description: "Configure concurrency quotas and retention policies" },
  { action: "audit:read", category: "Administration", label: "View Audit Logs", description: "Inspect tamper-evident cryptographic activity logs" },
];

let mockIamState: IamConfiguration = {
  roles: [
    {
      id: "role-org-admin",
      name: "Organization Administrator",
      description: "Full unconstrained administrative privileges across all workspaces.",
      isSystem: true,
      permissions: PERMISSION_CATALOG.map((p) => p.action),
    },
    {
      id: "role-ws-admin",
      name: "Workspace Administrator",
      description: "Manage targets, scope guardrails, and launch scans within assigned workspaces.",
      isSystem: true,
      permissions: [
        "assessments:create", "assessments:read", "assessments:cancel",
        "findings:read", "findings:triage", "findings:export",
        "targets:create", "targets:read", "targets:edit_scope",
        "users:invite", "audit:read",
      ],
    },
    {
      id: "role-analyst",
      name: "Security Analyst",
      description: "Perform assessments, triage vulnerabilities, and export remediation reports.",
      isSystem: true,
      permissions: [
        "assessments:create", "assessments:read",
        "findings:read", "findings:triage", "findings:export",
        "targets:read",
      ],
    },
    {
      id: "role-auditor",
      name: "Compliance Auditor",
      description: "Read-only access to findings, assessment manifests, and cryptographic audit logs.",
      isSystem: true,
      permissions: [
        "assessments:read", "findings:read", "findings:export", "targets:read", "audit:read",
      ],
    },
    {
      id: "role-member",
      name: "Team Member",
      description: "View assigned remediation tasks and collaborate on vulnerability notes.",
      isSystem: true,
      permissions: ["findings:read", "targets:read"],
    },
  ],
  saml: {
    enabled: true,
    idpEntityId: "http://www.okta.com/exk9823487123kelvin",
    idpSsoUrl: "https://kelvin-security.okta.com/app/kelvin/exk9823487123kelvin/sso/saml",
    x509Certificate: "-----BEGIN CERTIFICATE-----\nMIIDpDCCAoygAwIBAgIGAY87...[TRUNCATED_MOCK_CERT]...Q==\n-----END CERTIFICATE-----",
    spEntityId: "https://kelvin-sec.internal/services/kelvin/saml/metadata",
    spAcsUrl: "https://kelvin-sec.internal/services/kelvin/saml/acs",
    allowUnsolicited: false,
  },
  oidc: {
    enabled: false,
    issuerUrl: "https://accounts.google.com",
    clientId: "7823467812-kelvin-enterprise.apps.googleusercontent.com",
    clientSecret: "GOCSPX-mocked_secret_key_99812",
    scopes: ["openid", "profile", "email"],
  },
  scim: {
    enabled: true,
    endpointUrl: "https://kelvin-sec.internal/api/v1/scim/v2",
    bearerToken: "scim_tok_8471b3e9a12c45f8910d",
    lastSyncAt: "2026-11-03T19:45:00Z",
    syncedGroupsCount: 4,
  },
  mfaPolicy: "ADMINS_ONLY",
};

export async function fetchIamConfig(): Promise<IamConfiguration> {
  try {
    const res = await request<IamConfiguration>("/iam/config");
    if (res && res.roles) return res;
  } catch {
    // Local fallback
  }
  return {
    ...mockIamState,
    roles: [...mockIamState.roles],
  };
}

export async function createCustomRole(payload: CreateCustomRolePayload): Promise<RoleDefinition> {
  if (!payload.name.trim()) throw new Error("Role name is required");
  if (!payload.permissions.length) throw new Error("Role must have at least one permission");

  try {
    const res = await request<RoleDefinition>("/iam/roles", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (res && res.id) return res;
  } catch {
    // Local fallback
  }

  const newRole: RoleDefinition = {
    id: `role-custom-${Date.now().toString().slice(-4)}`,
    name: payload.name.trim(),
    description: payload.description.trim(),
    isSystem: false,
    permissions: payload.permissions,
  };

  mockIamState.roles.push(newRole);
  return newRole;
}

export async function updateSamlConfig(config: Partial<SamlConfig>): Promise<SamlConfig> {
  try {
    const res = await request<SamlConfig>("/iam/sso/saml", {
      method: "PUT",
      body: JSON.stringify(config),
    });
    if (res && res.spAcsUrl) return res;
  } catch {
    // Local fallback
  }

  mockIamState.saml = { ...mockIamState.saml, ...config };
  return mockIamState.saml;
}

export async function updateOidcConfig(config: Partial<OidcConfig>): Promise<OidcConfig> {
  try {
    const res = await request<OidcConfig>("/iam/sso/oidc", {
      method: "PUT",
      body: JSON.stringify(config),
    });
    if (res && res.clientId) return res;
  } catch {
    // Local fallback
  }

  mockIamState.oidc = { ...mockIamState.oidc, ...config };
  return mockIamState.oidc;
}

export async function updateMfaPolicy(policy: MfaPolicy): Promise<MfaPolicy> {
  try {
    const res = await request<{ policy: MfaPolicy }>("/iam/policies/mfa", {
      method: "PATCH",
      body: JSON.stringify({ policy }),
    });
    if (res && res.policy) return res.policy;
  } catch {
    // Local fallback
  }

  mockIamState.mfaPolicy = policy;
  return policy;
}

export async function rotateScimToken(): Promise<{ bearerToken: string }> {
  try {
    const res = await request<{ bearerToken: string }>("/iam/scim/rotate-token", {
      method: "POST",
    });
    if (res && res.bearerToken) return res;
  } catch {
    // Local fallback
  }

  const newToken = `scim_tok_${Math.random().toString(16).substring(2)}${Math.random().toString(16).substring(2)}`;
  mockIamState.scim.bearerToken = newToken;
  return { bearerToken: newToken };
}

export function resetMockIam(): void {
  mockIamState = {
    ...mockIamState,
    roles: mockIamState.roles.map((r) => ({ ...r, permissions: [...r.permissions] })),
  };
}
