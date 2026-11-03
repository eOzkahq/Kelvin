export type PermissionAction =
  | "assessments:create"
  | "assessments:read"
  | "assessments:cancel"
  | "assessments:delete"
  | "findings:read"
  | "findings:triage"
  | "findings:suppress"
  | "findings:export"
  | "targets:create"
  | "targets:read"
  | "targets:edit_scope"
  | "targets:delete"
  | "users:invite"
  | "users:manage_roles"
  | "settings:update"
  | "audit:read";

export interface PermissionDefinition {
  action: PermissionAction;
  category: "Assessments" | "Findings" | "Targets" | "Administration";
  label: string;
  description: string;
}

export interface RoleDefinition {
  id: string;
  name: string;
  description: string;
  isSystem: boolean;
  permissions: PermissionAction[];
}

export interface SamlConfig {
  enabled: boolean;
  idpEntityId: string;
  idpSsoUrl: string;
  x509Certificate: string;
  spEntityId: string;
  spAcsUrl: string;
  allowUnsolicited: boolean;
}

export interface OidcConfig {
  enabled: boolean;
  issuerUrl: string;
  clientId: string;
  clientSecret: string;
  scopes: string[];
}

export interface ScimConfig {
  enabled: boolean;
  endpointUrl: string;
  bearerToken: string;
  lastSyncAt?: string;
  syncedGroupsCount: number;
}

export type MfaPolicy = "OPTIONAL" | "ADMINS_ONLY" | "ALL_MEMBERS";

export interface IamConfiguration {
  roles: RoleDefinition[];
  saml: SamlConfig;
  oidc: OidcConfig;
  scim: ScimConfig;
  mfaPolicy: MfaPolicy;
}

export interface CreateCustomRolePayload {
  name: string;
  description: string;
  permissions: PermissionAction[];
}
