import { describe, it, expect, beforeEach } from "vitest";
import {
  fetchIamConfig,
  createCustomRole,
  updateSamlConfig,
  updateOidcConfig,
  updateMfaPolicy,
  rotateScimToken,
  resetMockIam,
} from "./iamApi";

describe("Roles, Permissions & SSO Management (FE-14)", () => {
  beforeEach(() => {
    resetMockIam();
  });

  it("retrieves IAM configuration including system roles and SSO providers", async () => {
    const config = await fetchIamConfig();
    expect(config).toBeDefined();
    expect(config.roles.length).toBeGreaterThanOrEqual(5);

    const orgAdmin = config.roles.find((r) => r.id === "role-org-admin");
    expect(orgAdmin?.isSystem).toBe(true);
    expect(orgAdmin?.permissions.length).toBeGreaterThan(10);

    expect(config.saml.spAcsUrl).toBeDefined();
    expect(config.oidc.scopes).toContain("openid");
  });

  it("composes custom security role with granular permissions", async () => {
    const customRole = await createCustomRole({
      name: "Third-Party PenTester",
      description: "External auditor with limited scan and export capabilities",
      permissions: ["assessments:read", "findings:read", "findings:export"],
    });

    expect(customRole.id).toBeDefined();
    expect(customRole.isSystem).toBe(false);
    expect(customRole.permissions).toEqual([
      "assessments:read",
      "findings:read",
      "findings:export",
    ]);

    const updatedConfig = await fetchIamConfig();
    expect(updatedConfig.roles.some((r) => r.id === customRole.id)).toBe(true);
  });

  it("rejects custom role creation without name or permissions", async () => {
    await expect(
      createCustomRole({
        name: "",
        description: "Empty name",
        permissions: ["findings:read"],
      })
    ).rejects.toThrow("Role name is required");

    await expect(
      createCustomRole({
        name: "No Permissions",
        description: "Empty permissions",
        permissions: [],
      })
    ).rejects.toThrow("at least one permission");
  });

  it("updates SAML 2.0 federation metadata", async () => {
    const updated = await updateSamlConfig({
      enabled: true,
      idpEntityId: "https://auth.company.corp/saml/idp",
      idpSsoUrl: "https://auth.company.corp/saml/sso",
    });

    expect(updated.enabled).toBe(true);
    expect(updated.idpEntityId).toBe("https://auth.company.corp/saml/idp");
  });

  it("updates OpenID Connect (OIDC) client parameters", async () => {
    const updated = await updateOidcConfig({
      enabled: true,
      issuerUrl: "https://accounts.google.com",
      clientId: "test-client-id-998",
    });

    expect(updated.enabled).toBe(true);
    expect(updated.clientId).toBe("test-client-id-998");
  });

  it("enforces enterprise MFA policy transitions", async () => {
    const policy = await updateMfaPolicy("ALL_MEMBERS");
    expect(policy).toBe("ALL_MEMBERS");

    const config = await fetchIamConfig();
    expect(config.mfaPolicy).toBe("ALL_MEMBERS");
  });

  it("rotates SCIM 2.0 directory bearer token", async () => {
    const initial = (await fetchIamConfig()).scim.bearerToken;
    const { bearerToken } = await rotateScimToken();

    expect(bearerToken).toBeDefined();
    expect(bearerToken).not.toBe(initial);
    expect(bearerToken).toContain("scim_tok_");
  });
});
