import { describe, it, expect, beforeEach } from "vitest";
import {
  fetchOrganizationProfile,
  updateOrganizationProfile,
  provisionWorkspace,
  fetchMembers,
  inviteMember,
  updateMemberRole,
  removeMember,
  fetchTeams,
  createTeam,
  resetMockOrganization,
} from "./orgApi";

describe("Organization & Team Management (FE-13)", () => {
  beforeEach(() => {
    resetMockOrganization();
  });

  it("retrieves organization profile with isolated workspaces", async () => {
    const profile = await fetchOrganizationProfile();
    expect(profile).toBeDefined();
    expect(profile.name).toBe("Kelvin Security Systems");
    expect(profile.tier).toBe("ENTERPRISE");
    expect(profile.workspaces.length).toBeGreaterThan(0);
  });

  it("updates security policies such as 2FA enforcement", async () => {
    const updated = await updateOrganizationProfile({
      enforce2FA: true,
      primaryDomain: "corp.kelvin-sec.internal",
    });
    expect(updated.enforce2FA).toBe(true);
    expect(updated.primaryDomain).toBe("corp.kelvin-sec.internal");
  });

  it("provisions a new isolated security workspace", async () => {
    const ws = await provisionWorkspace({
      name: "Cloud Edge Production",
      slug: "cloud-edge-prod",
      description: "Production perimeter scanning partition",
    });
    expect(ws.id).toBeDefined();
    expect(ws.slug).toBe("cloud-edge-prod");

    const profile = await fetchOrganizationProfile();
    expect(profile.workspaces.some((w) => w.slug === "cloud-edge-prod")).toBe(true);
  });

  it("retrieves member directory with role and 2FA status", async () => {
    const members = await fetchMembers();
    expect(members).toBeDefined();
    expect(members.length).toBeGreaterThan(0);

    const first = members[0];
    expect(first.email).toBeDefined();
    expect(first.role).toBeDefined();
    expect(typeof first.twoFactorEnabled).toBe("boolean");
  });

  it("invites new member with valid email and assigned role", async () => {
    const invited = await inviteMember({
      email: "new-engineer@kelvin-sec.internal",
      name: "New Engineer",
      role: "Analyst",
      workspaces: ["ws-primary"],
    });

    expect(invited.id).toBeDefined();
    expect(invited.status).toBe("PENDING_INVITE");
    expect(invited.role).toBe("Analyst");
  });

  it("rejects member invitation with invalid email", async () => {
    await expect(
      inviteMember({
        email: "not-an-email",
        name: "Invalid",
        role: "Member",
        workspaces: [],
      })
    ).rejects.toThrow("valid email address is required");
  });

  it("updates member role and prevents demotion of the last OrgAdmin", async () => {
    // Normal role update
    const updated = await updateMemberRole("usr-03", "WorkspaceAdmin");
    expect(updated.role).toBe("WorkspaceAdmin");

    // Guard check: demote all org admins down to 1
    const members = await fetchMembers();
    const orgAdmins = members.filter((m) => m.role === "OrgAdmin");
    expect(orgAdmins.length).toBeGreaterThanOrEqual(2);

    // Demote one OrgAdmin
    await updateMemberRole(orgAdmins[0].id, "Analyst");

    // Demoting the final OrgAdmin should fail
    await expect(updateMemberRole(orgAdmins[1].id, "Analyst")).rejects.toThrow(
      "Cannot demote the last remaining Organization Administrator"
    );
  });

  it("removes a standard member and enforces protection for the last OrgAdmin", async () => {
    // Remove analyst
    const removed = await removeMember("usr-03");
    expect(removed).toBe(true);
    const members = await fetchMembers();
    expect(members.some((m) => m.id === "usr-03")).toBe(false);

    // Protection check
    const orgAdmins = members.filter((m) => m.role === "OrgAdmin");
    if (orgAdmins.length > 1) {
      await removeMember(orgAdmins[0].id);
    }
    const finalAdmin = (await fetchMembers()).find((m) => m.role === "OrgAdmin");
    if (finalAdmin) {
      await expect(removeMember(finalAdmin.id)).rejects.toThrow(
        "Cannot remove the last remaining Organization Administrator"
      );
    }
  });

  it("creates a cross-functional security team", async () => {
    const team = await createTeam({
      name: "Red Team Assessment Squad",
      description: "Adversary simulation and offensive penetration testing",
      leadEmail: "inkeskdozing@gmail.com",
    });

    expect(team.id).toBeDefined();
    expect(team.name).toBe("Red Team Assessment Squad");
    expect(team.leadEmail).toBe("inkeskdozing@gmail.com");

    const teams = await fetchTeams();
    expect(teams.some((t) => t.id === team.id)).toBe(true);
  });
});
