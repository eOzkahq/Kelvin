import { request } from "../../services/api";
import type {
  CreateTeamPayload,
  GlobalRole,
  InviteMemberPayload,
  MemberItem,
  OrganizationProfile,
  ProvisionWorkspacePayload,
  TeamItem,
  WorkspaceSummary,
} from "./types";

let mockOrgProfile: OrganizationProfile = {
  id: "org-kelvin-corp",
  name: "Kelvin Security Systems",
  slug: "kelvin-corp",
  primaryDomain: "kelvin-sec.internal",
  tier: "ENTERPRISE",
  seatLimit: 50,
  seatsUsed: 14,
  enforce2FA: true,
  createdAt: "2026-09-01T00:00:00Z",
  workspaces: [
    {
      id: "ws-primary",
      name: "Primary Enterprise Core",
      slug: "primary-core",
      description: "Default workspace for core platform assessments and findings.",
      isDefault: true,
      activeAssessmentsCount: 2,
      totalFindingsCount: 68,
      createdAt: "2026-09-01T00:00:00Z",
    },
    {
      id: "ws-staging",
      name: "Staging Microservices Cluster",
      slug: "staging-microservices",
      description: "Isolated environment for automated pre-production pipeline scanning.",
      isDefault: false,
      activeAssessmentsCount: 1,
      totalFindingsCount: 12,
      createdAt: "2026-10-10T12:00:00Z",
    },
    {
      id: "ws-payment",
      name: "Payment Gateway PCI Perimeter",
      slug: "payment-pci",
      description: "Dedicated PCI-DSS Tier 1 segmented compliance workspace.",
      isDefault: false,
      activeAssessmentsCount: 0,
      totalFindingsCount: 4,
      createdAt: "2026-10-25T16:00:00Z",
    },
  ],
};

let mockMembersStore: MemberItem[] = [
  {
    id: "usr-01",
    name: "Harsh Dev Jha",
    email: "inkeskdozing@gmail.com",
    role: "OrgAdmin",
    status: "ACTIVE",
    workspaces: ["ws-primary", "ws-staging", "ws-payment"],
    twoFactorEnabled: true,
    lastActiveAt: "2026-11-03T20:30:00Z",
  },
  {
    id: "usr-02",
    name: "Mrinal Prakash",
    email: "mrinalprakashfsd@kelvin.io",
    role: "OrgAdmin",
    status: "ACTIVE",
    workspaces: ["ws-primary", "ws-staging"],
    twoFactorEnabled: true,
    lastActiveAt: "2026-11-03T19:00:00Z",
  },
  {
    id: "usr-03",
    name: "Alice Security Analyst",
    email: "alice@kelvin.io",
    role: "Analyst",
    status: "ACTIVE",
    workspaces: ["ws-primary", "ws-staging"],
    twoFactorEnabled: true,
    lastActiveAt: "2026-11-03T18:15:00Z",
  },
  {
    id: "usr-04",
    name: "Bob DevSecOps",
    email: "bob@kelvin.io",
    role: "WorkspaceAdmin",
    status: "ACTIVE",
    workspaces: ["ws-staging"],
    twoFactorEnabled: true,
    lastActiveAt: "2026-11-02T15:20:00Z",
  },
  {
    id: "usr-05",
    name: "Carol Compliance Auditor",
    email: "carol@kelvin.io",
    role: "Auditor",
    status: "PENDING_INVITE",
    workspaces: ["ws-payment"],
    twoFactorEnabled: false,
    invitedAt: "2026-11-03T10:00:00Z",
  },
];

let mockTeamsStore: TeamItem[] = [
  {
    id: "team-secops",
    name: "Security Operations (SecOps)",
    slug: "secops",
    description: "Perimeter monitoring, alert triage, and incident containment.",
    memberCount: 3,
    members: ["inkeskdozing@gmail.com", "mrinalprakashfsd@kelvin.io", "alice@kelvin.io"],
    leadEmail: "mrinalprakashfsd@kelvin.io",
    createdAt: "2026-09-05T00:00:00Z",
  },
  {
    id: "team-appsec",
    name: "Application Security & Vulnerability Mgmt",
    slug: "appsec",
    description: "SAST/DAST analysis, container security, and code vulnerability mitigation.",
    memberCount: 2,
    members: ["alice@kelvin.io", "bob@kelvin.io"],
    leadEmail: "alice@kelvin.io",
    createdAt: "2026-09-10T00:00:00Z",
  },
  {
    id: "team-compliance",
    name: "Governance, Risk & Compliance (GRC)",
    slug: "grc",
    description: "PCI-DSS, SOC 2, and ISO 27001 evidence verification.",
    memberCount: 1,
    members: ["carol@kelvin.io"],
    leadEmail: "carol@kelvin.io",
    createdAt: "2026-10-01T00:00:00Z",
  },
];

export async function fetchOrganizationProfile(): Promise<OrganizationProfile> {
  try {
    const res = await request<OrganizationProfile>("/organization");
    if (res && res.id) return res;
  } catch {
    // Local fallback
  }
  return { ...mockOrgProfile, workspaces: [...mockOrgProfile.workspaces] };
}

export async function updateOrganizationProfile(
  updates: Partial<OrganizationProfile>
): Promise<OrganizationProfile> {
  try {
    const res = await request<OrganizationProfile>("/organization", {
      method: "PATCH",
      body: JSON.stringify(updates),
    });
    if (res && res.id) return res;
  } catch {
    // Local fallback
  }
  mockOrgProfile = { ...mockOrgProfile, ...updates };
  return { ...mockOrgProfile };
}

export async function provisionWorkspace(
  payload: ProvisionWorkspacePayload
): Promise<WorkspaceSummary> {
  try {
    const res = await request<WorkspaceSummary>("/organization/workspaces", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (res && res.id) return res;
  } catch {
    // Local fallback
  }

  const newWs: WorkspaceSummary = {
    id: `ws-${Date.now().toString().slice(-4)}`,
    name: payload.name.trim(),
    slug: payload.slug.trim(),
    description: payload.description.trim(),
    isDefault: false,
    activeAssessmentsCount: 0,
    totalFindingsCount: 0,
    createdAt: new Date().toISOString(),
  };

  mockOrgProfile.workspaces.push(newWs);
  return newWs;
}

export async function fetchMembers(): Promise<MemberItem[]> {
  try {
    const res = await request<MemberItem[]>("/members");
    if (res && Array.isArray(res)) return res;
  } catch {
    // Local fallback
  }
  return [...mockMembersStore];
}

export async function inviteMember(payload: InviteMemberPayload): Promise<MemberItem> {
  if (!payload.email || !payload.email.includes("@")) {
    throw new Error("A valid email address is required for invitation.");
  }

  try {
    const res = await request<MemberItem>("/members/invite", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (res && res.id) return res;
  } catch {
    // Local fallback
  }

  const newMember: MemberItem = {
    id: `usr-${Date.now().toString().slice(-4)}`,
    name: payload.name || payload.email.split("@")[0],
    email: payload.email.toLowerCase().trim(),
    role: payload.role,
    status: "PENDING_INVITE",
    workspaces: payload.workspaces,
    twoFactorEnabled: false,
    invitedAt: new Date().toISOString(),
  };

  mockMembersStore.push(newMember);
  return newMember;
}

export async function updateMemberRole(
  memberId: string,
  newRole: GlobalRole
): Promise<MemberItem> {
  const memberIndex = mockMembersStore.findIndex((m) => m.id === memberId);
  if (memberIndex === -1) throw new Error("Member not found");

  const member = mockMembersStore[memberIndex];
  // Guard: Check if reducing last OrgAdmin
  if (member.role === "OrgAdmin" && newRole !== "OrgAdmin") {
    const adminCount = mockMembersStore.filter(
      (m) => m.role === "OrgAdmin" && m.status === "ACTIVE"
    ).length;
    if (adminCount <= 1) {
      throw new Error("Cannot demote the last remaining Organization Administrator.");
    }
  }

  try {
    const res = await request<MemberItem>(`/members/${memberId}/role`, {
      method: "PATCH",
      body: JSON.stringify({ role: newRole }),
    });
    if (res && res.id) return res;
  } catch {
    // Local fallback
  }

  mockMembersStore[memberIndex] = { ...member, role: newRole };
  return mockMembersStore[memberIndex];
}

export async function removeMember(memberId: string): Promise<boolean> {
  const member = mockMembersStore.find((m) => m.id === memberId);
  if (!member) throw new Error("Member not found");

  if (member.role === "OrgAdmin") {
    const adminCount = mockMembersStore.filter(
      (m) => m.role === "OrgAdmin" && m.status === "ACTIVE"
    ).length;
    if (adminCount <= 1) {
      throw new Error("Cannot remove the last remaining Organization Administrator.");
    }
  }

  try {
    await request(`/members/${memberId}`, { method: "DELETE" });
  } catch {
    // Local fallback
  }

  mockMembersStore = mockMembersStore.filter((m) => m.id !== memberId);
  return true;
}

export async function fetchTeams(): Promise<TeamItem[]> {
  try {
    const res = await request<TeamItem[]>("/teams");
    if (res && Array.isArray(res)) return res;
  } catch {
    // Local fallback
  }
  return [...mockTeamsStore];
}

export async function createTeam(payload: CreateTeamPayload): Promise<TeamItem> {
  if (!payload.name.trim()) throw new Error("Team name is required");

  try {
    const res = await request<TeamItem>("/teams", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (res && res.id) return res;
  } catch {
    // Local fallback
  }

  const newTeam: TeamItem = {
    id: `team-${Date.now().toString().slice(-4)}`,
    name: payload.name.trim(),
    slug: payload.name.toLowerCase().replace(/[^a-z0-9]+/g, "-"),
    description: payload.description.trim(),
    memberCount: 1,
    members: [payload.leadEmail],
    leadEmail: payload.leadEmail,
    createdAt: new Date().toISOString(),
  };

  mockTeamsStore.push(newTeam);
  return newTeam;
}

export function resetMockOrganization(): void {
  mockMembersStore = mockMembersStore.map((m) => ({ ...m }));
  mockTeamsStore = mockTeamsStore.map((t) => ({ ...t, members: [...t.members] }));
}
