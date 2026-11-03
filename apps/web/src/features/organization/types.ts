export type GlobalRole =
  | "OrgAdmin"
  | "WorkspaceAdmin"
  | "Analyst"
  | "Auditor"
  | "Member";

export type MemberStatus = "ACTIVE" | "PENDING_INVITE" | "SUSPENDED";

export interface WorkspaceSummary {
  id: string;
  name: string;
  slug: string;
  description: string;
  isDefault: boolean;
  activeAssessmentsCount: number;
  totalFindingsCount: number;
  createdAt: string;
}

export interface OrganizationProfile {
  id: string;
  name: string;
  slug: string;
  primaryDomain: string;
  tier: "ENTERPRISE" | "BUSINESS" | "COMMUNITY";
  seatLimit: number;
  seatsUsed: number;
  enforce2FA: boolean;
  createdAt: string;
  workspaces: WorkspaceSummary[];
}

export interface MemberItem {
  id: string;
  name: string;
  email: string;
  role: GlobalRole;
  status: MemberStatus;
  workspaces: string[];
  twoFactorEnabled: boolean;
  invitedAt?: string;
  lastActiveAt?: string;
}

export interface TeamItem {
  id: string;
  name: string;
  slug: string;
  description: string;
  memberCount: number;
  members: string[]; // member emails
  leadEmail: string;
  createdAt: string;
}

export interface InviteMemberPayload {
  email: string;
  name: string;
  role: GlobalRole;
  workspaces: string[];
}

export interface CreateTeamPayload {
  name: string;
  description: string;
  leadEmail: string;
}

export interface ProvisionWorkspacePayload {
  name: string;
  slug: string;
  description: string;
}
