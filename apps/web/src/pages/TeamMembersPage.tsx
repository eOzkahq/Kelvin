import React, { useEffect, useState, useCallback } from "react";
import {
  fetchMembers,
  fetchTeams,
  inviteMember,
  updateMemberRole,
  removeMember,
  createTeam,
  type MemberItem,
  type TeamItem,
  type GlobalRole,
} from "../features/organization";
import {
  Button,
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  EmptyState,
  Input,
  Modal,
  SkeletonLoader,
} from "../components/ui";

export default function TeamMembersPage() {
  const [members, setMembers] = useState<MemberItem[]>([]);
  const [teams, setTeams] = useState<TeamItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Filter
  const [searchQuery, setSearchQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState<string>("");

  // Modals
  const [isInviteOpen, setIsInviteOpen] = useState(false);
  const [isCreateTeamOpen, setIsCreateTeamOpen] = useState(false);

  // Invite Form
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteName, setInviteName] = useState("");
  const [inviteRole, setInviteRole] = useState<GlobalRole>("Analyst");
  const [isInviting, setIsInviting] = useState(false);

  // Create Team Form
  const [teamName, setTeamName] = useState("");
  const [teamDesc, setTeamDesc] = useState("");
  const [teamLead, setTeamLead] = useState("");
  const [isCreatingTeam, setIsCreatingTeam] = useState(false);

  const [notification, setNotification] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [m, t] = await Promise.all([fetchMembers(), fetchTeams()]);
      setMembers(m);
      setTeams(t);
    } catch (err) {
      console.error("Failed to load members/teams:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleInviteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsInviting(true);
    try {
      const created = await inviteMember({
        email: inviteEmail,
        name: inviteName,
        role: inviteRole,
        workspaces: ["ws-primary"],
      });
      setMembers((prev) => [...prev, created]);
      setIsInviteOpen(false);
      setInviteEmail("");
      setInviteName("");
      setNotification(`Invitation sent to ${created.email}.`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Invitation failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsInviting(false);
    }
  };

  const handleCreateTeamSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsCreatingTeam(true);
    try {
      const created = await createTeam({
        name: teamName,
        description: teamDesc,
        leadEmail: teamLead || "inkeskdozing@gmail.com",
      });
      setTeams((prev) => [...prev, created]);
      setIsCreateTeamOpen(false);
      setTeamName("");
      setTeamDesc("");
      setNotification(`Team "${created.name}" created.`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Team creation failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsCreatingTeam(false);
    }
  };

  const handleRoleChange = async (memberId: string, newRole: GlobalRole) => {
    try {
      const updated = await updateMemberRole(memberId, newRole);
      setMembers((prev) => prev.map((m) => (m.id === updated.id ? updated : m)));
      setNotification(`Role updated to ${newRole}`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Role update failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleRemoveMember = async (memberId: string, email: string) => {
    if (!confirm(`Are you sure you want to revoke access for ${email}?`)) return;
    try {
      await removeMember(memberId);
      setMembers((prev) => prev.filter((m) => m.id !== memberId));
      setNotification(`Revoked access for ${email}`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Remove member failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const filteredMembers = members.filter((m) => {
    const matchesSearch =
      !searchQuery ||
      m.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      m.email.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesRole = !roleFilter || m.role === roleFilter;
    return matchesSearch && matchesRole;
  });

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
            Team &amp; Member Directory
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            Enterprise team organization, member invitations, role authorization, and security compliance.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {notification && (
            <span className="rounded bg-emerald-950/60 border border-emerald-800 px-3 py-1 text-xs text-emerald-400 animate-in fade-in">
              {notification}
            </span>
          )}
          <Button variant="secondary" onClick={() => setIsCreateTeamOpen(true)}>
            + Create Team
          </Button>
          <Button variant="primary" onClick={() => setIsInviteOpen(true)}>
            + Invite Member
          </Button>
        </div>
      </div>

      {/* Cross-Functional Teams Grid */}
      <Card className="p-6 space-y-4">
        <CardHeader>
          <CardTitle>Cross-Functional Security Teams ({teams.length})</CardTitle>
          <CardDescription>
            Organize engineers and analysts into operational squads for finding assignment and SLA tracking.
          </CardDescription>
        </CardHeader>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {teams.map((t) => (
            <div
              key={t.id}
              className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 space-y-2 hover:border-zinc-700 transition-colors"
            >
              <div className="flex items-center justify-between">
                <span className="font-bold text-sm text-zinc-200">{t.name}</span>
                <span className="rounded-full bg-zinc-800 px-2 py-0.5 text-[10px] font-mono text-zinc-400">
                  {t.memberCount} members
                </span>
              </div>
              <p className="text-xs text-zinc-400">{t.description}</p>
              <div className="pt-2 text-[11px] text-zinc-500 font-mono">
                Team Lead: <span className="text-zinc-300">{t.leadEmail}</span>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Filter Bar */}
      <Card className="p-4 space-y-3">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-12">
          <div className="md:col-span-8">
            <Input
              type="text"
              placeholder="Search members by name or corporate email..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div className="md:col-span-4">
            <select
              value={roleFilter}
              onChange={(e) => setRoleFilter(e.target.value)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Roles</option>
              <option value="OrgAdmin">Organization Admin</option>
              <option value="WorkspaceAdmin">Workspace Admin</option>
              <option value="Analyst">Security Analyst</option>
              <option value="Auditor">Compliance Auditor</option>
              <option value="Member">Team Member</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Member Directory Table */}
      <div className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-900/60">
        <table className="w-full text-left text-sm text-zinc-300">
          <thead className="border-b border-zinc-800 bg-zinc-900 text-xs uppercase text-zinc-400">
            <tr>
              <th className="px-4 py-3">Member Name &amp; Email</th>
              <th className="px-4 py-3">Global Role</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">2FA Status</th>
              <th className="px-4 py-3">Assigned Workspaces</th>
              <th className="px-4 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800/60">
            {isLoading ? (
              <tr>
                <td colSpan={6} className="p-4">
                  <SkeletonLoader lines={5} />
                </td>
              </tr>
            ) : filteredMembers.length === 0 ? (
              <tr>
                <td colSpan={6} className="p-8">
                  <EmptyState
                    title="No Members Found"
                    description="No organization members match your search criteria."
                    actionLabel="Invite Member"
                    onAction={() => setIsInviteOpen(true)}
                  />
                </td>
              </tr>
            ) : (
              filteredMembers.map((member) => (
                <tr key={member.id} className="hover:bg-zinc-800/30">
                  <td className="px-4 py-3">
                    <div className="font-semibold text-zinc-100">{member.name}</div>
                    <code className="text-xs font-mono text-zinc-400">{member.email}</code>
                  </td>
                  <td className="px-4 py-3">
                    <select
                      value={member.role}
                      onChange={(e) =>
                        handleRoleChange(member.id, e.target.value as GlobalRole)
                      }
                      className="rounded border border-zinc-800 bg-zinc-900 px-2 py-1 text-xs text-zinc-200 focus:outline-none"
                    >
                      <option value="OrgAdmin">OrgAdmin</option>
                      <option value="WorkspaceAdmin">WorkspaceAdmin</option>
                      <option value="Analyst">Analyst</option>
                      <option value="Auditor">Auditor</option>
                      <option value="Member">Member</option>
                    </select>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`rounded px-2 py-0.5 text-xs font-medium ${
                        member.status === "ACTIVE"
                          ? "bg-emerald-950/60 border border-emerald-800 text-emerald-300"
                          : "bg-amber-950/60 border border-amber-800 text-amber-300"
                      }`}
                    >
                      {member.status.replace("_", " ")}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {member.twoFactorEnabled ? (
                      <span className="text-emerald-400 font-semibold">✓ Enforced</span>
                    ) : (
                      <span className="text-amber-400">⚠ Not Enabled</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs font-mono text-zinc-400">
                    {member.workspaces.join(", ")}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => handleRemoveMember(member.id, member.email)}
                      className="text-zinc-500 hover:text-red-400"
                    >
                      Remove
                    </Button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Invite Member Modal */}
      <Modal
        isOpen={isInviteOpen}
        onClose={() => setIsInviteOpen(false)}
        title="Invite New Organization Member"
      >
        <form onSubmit={handleInviteSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Corporate Email Address <span className="text-red-400">*</span>
            </label>
            <Input
              type="email"
              placeholder="e.g. security-engineer@kelvin-sec.internal"
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              required
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">Full Name</label>
            <Input
              type="text"
              placeholder="e.g. Jane Doe"
              value={inviteName}
              onChange={(e) => setInviteName(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">Assigned Role</label>
            <select
              value={inviteRole}
              onChange={(e) => setInviteRole(e.target.value as GlobalRole)}
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm text-zinc-200 focus:outline-none"
            >
              <option value="Analyst">Security Analyst (Execute assessments &amp; triage)</option>
              <option value="WorkspaceAdmin">Workspace Administrator (Manage targets &amp; rules)</option>
              <option value="Auditor">Compliance Auditor (Read-only reports)</option>
              <option value="OrgAdmin">Organization Administrator (Full root privileges)</option>
              <option value="Member">Team Member (Remediation contributor)</option>
            </select>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => setIsInviteOpen(false)} type="button">
              Cancel
            </Button>
            <Button variant="primary" type="submit" isLoading={isInviting}>
              Send Invitation
            </Button>
          </div>
        </form>
      </Modal>

      {/* Create Team Modal */}
      <Modal
        isOpen={isCreateTeamOpen}
        onClose={() => setIsCreateTeamOpen(false)}
        title="Create Cross-Functional Team"
      >
        <form onSubmit={handleCreateTeamSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Team Name <span className="text-red-400">*</span>
            </label>
            <Input
              type="text"
              placeholder="e.g. Cloud Infrastructure Security"
              value={teamName}
              onChange={(e) => setTeamName(e.target.value)}
              required
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Team Description
            </label>
            <Input
              type="text"
              placeholder="Scope and purpose of this squad..."
              value={teamDesc}
              onChange={(e) => setTeamDesc(e.target.value)}
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Team Lead Email
            </label>
            <Input
              type="email"
              placeholder="e.g. lead@kelvin.io"
              value={teamLead}
              onChange={(e) => setTeamLead(e.target.value)}
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => setIsCreateTeamOpen(false)} type="button">
              Cancel
            </Button>
            <Button variant="primary" type="submit" isLoading={isCreatingTeam}>
              Create Team
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
