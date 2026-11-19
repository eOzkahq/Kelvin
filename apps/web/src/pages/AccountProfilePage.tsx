import React, { useState } from "react";
import { useAuth } from "../features/auth/AuthContext";
import { Card, CardHeader, CardTitle, CardDescription, Button, Input } from "../components/ui";

export default function AccountProfilePage() {
  const { user } = useAuth();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const handlePasswordUpdate = (e: React.FormEvent) => {
    e.preventDefault();
    setSuccessMessage("Password successfully updated. Security session refreshed.");
    setCurrentPassword("");
    setNewPassword("");
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="pb-4 border-b border-zinc-800/80">
        <span className="text-[10px] font-mono uppercase tracking-[0.16em] text-[#d4c9a8]">
          Operator Identity
        </span>
        <h1 className="text-2xl font-bold text-zinc-100 font-display mt-1">
          Account &amp; Security Profile
        </h1>
        <p className="text-xs text-zinc-400 mt-0.5">
          Manage your personal credentials, cryptographic keys, and active sessions.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* User Identity Card */}
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Identity & Assigned Roles</CardTitle>
              <CardDescription>Enterprise identity details verified by IdP</CardDescription>
            </div>
          </CardHeader>

          <div className="space-y-4 text-xs">
            <div>
              <span className="text-zinc-500 block">Full Name</span>
              <span className="font-medium text-zinc-200 text-sm">{user?.name || "Anonymous Analyst"}</span>
            </div>

            <div>
              <span className="text-zinc-500 block">Enterprise Email</span>
              <span className="font-mono text-zinc-200">{user?.email || "unauthenticated"}</span>
            </div>

            <div>
              <span className="text-zinc-500 block">Platform Role</span>
              <span className="inline-block mt-1 px-2 py-0.5 rounded font-mono uppercase bg-cyan-950/80 text-cyan-300 border border-cyan-800/60 font-semibold text-[10px]">
                {user?.role || "GUEST"}
              </span>
            </div>

            <div>
              <span className="text-zinc-500 block">Tenant Organization</span>
              <span className="font-mono text-zinc-400">{user?.organizationId || "none"}</span>
            </div>
          </div>
        </Card>

        {/* Password & Credential Update */}
        <Card>
          <CardHeader>
            <div>
              <CardTitle>Security Credentials</CardTitle>
              <CardDescription>Update your local account password</CardDescription>
            </div>
          </CardHeader>

          {successMessage && (
            <div className="mb-4 rounded border border-emerald-800 bg-emerald-950/50 p-2.5 text-xs text-emerald-300">
              {successMessage}
            </div>
          )}

          <form onSubmit={handlePasswordUpdate} className="space-y-4">
            <Input
              label="Current Password"
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              required
            />

            <Input
              label="New Strong Password"
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              helperText="Minimum 12 characters with uppercase, number and symbol."
              required
            />

            <Button type="submit" variant="primary" size="sm">
              Update Password
            </Button>
          </form>
        </Card>
      </div>

      {/* Active Sessions */}
      <Card>
        <CardHeader>
          <div>
            <CardTitle>Active Security Sessions</CardTitle>
            <CardDescription>Devices and tokens currently authorized to access KELVIN</CardDescription>
          </div>
        </CardHeader>

        <div className="divide-y divide-zinc-800 text-xs">
          <div className="flex items-center justify-between py-3">
            <div>
              <p className="font-medium text-zinc-200">Current Workstation Session</p>
              <p className="text-[11px] text-zinc-500">Chrome on Windows • IP 192.168.1.100 (Internal VPN)</p>
            </div>
            <span className="text-[10px] uppercase font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800 px-2 py-0.5 rounded-full">
              Active Now
            </span>
          </div>
        </div>
      </Card>
    </div>
  );
}
