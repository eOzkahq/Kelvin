import React, { useState } from "react";
import { useAuth } from "../../features/auth/AuthContext";
import { setTenantContext } from "../../services/api";

export const TenantSwitcher: React.FC = () => {
  const { user } = useAuth();
  const [isOpen, setIsOpen] = useState(false);

  if (!user) {
    return null;
  }

  // Build a single workspace from the authenticated user's tenant
  const orgName = (user as (typeof user & { organization?: string }))?.organization ?? user.organizationId ?? "Organization";
  const orgId = user.organizationId;

  const handleSelect = () => {
    setTenantContext({ tenantId: orgId });
    setIsOpen(false);
  };

  return (
    <div className="relative inline-block text-left">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        aria-haspopup="true"
        className="flex items-center gap-2 rounded-md border border-zinc-800/80 bg-zinc-900/80 px-2.5 py-1.5 text-xs font-medium text-zinc-200 hover:border-[#d4c9a8]/40 hover:bg-zinc-800/80 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
      >
        <span className="h-2 w-2 rounded-full bg-[#d4c9a8]" aria-hidden="true" />
        <div className="flex flex-col text-left">
          <span className="font-semibold text-zinc-100 max-w-[140px] truncate">{orgName}</span>
          <span className="text-[10px] text-zinc-400 font-mono capitalize">{user.role?.toLowerCase().replace(/_/g, " ")}</span>
        </div>
        <span className="text-zinc-500 ml-1">▾</span>
      </button>

      {isOpen && (
        <div
          role="menu"
          className="absolute left-0 mt-1.5 w-64 rounded-md border border-zinc-800 bg-zinc-900 shadow-xl z-50 p-1"
        >
          <div className="px-2 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
            Active Workspace
          </div>
          <button
            role="menuitem"
            type="button"
            onClick={handleSelect}
            className="w-full flex items-center justify-between rounded px-2.5 py-1.5 text-xs text-left transition-colors bg-cyan-950/60 text-cyan-300 font-medium"
          >
            <div className="flex flex-col">
              <span className="font-medium truncate max-w-[180px]">{orgName}</span>
              <span className="text-[10px] text-zinc-500 font-mono">{orgId}</span>
            </div>
            <span className="text-cyan-400 font-bold" aria-hidden="true">✓</span>
          </button>
        </div>
      )}
    </div>
  );
};
