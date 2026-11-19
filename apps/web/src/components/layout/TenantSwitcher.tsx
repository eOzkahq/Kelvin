import React, { useState, useRef, useEffect } from "react";
import { useAuth } from "../../features/auth/AuthContext";
import { setTenantContext } from "../../services/api";

const WORKSPACES = [
  { id: "ws-prod", name: "Production Perimeter", env: "PROD" },
  { id: "ws-staging", name: "Staging Cluster", env: "STG" },
];

function formatRoleLabel(role?: string): string {
  if (!role) return "Member";
  return role
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export const TenantSwitcher: React.FC = () => {
  const { user } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const [activeWorkspace, setActiveWorkspace] = useState(WORKSPACES[0]);
  const wrapperRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onOutside = (e: MouseEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", onOutside);
    return () => document.removeEventListener("mousedown", onOutside);
  }, []);

  if (!user) {
    return null;
  }

  const orgId = user.organizationId;
  const rawOrg = (user as typeof user & { organization?: string })?.organization;
  const orgName =
    rawOrg ||
    (orgId === "11111111-1111-7000-8000-000000000001" ? "Acme Defense Corp" : "Primary Workspace");

  const handleSelectWorkspace = (ws: (typeof WORKSPACES)[number]) => {
    setActiveWorkspace(ws);
    setTenantContext({ tenantId: orgId, workspaceId: ws.id });
    setIsOpen(false);
  };

  return (
    <div className="relative inline-block text-left" ref={wrapperRef}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        aria-haspopup="true"
        aria-label="Switch workspace or tenant"
        className="flex items-center gap-2.5 rounded-lg border border-zinc-800/90 bg-zinc-900/70 px-2.5 py-1.5 text-xs font-medium text-zinc-200 hover:border-zinc-700 hover:bg-zinc-900 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4c9a8] cursor-pointer"
      >
          <span className="h-5 w-5 rounded-md bg-zinc-850 border border-zinc-700/80 flex items-center justify-center text-[10px] font-semibold text-[var(--brand-text)] font-display" aria-hidden="true">
            {orgName.charAt(0).toUpperCase()}
          </span>
          <div className="flex flex-col text-left leading-tight">
            <div className="flex items-center gap-1.5">
              <span className="font-medium text-zinc-100 max-w-[140px] truncate">{orgName}</span>
              <span className="text-zinc-600">/</span>
              <span className="text-zinc-400 max-w-[120px] truncate hidden sm:inline">{activeWorkspace.name}</span>
            </div>
            <span className="text-[10px] text-zinc-500">
              {formatRoleLabel(user.role)}
            </span>
          </div>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-zinc-500 ml-0.5" aria-hidden="true">
            <path d="m6 9 6 6 6-6" />
          </svg>
      </button>

      {isOpen && (
        <div
          role="menu"
          className="absolute left-0 mt-1.5 w-64 rounded-xl border border-zinc-800 bg-zinc-900 shadow-2xl z-50 p-1.5"
        >
          <div className="px-2.5 py-1.5 text-[10px] font-mono uppercase tracking-wider text-zinc-500">
            {orgName}
          </div>
          <div className="space-y-1">
            {WORKSPACES.map((ws) => {
              const selected = ws.id === activeWorkspace.id;
              return (
                <button
                  key={ws.id}
                  role="menuitem"
                  type="button"
                  onClick={() => handleSelectWorkspace(ws)}
                  className={`w-full flex items-center justify-between rounded-lg px-2.5 py-2 text-xs text-left transition-colors cursor-pointer ${selected
                        ? "bg-[var(--brand-bg)] text-[var(--brand-text)] border border-[var(--brand-border)] font-medium"
                        : "text-zinc-300 hover:bg-zinc-850 border border-transparent"
                    }`}
                >
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-950 border border-zinc-800 text-zinc-400">
                      {ws.env}
                    </span>
                    <span className="truncate">{ws.name}</span>
                  </div>
                  {selected && (
                      <span className="text-[var(--brand)] font-bold" aria-hidden="true">
                        ✓
                      </span>
                  )}
                    </button>
                  );
            })}
                </div>
        </div>
      )}
        </div>
      );
};
