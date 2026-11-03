import React, { useState } from "react";
import { setTenantContext, getTenantContext } from "../../services/api";

export interface WorkspaceOption {
  id: string;
  name: string;
  orgId: string;
  orgName: string;
}

const mockWorkspaces: WorkspaceOption[] = [
  { id: "ws-primary", name: "Primary Production", orgId: "org-sec-corp", orgName: "Kelvin Security Corp" },
  { id: "ws-staging", name: "Staging Assessment", orgId: "org-sec-corp", orgName: "Kelvin Security Corp" },
  { id: "ws-rnd", name: "R&D Penetration Lab", orgId: "org-rnd", orgName: "Cyber Research Lab" },
];

export const TenantSwitcher: React.FC = () => {
  const currentContext = getTenantContext();
  const [selectedWs, setSelectedWs] = useState<WorkspaceOption>(() => {
    const found = mockWorkspaces.find((ws) => ws.id === currentContext.workspaceId);
    return found ?? mockWorkspaces[0];
  });
  const [isOpen, setIsOpen] = useState(false);

  const handleSelect = (ws: WorkspaceOption) => {
    setSelectedWs(ws);
    setTenantContext({
      tenantId: ws.orgId,
      workspaceId: ws.id,
    });
    setIsOpen(false);
  };

  return (
    <div className="relative inline-block text-left">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        aria-haspopup="true"
        className="flex items-center gap-2 rounded-md border border-zinc-800 bg-zinc-900/80 px-2.5 py-1.5 text-xs font-medium text-zinc-200 hover:border-zinc-700 hover:bg-zinc-800/80 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
      >
        <span className="h-2 w-2 rounded-full bg-cyan-400" aria-hidden="true" />
        <div className="flex flex-col text-left">
          <span className="font-semibold text-zinc-100">{selectedWs.orgName}</span>
          <span className="text-[10px] text-zinc-400">{selectedWs.name}</span>
        </div>
        <span className="text-zinc-500 ml-1">▾</span>
      </button>

      {isOpen && (
        <div
          role="menu"
          className="absolute left-0 mt-1.5 w-64 rounded-md border border-zinc-800 bg-zinc-900 shadow-xl z-50 p-1"
        >
          <div className="px-2 py-1.5 text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
            Select Workspace
          </div>
          {mockWorkspaces.map((ws) => (
            <button
              key={ws.id}
              role="menuitem"
              type="button"
              onClick={() => handleSelect(ws)}
              className={`w-full flex items-center justify-between rounded px-2.5 py-1.5 text-xs text-left transition-colors ${
                ws.id === selectedWs.id
                  ? "bg-cyan-950/60 text-cyan-300 font-medium"
                  : "text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100"
              }`}
            >
              <div className="flex flex-col">
                <span className="font-medium">{ws.name}</span>
                <span className="text-[10px] text-zinc-500">{ws.orgName}</span>
              </div>
              {ws.id === selectedWs.id && (
                <span className="text-cyan-400 font-bold" aria-hidden="true">
                  ✓
                </span>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
};
