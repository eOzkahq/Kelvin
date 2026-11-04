import React from "react";
import { NavLink } from "react-router-dom";

export interface NavItem {
  to: string;
  label: string;
  iconText?: string;
  requiredRole?: string[];
}

export const primaryNavItems: NavItem[] = [
  { to: "/dashboard", label: "Dashboard", iconText: "📊" },
  { to: "/assessments", label: "Assessments", iconText: "🛡️" },
  { to: "/findings", label: "Findings", iconText: "🔍" },
  { to: "/remediation", label: "Remediation", iconText: "🔧" },
  { to: "/targets", label: "Targets & Scope", iconText: "🎯" },
  { to: "/reports", label: "Reports", iconText: "📄" },
  { to: "/compare", label: "Comparison", iconText: "⚖️" },
  { to: "/audit", label: "Audit Logs", iconText: "📜" },
];

export const adminNavItems: NavItem[] = [
  { to: "/admin/org", label: "Organization", iconText: "🏢", requiredRole: ["OrgAdmin"] },
  { to: "/admin/team", label: "Team & Members", iconText: "👥", requiredRole: ["OrgAdmin", "WorkspaceAdmin"] },
  { to: "/admin/roles", label: "Roles & SSO", iconText: "🔐", requiredRole: ["OrgAdmin"] },
  { to: "/admin/integrations", label: "Integrations", iconText: "🔌", requiredRole: ["OrgAdmin", "WorkspaceAdmin"] },
  { to: "/admin/settings", label: "Settings", iconText: "⚙️", requiredRole: ["OrgAdmin", "WorkspaceAdmin"] },
];

export interface SidebarProps {
  isCollapsed: boolean;
  onToggleCollapse: () => void;
  userRole?: string;
}

export const Sidebar: React.FC<SidebarProps> = ({
  isCollapsed,
  onToggleCollapse,
  userRole = "OrgAdmin",
}) => {
  const filterByRole = (item: NavItem) => {
    if (!item.requiredRole || item.requiredRole.length === 0) return true;
    return item.requiredRole.includes(userRole);
  };

  const visibleAdminItems = adminNavItems.filter(filterByRole);

  return (
    <aside
      className={`flex flex-col border-r border-zinc-800 bg-zinc-950 transition-all duration-200 select-none ${
        isCollapsed ? "w-16" : "w-60"
      }`}
      aria-label="Main Navigation"
    >
      {/* Brand Header */}
      <div className="flex h-14 items-center justify-between px-3 border-b border-zinc-800">
        {!isCollapsed && (
          <div className="flex items-center gap-2">
            <span className="h-6 w-6 rounded bg-gradient-to-br from-cyan-500 to-cyan-700 flex items-center justify-center font-bold text-xs text-black">
              K
            </span>
            <span className="font-bold tracking-tight text-zinc-100 text-sm">
              KELVIN <span className="text-[10px] text-cyan-400 font-mono font-normal">v1.0</span>
            </span>
          </div>
        )}
        <button
          type="button"
          onClick={onToggleCollapse}
          className="rounded p-1 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
          aria-label={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {isCollapsed ? "»" : "«"}
        </button>
      </div>

      {/* Nav Content */}
      <div className="flex-1 overflow-y-auto px-2 py-3 space-y-6">
        <div>
          {!isCollapsed && (
            <h4 className="px-2 text-[10px] font-semibold uppercase tracking-wider text-zinc-500 mb-2">
              Assessment Engine
            </h4>
          )}
          <nav className="space-y-1">
            {primaryNavItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `flex items-center gap-3 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors ${
                    isActive
                      ? "bg-cyan-950/60 text-cyan-300 border border-cyan-800/40"
                      : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-100"
                  }`
                }
              >
                <span className="text-sm" aria-hidden="true">
                  {item.iconText}
                </span>
                {!isCollapsed && <span>{item.label}</span>}
              </NavLink>
            ))}
          </nav>
        </div>

        {visibleAdminItems.length > 0 && (
          <div>
            {!isCollapsed && (
              <h4 className="px-2 text-[10px] font-semibold uppercase tracking-wider text-zinc-500 mb-2">
                Administration
              </h4>
            )}
            <nav className="space-y-1">
              {visibleAdminItems.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className={({ isActive }) =>
                    `flex items-center gap-3 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors ${
                      isActive
                        ? "bg-cyan-950/60 text-cyan-300 border border-cyan-800/40"
                        : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-100"
                    }`
                  }
                >
                  <span className="text-sm" aria-hidden="true">
                    {item.iconText}
                  </span>
                  {!isCollapsed && <span>{item.label}</span>}
                </NavLink>
              ))}
            </nav>
          </div>
        )}
      </div>
    </aside>
  );
};
