import React from "react";
import { NavLink } from "react-router-dom";
import { NavIcon } from "../ui/Icons";
import { BrandMark } from "../ui/eOzkaBrand";
import { useOptionalPlan } from "../../features/billing/PlanContext";

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

const normalizeRole = (role: string): string => {
  const upper = role.toUpperCase();
  if (upper === "ORG_ADMIN" || upper === "ORGADMIN" || upper === "ADMIN" || upper === "SUPER_ADMIN") {
    return "OrgAdmin";
  }
  if (upper === "WORKSPACE_ADMIN" || upper === "WORKSPACEADMIN") {
    return "WorkspaceAdmin";
  }
  return role;
};

export const Sidebar: React.FC<SidebarProps> = ({
  isCollapsed,
  onToggleCollapse,
  userRole = "OrgAdmin",
}) => {
  const normalizedRole = normalizeRole(userRole);
  const planCtx = useOptionalPlan();
  const activePlan = planCtx?.currentPlan;
  const activeCoupon = planCtx?.activeCoupon;

  const filterByRole = (item: NavItem) => {
    if (!item.requiredRole || item.requiredRole.length === 0) return true;
    return item.requiredRole.includes(userRole) || item.requiredRole.includes(normalizedRole);
  };

  const visibleAdminItems = adminNavItems.filter(filterByRole);

  return (
    <aside
      className={`flex flex-col border-r border-zinc-800/80 bg-zinc-950/95 backdrop-blur-md transition-all duration-200 select-none h-full ${isCollapsed ? "w-16" : "w-64"
        }`}
      aria-label="Main Navigation"
    >
      {/* Brand Header */}
        <div className="flex h-16 items-center justify-between px-3.5 border-b border-zinc-800/80">
          {!isCollapsed && (
              <NavLink to="/dashboard" className="group min-w-0">
                <BrandMark variant="compact" />
              </NavLink>
        )}
              <button
                type="button"
                onClick={onToggleCollapse}
                className={`rounded-lg p-1.5 text-zinc-400 hover:bg-zinc-800/80 hover:text-[#e8debe] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4c9a8] ${isCollapsed ? "mx-auto" : ""
                  }`}
                aria-label={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
                title={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}
              >
                <svg
                  width="15"
                  height="15"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.75"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  className={`transition-transform duration-200 ${isCollapsed ? "rotate-180" : ""}`}
                  aria-hidden="true"
                >
                  <path d="m11 17-5-5 5-5" />
                  <path d="m18 17-5-5 5-5" />
                </svg>
              </button>
            </div>

      {/* Nav Content */}
          <div className="flex-1 overflow-y-auto px-2.5 py-4 space-y-6">
            <div>
              {!isCollapsed && (
                <h4 className="px-2.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500 mb-2 font-mono">
                  Assessment Engine
                </h4>
              )}
              <nav className="space-y-1">
                {primaryNavItems.map((item) => (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    title={isCollapsed ? item.label : undefined}
                    className={({ isActive }) =>
                      `relative flex items-center gap-3 rounded-lg px-2.5 py-2 text-xs font-medium transition-all ${isActive
                        ? "bg-[var(--brand-bg)] text-[var(--brand-strong)] border border-[var(--brand-border)] font-semibold"
                        : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-100 border border-transparent"
                      }`
                    }
                  >
                    {({ isActive }) => (
                      <>
                        {isActive && (
                          <span
                            className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-r bg-[var(--brand)]"
                            aria-hidden="true"
                          />
                        )}
                        <NavIcon
                          route={item.to}
                          size={15}
                          className={isActive ? "text-[var(--brand-text)]" : "text-zinc-500"}
                        />
                        {!isCollapsed && <span>{item.label}</span>}
                      </>
                    )}
                  </NavLink>
                ))}
              </nav>
            </div>

            {visibleAdminItems.length > 0 && (
              <div>
                {!isCollapsed && (
                  <h4 className="px-2.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500 mb-2 font-mono">
                    Administration
                  </h4>
                )}
                <nav className="space-y-1">
                  {visibleAdminItems.map((item) => (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      title={isCollapsed ? item.label : undefined}
                      className={({ isActive }) =>
                        `relative flex items-center gap-3 rounded-lg px-2.5 py-2 text-xs font-medium transition-all ${isActive
                          ? "bg-[var(--brand-bg)] text-[var(--brand-strong)] border border-[var(--brand-border)] font-semibold"
                          : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-100 border border-transparent"
                        }`
                      }
                    >
                      {({ isActive }) => (
                        <>
                          {isActive && (
                            <span
                              className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-r bg-[var(--brand)]"
                              aria-hidden="true"
                            />
                          )}
                          <NavIcon
                            route={item.to}
                            size={15}
                            className={isActive ? "text-[var(--brand-text)]" : "text-zinc-500"}
                          />
                          {!isCollapsed && <span>{item.label}</span>}
                        </>
                      )}
                    </NavLink>
                  ))}
                </nav>
              </div>
            )}
          </div>

          {/* Workspace Tier & Shortcut Footer */}
          {!isCollapsed && (
            <div className="px-3 py-3 border-t border-zinc-800/80 space-y-2.5">
                  <div className="flex items-center justify-between rounded-lg border border-zinc-800/90 bg-zinc-900 px-2.5 py-2 text-xs">
                    <div className="min-w-0 truncate">
                      <span className="text-zinc-400">
                        Plan {activePlan?.tierNumber ?? 1} ·{" "}
                      </span>
                      <span className="font-semibold text-zinc-100">
                        {activePlan?.name ?? "Starter"}
                      </span>
                      {activeCoupon && (
                        <span className="ml-1.5 text-[10px] font-mono text-emerald-400">
                          FREE
                        </span>
                      )}
                    </div>
                    <NavLink
                      to="/plans"
                      className="text-[11px] font-mono text-[var(--brand-text)] hover:underline shrink-0 ml-2"
                    >
                      Plans &rarr;
                    </NavLink>
                  </div>
                    <div className="flex items-center justify-between px-1 text-[11px] text-zinc-400">
                      <span>Command Search</span>
                        <kbd className="rounded bg-zinc-900 border border-zinc-800 px-1.5 py-0.5 text-[10px] font-mono text-zinc-300">
                          Ctrl+Shift+P
                        </kbd>
                    </div>
                  </div>
      )}
                </aside>
                );
};
