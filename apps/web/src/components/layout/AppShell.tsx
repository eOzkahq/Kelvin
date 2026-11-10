import React, { useState, useEffect } from "react";
import { Sidebar } from "./Sidebar";
import { Breadcrumbs } from "./Breadcrumbs";
import { TenantSwitcher } from "./TenantSwitcher";
import { UserMenu } from "./UserMenu";
import { isDemoMode } from "../../config/env";

export interface AppShellProps {
  children: React.ReactNode;
  userRole?: string;
}

export const AppShell: React.FC<AppShellProps> = ({ children, userRole = "OrgAdmin" }) => {
  const [isCollapsed, setIsCollapsed] = useState<boolean>(() => {
    return localStorage.getItem("kelvin_sidebar_collapsed") === "true";
  });
  const [isMobileDrawerOpen, setIsMobileDrawerOpen] = useState(false);

  useEffect(() => {
    localStorage.setItem("kelvin_sidebar_collapsed", String(isCollapsed));
  }, [isCollapsed]);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-zinc-950 text-zinc-100 font-sans">
      {/* Desktop Sidebar (hidden on screens < 768px) */}
      <div className="hidden md:flex flex-shrink-0">
        <Sidebar
          isCollapsed={isCollapsed}
          onToggleCollapse={() => setIsCollapsed(!isCollapsed)}
          userRole={userRole}
        />
      </div>

      {/* Mobile Drawer (visible when isMobileDrawerOpen on screens < 768px) */}
      {isMobileDrawerOpen && (
        <div
          className="fixed inset-0 z-50 flex md:hidden bg-black/80 backdrop-blur-xs"
          role="dialog"
          aria-modal="true"
          onClick={() => setIsMobileDrawerOpen(false)}
        >
          <div
            className="w-64 max-w-[80vw] h-full bg-zinc-950 border-r border-zinc-800"
            onClick={(e) => e.stopPropagation()}
          >
            <Sidebar
              isCollapsed={false}
              onToggleCollapse={() => setIsMobileDrawerOpen(false)}
              userRole={userRole}
            />
          </div>
        </div>
      )}

      {/* Main Column */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Persistent Demo Warning Banner */}
        {isDemoMode() && (
          <aside
            role="status"
            aria-label="Demo Mode Active"
            className="bg-amber-500 text-black px-4 py-1.5 text-center font-bold text-xs tracking-wider flex items-center justify-center gap-2 select-none shadow-md z-30"
          >
            <span>⚠️</span>
            <span>DEMO DATA — NOT LIVE SECURITY RESULTS</span>
            <span className="font-mono text-[10px] font-normal bg-black/15 px-1.5 py-0.5 rounded">
              VITE_KELVIN_DEMO_MODE=true
            </span>
          </aside>
        )}

        {/* Top Header */}
        <header className="flex h-14 items-center justify-between border-b border-zinc-800 bg-zinc-900/60 px-4 backdrop-blur">
          <div className="flex items-center gap-3">
            {/* Mobile Hamburger Button */}
            <button
              type="button"
              onClick={() => setIsMobileDrawerOpen(true)}
              className="md:hidden rounded p-1.5 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
              aria-label="Open mobile navigation"
            >
              ☰
            </button>

            {/* Mobile Logo */}
            <div className="flex items-center gap-2 md:hidden">
              <span className="h-6 w-6 rounded bg-gradient-to-br from-cyan-500 to-cyan-700 flex items-center justify-center font-bold text-xs text-black">
                K
              </span>
              <span className="font-bold tracking-tight text-sm text-zinc-100">KELVIN</span>
            </div>

            {/* Tenant & Workspace Switcher */}
            <TenantSwitcher />
          </div>

          {/* Right Header Controls */}
          <div className="flex items-center gap-3">
            {/* Quick Omnibar search trigger */}
            <button
              type="button"
              className="hidden sm:flex items-center gap-2 rounded-md border border-zinc-800 bg-zinc-900 px-3 py-1.5 text-xs text-zinc-400 hover:border-zinc-700 hover:text-zinc-200 transition-colors"
              aria-label="Search assets, findings, and documentation (Ctrl+K)"
            >
              <span>Search platform...</span>
              <kbd className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] font-mono text-zinc-500">
                ⌘K
              </kbd>
            </button>

            {/* Notification trigger */}
            <button
              type="button"
              className="relative rounded p-1.5 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
              aria-label="View notifications"
            >
              🔔
              <span className="absolute top-1 right-1 h-2 w-2 rounded-full bg-cyan-400" />
            </button>

            {/* User Profile Menu */}
            <UserMenu />
          </div>
        </header>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto px-4 md:px-8 py-4">
          <Breadcrumbs />
          <main className="mt-2">{children}</main>
        </div>
      </div>
    </div>
  );
};
