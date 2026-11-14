import React, { useState, useEffect } from "react";
import { Sidebar } from "./Sidebar";
import { Breadcrumbs } from "./Breadcrumbs";
import { TenantSwitcher } from "./TenantSwitcher";
import { UserMenu } from "./UserMenu";
import { CustomCursor, BackgroundParticles } from "../ui";
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
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  useEffect(() => {
    localStorage.setItem("kelvin_sidebar_collapsed", String(isCollapsed));
  }, [isCollapsed]);

  useEffect(() => {
    let saved = null;
    try {
      saved = localStorage.getItem("kelvin_theme");
    } catch {
      // ignore
    }
    const htmlEl = document.documentElement;
    if (saved === "light") {
      htmlEl.setAttribute("data-theme", "light");
      setTheme("light");
    } else {
      htmlEl.removeAttribute("data-theme");
      setTheme("dark");
    }
  }, []);

  const toggleTheme = () => {
    const htmlEl = document.documentElement;
    if (theme === "light") {
      htmlEl.removeAttribute("data-theme");
      try {
        localStorage.setItem("kelvin_theme", "dark");
      } catch {
        // ignore
      }
      setTheme("dark");
    } else {
      htmlEl.setAttribute("data-theme", "light");
      try {
        localStorage.setItem("kelvin_theme", "light");
      } catch {
        // ignore
      }
      setTheme("light");
    }
  };

  return (
    <div className="relative flex h-screen w-screen overflow-hidden bg-zinc-950 text-zinc-100 font-sans">
      <BackgroundParticles />
      <CustomCursor />

      {/* Desktop Sidebar (hidden on screens < 768px) */}
      <div className="hidden md:flex flex-shrink-0 z-20">
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
      <div className="flex flex-1 flex-col overflow-hidden z-10">
        {/* Persistent Demo Warning Banner */}
        {isDemoMode() && (
          <aside
            role="status"
            aria-label="Demo Mode Active"
            className="bg-[#d4c9a8] text-[#0c0c0c] px-4 py-1.5 text-center font-bold text-xs tracking-wider flex items-center justify-center gap-2 select-none shadow-md z-30"
          >
            <span>⚠️</span>
            <span>DEMO DATA — NOT LIVE SECURITY RESULTS</span>
            <span className="font-mono text-[10px] font-normal bg-black/15 px-1.5 py-0.5 rounded">
              VITE_KELVIN_DEMO_MODE=true
            </span>
          </aside>
        )}

        {/* Top Header */}
        <header className="flex h-14 items-center justify-between border-b border-zinc-800/80 bg-zinc-950/80 px-4 backdrop-blur-md">
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
              <span className="h-6 w-6 rounded bg-gradient-to-br from-[#f0eeea] via-[#d4c9a8] to-[#936e1f] flex items-center justify-center font-bold text-xs text-[#0c0c0c]">
                K
              </span>
              <span className="font-bold tracking-tight text-sm text-zinc-100">KELVIN</span>
            </div>

            {/* Tenant & Workspace Switcher */}
            <TenantSwitcher />
          </div>

          {/* Right Header Controls */}
          <div className="flex items-center gap-2.5">
            {/* Quick Omnibar search trigger */}
            <button
              type="button"
              className="hidden sm:flex items-center gap-2 rounded-md border border-zinc-800/80 bg-zinc-900/80 px-3 py-1.5 text-xs text-zinc-400 hover:border-zinc-700 hover:text-zinc-200 transition-colors"
              aria-label="Search assets, findings, and documentation (Ctrl+K)"
            >
              <span>Search platform...</span>
              <kbd className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] font-mono text-zinc-500">
                ⌘K
              </kbd>
            </button>

            {/* Theme Toggle Button matching EOZKA */}
            <button
              type="button"
              onClick={toggleTheme}
              className="rounded-md border border-zinc-800/80 bg-zinc-900/60 p-1.5 text-zinc-400 hover:border-zinc-700 hover:text-[#d4c9a8] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
              title={theme === "light" ? "Switch to Dark Theme" : "Switch to Light Theme"}
              aria-label="Toggle Theme"
            >
              {theme === "light" ? (
                <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
                </svg>
              ) : (
                <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="5" />
                  <line x1="12" y1="1" x2="12" y2="3" />
                  <line x1="12" y1="21" x2="12" y2="23" />
                  <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
                  <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
                  <line x1="1" y1="12" x2="3" y2="12" />
                  <line x1="21" y1="12" x2="23" y2="12" />
                  <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
                  <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
                </svg>
              )}
            </button>

            {/* Notification trigger */}
            <button
              type="button"
              className="relative rounded-md border border-zinc-800/80 bg-zinc-900/60 p-1.5 text-zinc-400 hover:border-zinc-700 hover:text-zinc-100 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
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
