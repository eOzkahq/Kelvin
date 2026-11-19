import React, { useState, useEffect, useRef } from "react";
import { Sidebar } from "./Sidebar";
import { Breadcrumbs } from "./Breadcrumbs";
import { TenantSwitcher } from "./TenantSwitcher";
import { UserMenu } from "./UserMenu";
import { CommandPalette } from "../navigation/CommandPalette";
import { BellIcon, SearchIcon } from "../ui/Icons";
import { useAuth } from "../../features/auth/AuthContext";
import { isDemoMode } from "../../config/env";
import { Link } from "react-router-dom";

export interface AppShellProps {
  children: React.ReactNode;
}

const NOTIFICATIONS = [
  {
    id: "al-1",
    title: "Critical Finding Detected",
    detail: "Spring Framework RCE flagged on api.staging.kelvin.internal",
    time: "4m ago",
    href: "/findings",
  },
  {
    id: "al-2",
    title: "Scan Completed",
    detail: "Production API Perimeter finished with 14 findings",
    time: "18m ago",
    href: "/assessments",
  },
  {
    id: "al-3",
    title: "SLA Escalation Window",
    detail: "1 remediation ticket approaching 48h breach boundary",
    time: "1h ago",
    href: "/remediation",
  },
];

export const AppShell: React.FC<AppShellProps> = ({ children }) => {
  const { user } = useAuth();
  const userRole = user?.role ?? "READ_ONLY_AUDITOR";
  const [isCollapsed, setIsCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem("kelvin_sidebar_collapsed") === "true";
    } catch {
      return false;
    }
  });
  const [isMobileDrawerOpen, setIsMobileDrawerOpen] = useState(false);
  const [isPaletteOpen, setIsPaletteOpen] = useState(false);
  const [isNotificationsOpen, setIsNotificationsOpen] = useState(false);
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const notifRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    try {
      localStorage.setItem("kelvin_sidebar_collapsed", String(isCollapsed));
    } catch {
      // ignore
    }
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

  // Global keyboard shortcuts for Command Palette (Ctrl+Shift+P, Ctrl/Cmd+K, /)
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const isTyping =
        target?.tagName === "INPUT" ||
        target?.tagName === "TEXTAREA" ||
        target?.isContentEditable;

      if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key.toLowerCase() === "p") {
        e.preventDefault();
        setIsPaletteOpen((open) => !open);
        return;
      }

      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setIsPaletteOpen((open) => !open);
        return;
      }

      if (!isTyping && e.key === "/" && !e.metaKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault();
        setIsPaletteOpen(true);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  // Close notifications popover on outside click
  useEffect(() => {
    const onMouseDown = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setIsNotificationsOpen(false);
      }
    };
    document.addEventListener("mousedown", onMouseDown);
    return () => document.removeEventListener("mousedown", onMouseDown);
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
      <CommandPalette isOpen={isPaletteOpen} onClose={() => setIsPaletteOpen(false)} />

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
        <div className="flex flex-1 flex-col overflow-hidden">
          {/* Persistent Demo Warning Banner */}
          {isDemoMode() && (
            <aside
              role="status"
              aria-label="Demo Mode Active"
              className="bg-zinc-900 border-b border-zinc-800 text-zinc-300 px-4 py-1 text-center font-medium text-[11px] tracking-wide flex items-center justify-center gap-2 select-none z-30"
            >
              <span className="h-1.5 w-1.5 rounded-full bg-[var(--brand)]" aria-hidden="true" />
              <span>Preview Workspace — Sample Telemetry Active</span>
            </aside>
          )}

          {/* Top Header */}
          <header className="flex h-14 items-center justify-between border-b border-zinc-800/80 bg-zinc-950/85 px-4 md:px-6 backdrop-blur-md z-20">
            <div className="flex items-center gap-3">
              {/* Mobile Hamburger Button */}
              <button
                type="button"
                onClick={() => setIsMobileDrawerOpen(true)}
                className="md:hidden rounded-lg p-1.5 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4c9a8]"
                aria-label="Open mobile navigation"
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
                  <line x1="3" y1="6" x2="21" y2="6" />
                  <line x1="3" y1="12" x2="21" y2="12" />
                  <line x1="3" y1="18" x2="21" y2="18" />
                </svg>
              </button>

              {/* Mobile Logo */}
              <div className="flex items-center gap-2 md:hidden">
                <span className="h-6 w-6 rounded-lg bg-gradient-to-br from-[#f0eeea] via-[#d4c9a8] to-[#936e1f] flex items-center justify-center font-bold text-xs text-[#0c0c0c] font-display">
                  K
                </span>
                <span className="font-bold tracking-tight text-sm text-zinc-100 font-display">KELVIN</span>
              </div>

              {/* Tenant & Workspace Switcher */}
              <TenantSwitcher />
            </div>

            {/* Right Header Controls */}
            <div className="flex items-center gap-2.5">
              {/* Quick Omnibar search trigger */}
              <button
                type="button"
                onClick={() => setIsPaletteOpen(true)}
                className="hidden sm:flex items-center justify-between gap-4 w-56 lg:w-72 rounded-lg border border-zinc-800 bg-zinc-900/70 px-3 py-1.5 text-xs text-zinc-400 hover:border-zinc-700 hover:text-zinc-200 transition-colors cursor-pointer"
                aria-label="Search assets, findings, and commands (Ctrl+Shift+P)"
                title="Open Command Search (Ctrl+Shift+P or Ctrl+K)"
              >
                <span className="flex items-center gap-2 truncate">
                  <SearchIcon size={13} className="text-zinc-500 shrink-0" />
                  <span className="truncate">Search or jump to...</span>
                </span>
                <kbd className="rounded bg-zinc-950 border border-zinc-800 px-1.5 py-0.5 text-[10px] font-mono text-zinc-400 shrink-0">
                  Ctrl+Shift+P
                </kbd>
              </button>

              {/* Theme Toggle Button */}
              <button
                type="button"
                onClick={toggleTheme}
                className="rounded-lg border border-zinc-800/90 bg-zinc-900/70 p-2 text-zinc-400 hover:border-[#d4c9a8]/45 hover:text-[#d4c9a8] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4c9a8] cursor-pointer"
                title={theme === "light" ? "Switch to Dark Theme" : "Switch to Light Theme"}
                aria-label="Toggle Theme"
              >
                {theme === "light" ? (
                  <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
                  </svg>
                ) : (
                  <svg className="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
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

              {/* Notification trigger & popover */}
              <div className="relative" ref={notifRef}>
                <button
                  type="button"
                  onClick={() => setIsNotificationsOpen((open) => !open)}
                  aria-expanded={isNotificationsOpen}
                  className="relative rounded-lg border border-zinc-800/90 bg-zinc-900/70 p-2 text-zinc-400 hover:border-[#d4c9a8]/45 hover:text-zinc-100 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4c9a8] cursor-pointer"
                  aria-label="View notifications"
                >
                  <BellIcon size={15} />
                  <span className="absolute top-1.5 right-1.5 h-1.5 w-1.5 rounded-full bg-[#d4c9a8]" />
                </button>

                {isNotificationsOpen && (
                  <div
                    role="menu"
                    className="absolute right-0 mt-2 w-80 rounded-xl border border-zinc-800 bg-zinc-900/95 backdrop-blur-md shadow-2xl z-50 overflow-hidden"
                  >
                    <div className="flex items-center justify-between px-3.5 py-2.5 border-b border-zinc-800/80">
                      <span className="text-xs font-semibold text-zinc-100 font-display">
                        Notifications
                      </span>
                      <span className="text-[10px] font-mono text-zinc-500">3 unread</span>
                    </div>
                    <div className="divide-y divide-zinc-800/70 max-h-72 overflow-y-auto">
                      {NOTIFICATIONS.map((item) => (
                        <Link
                          key={item.id}
                          to={item.href}
                          onClick={() => setIsNotificationsOpen(false)}
                          className="block px-3.5 py-2.5 hover:bg-zinc-800/50 transition-colors"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-medium text-zinc-100">{item.title}</span>
                            <span className="text-[10px] font-mono text-zinc-500">{item.time}</span>
                          </div>
                          <p className="text-[11px] text-zinc-400 mt-0.5 leading-snug">{item.detail}</p>
                        </Link>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* User Profile Menu */}
              <UserMenu />
            </div>
          </header>

          {/* Content Body */}
          <div className="flex-1 overflow-y-auto px-4 md:px-8 py-5">
            <div className="max-w-7xl mx-auto">
              <Breadcrumbs />
              <main className="mt-3 pb-10">{children}</main>
            </div>
          </div>
        </div>
      </div>
      );
};
