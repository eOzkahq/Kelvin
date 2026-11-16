import React, { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../features/auth/AuthContext";

export const UserMenu: React.FC = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setIsOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const handleLogout = async () => {
    setIsOpen(false);
    await logout();
    navigate("/login", { replace: true });
  };

  const displayName = user?.name ?? "Account";
  const displayEmail = user?.email ?? "";
  const displayRole = user?.role ?? "";
  const displayOrg = (user as (typeof user & { organization?: string }) | null)?.organization ?? user?.organizationId ?? "";
  const initial = displayName.charAt(0).toUpperCase();

  return (
    <div className="relative inline-block text-left" ref={menuRef}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        aria-haspopup="true"
        className="flex items-center gap-2 rounded-full border border-zinc-700/80 bg-zinc-800/80 p-0.5 text-xs text-zinc-200 hover:border-[#d4c9a8]/50 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
      >
        <span className="flex h-7 w-7 items-center justify-center rounded-full bg-gradient-to-br from-[#f0eeea] via-[#d4c9a8] to-[#936e1f] font-bold text-[#0c0c0c] text-xs shadow-sm">
          {initial}
        </span>
      </button>

      {isOpen && (
        <div
          role="menu"
          className="absolute right-0 mt-2 w-64 rounded-md border border-zinc-800 bg-zinc-900 shadow-2xl z-50 p-1 divide-y divide-zinc-800"
        >
          {/* Identity block */}
          <div className="px-3 py-2 text-left">
            <p className="text-xs font-semibold text-zinc-100 truncate">{displayName}</p>
            <p className="text-[11px] text-zinc-400 truncate">{displayEmail}</p>
            {displayOrg && (
              <p className="text-[10px] text-zinc-500 truncate mt-0.5">📁 {displayOrg}</p>
            )}
            {displayRole && (
              <span className="inline-block mt-1 px-1.5 py-0.5 text-[9px] uppercase font-mono font-medium rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/60">
                {displayRole}
              </span>
            )}
          </div>

          {/* Nav links */}
          <div className="py-1">
            <a
              href="/account"
              role="menuitem"
              onClick={() => setIsOpen(false)}
              className="block px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100 rounded transition-colors"
            >
              Account / Profile
            </a>
            <a
              href="/admin"
              role="menuitem"
              onClick={() => setIsOpen(false)}
              className="block px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100 rounded transition-colors"
            >
              Organization Settings
            </a>
          </div>

          {/* Sign out */}
          <div className="pt-1">
            <button
              type="button"
              role="menuitem"
              onClick={handleLogout}
              className="w-full text-left px-3 py-1.5 text-xs text-red-400 hover:bg-red-950/50 hover:text-red-300 rounded transition-colors"
            >
              Sign out
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
