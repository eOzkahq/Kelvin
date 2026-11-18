import React, { useState, useRef, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../../features/auth/AuthContext";
import { BuildingIcon, ChevronRightIcon } from "../ui/Icons";

export interface UserMenuUserProp {
  name: string;
  email: string;
  role: string;
  organization?: string;
  organizationId?: string;
}

export interface UserMenuProps {
  user?: UserMenuUserProp;
}

export const UserMenu: React.FC<UserMenuProps> = ({ user: userProp }) => {
  const { user: authUser, logout } = useAuth();
  const user = userProp ?? authUser;
  const navigate = useNavigate();
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

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
  const displayOrg =
    (user as (typeof user & { organization?: string }) | null)?.organization ??
    user?.organizationId ??
    "";
  const initial = displayName.charAt(0).toUpperCase();

  return (
    <div className="relative inline-block text-left" ref={menuRef}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        aria-haspopup="true"
        className="flex items-center gap-2 rounded-full border border-zinc-700/80 bg-zinc-900/90 p-0.5 pr-2 text-xs text-zinc-200 hover:border-[#d4c9a8]/55 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4c9a8] cursor-pointer"
      >
          <span className="flex h-7 w-7 items-center justify-center rounded-full bg-[var(--brand-bg)] border border-[var(--brand-border)] font-bold text-[var(--brand-text)] text-xs font-display">
            {initial}
          </span>
          <span className="hidden lg:inline text-xs font-medium text-zinc-300 max-w-[110px] truncate">
            {displayName}
          </span>
      </button>

      {isOpen && (
        <div
          role="menu"
          className="absolute right-0 mt-2 w-64 rounded-xl border border-zinc-800 bg-zinc-900/95 backdrop-blur-md shadow-2xl z-50 p-1.5 divide-y divide-zinc-800/80"
        >
          {/* Identity block */}
          <div className="px-3 py-2.5 text-left">
            <p className="text-xs font-semibold text-zinc-100 truncate font-display">{displayName}</p>
            <p className="text-[11px] text-zinc-400 truncate font-mono mt-0.5">{displayEmail}</p>
            {displayOrg && (
              <p className="text-[10px] text-zinc-500 truncate mt-1.5 flex items-center gap-1.5">
                <BuildingIcon size={11} className="text-zinc-500" />
                <span>{displayOrg}</span>
              </p>
            )}
            {displayRole && (
                <span className="inline-block mt-2 px-2 py-0.5 text-[9px] uppercase font-mono font-medium rounded-full bg-[var(--brand-bg)] text-[var(--brand-text)] border border-[var(--brand-border)]">
                  {displayRole}
                </span>
            )}
              </div>

          {/* Nav links */}
            <div className="py-1.5 space-y-0.5">
              <Link
                to="/onboarding"
                role="menuitem"
                onClick={() => setIsOpen(false)}
                className="flex items-center justify-between px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-850 hover:text-zinc-100 rounded-lg transition-colors"
              >
                <span>Workspace Onboarding</span>
                <ChevronRightIcon size={12} className="text-zinc-500" />
              </Link>
              <Link
                to="/plans"
                role="menuitem"
                onClick={() => setIsOpen(false)}
                className="flex items-center justify-between px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-850 hover:text-zinc-100 rounded-lg transition-colors"
              >
                <span>Plan &amp; Billing</span>
                <ChevronRightIcon size={12} className="text-zinc-500" />
              </Link>
              <Link
                to="/account"
                role="menuitem"
                onClick={() => setIsOpen(false)}
                className="flex items-center justify-between px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-850 hover:text-zinc-100 rounded-lg transition-colors"
              >
                <span>Account &amp; Security Profile</span>
                <ChevronRightIcon size={12} className="text-zinc-500" />
              </Link>
              <Link
                to="/admin/org"
                role="menuitem"
                onClick={() => setIsOpen(false)}
                className="flex items-center justify-between px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-850 hover:text-zinc-100 rounded-lg transition-colors"
              >
                <span>Organization Settings</span>
                <ChevronRightIcon size={12} className="text-zinc-500" />
              </Link>
            </div>

            {/* Sign out */}
            <div className="pt-1.5">
              <button
                type="button"
                role="menuitem"
                onClick={handleLogout}
                className="w-full text-left px-3 py-1.5 text-xs text-red-400 hover:bg-red-950/50 hover:text-red-300 rounded-lg transition-colors cursor-pointer"
              >
                Sign out
              </button>
            </div>
          </div>
      )}
        </div>
      );
};
