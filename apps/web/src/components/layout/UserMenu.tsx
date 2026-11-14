import React, { useState } from "react";
import { clearAuthToken } from "../../services/api";

export interface UserMenuProps {
  user?: {
    name: string;
    email: string;
    role: string;
  };
}

export const UserMenu: React.FC<UserMenuProps> = ({
  user = {
    name: "Alex Vance",
    email: "alex@kelvin.io",
    role: "OrgAdmin",
  },
}) => {
  const [isOpen, setIsOpen] = useState(false);

  const handleLogout = () => {
    clearAuthToken();
    window.location.href = "/services/kelvin/login";
  };

  return (
    <div className="relative inline-block text-left">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        aria-expanded={isOpen}
        aria-haspopup="true"
        className="flex items-center gap-2 rounded-full border border-zinc-700/80 bg-zinc-800/80 p-0.5 text-xs text-zinc-200 hover:border-[#d4c9a8]/50 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500"
      >
        <span className="flex h-7 w-7 items-center justify-center rounded-full bg-gradient-to-br from-[#f0eeea] via-[#d4c9a8] to-[#936e1f] font-bold text-[#0c0c0c] text-xs shadow-sm">
          {user.name.charAt(0)}
        </span>
      </button>

      {isOpen && (
        <div
          role="menu"
          className="absolute right-0 mt-2 w-56 rounded-md border border-zinc-800 bg-zinc-900 shadow-2xl z-50 p-1 divide-y divide-zinc-800"
        >
          <div className="px-3 py-2 text-left">
            <p className="text-xs font-semibold text-zinc-100">{user.name}</p>
            <p className="text-[11px] text-zinc-400 truncate">{user.email}</p>
            <span className="inline-block mt-1 px-1.5 py-0.5 text-[9px] uppercase font-mono font-medium rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/60">
              {user.role}
            </span>
          </div>

          <div className="py-1">
            <a
              href="#profile"
              role="menuitem"
              className="block px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100 rounded transition-colors"
            >
              Account Settings
            </a>
            <a
              href="#keys"
              role="menuitem"
              className="block px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100 rounded transition-colors"
            >
              API Credentials
            </a>
          </div>

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
