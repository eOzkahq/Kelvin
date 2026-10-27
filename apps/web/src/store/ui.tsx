import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

type UIState = {
  sidebarOpen: boolean;
  toggleSidebar: () => void;
};

const UIContext = createContext<UIState | null>(null);

export function UIProvider({ children }: { children: ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const toggleSidebar = useCallback(() => setSidebarOpen((open) => !open), []);

  const value = useMemo(() => ({ sidebarOpen, toggleSidebar }), [sidebarOpen, toggleSidebar]);

  return <UIContext.Provider value={value}>{children}</UIContext.Provider>;
}

export function useUI(): UIState {
  const state = useContext(UIContext);
  if (!state) {
    throw new Error("useUI must be used within UIProvider");
  }
  return state;
}
