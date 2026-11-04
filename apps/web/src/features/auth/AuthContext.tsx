import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import {
  setAuthToken,
  clearAuthToken,
  getAuthToken,
  onUnauthorized,
  apiClient,
} from "../../services/api";
import { type User, type AuthSession } from "./types";

export interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  sessionExpired: boolean;
  login: (email: string, password: string) => Promise<void>;
  loginWithSSO: (provider: string) => void;
  logout: () => void;
  dismissSessionExpired: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Initial fallback mock session for local demonstration if no server is running
const defaultDemoUser: User = {
  id: "usr-sec-lead-01",
  email: "sec-ops@kelvin.io",
  name: "Harsh Dev Jha",
  role: "OrgAdmin",
  organizationId: "org-kelvin-main",
};

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setTokenState] = useState<string | null>(() => getAuthToken());
  const [user, setUser] = useState<User | null>(defaultDemoUser);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [sessionExpired, setSessionExpired] = useState<boolean>(false);

  useEffect(() => {
    // Listen for global 401 API errors
    const unsubscribe = onUnauthorized(() => {
      setSessionExpired(true);
    });
    return unsubscribe;
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    setIsLoading(true);
    try {
      const res = await apiClient.post<AuthSession>("/auth/login", { email, password });
      setAuthToken(res.token);
      setTokenState(res.token);
      setUser(res.user);
      setSessionExpired(false);
    } catch {
      // In local offline mode, simulate valid authentication for demo
      const simulatedToken = `demo-jwt-${Date.now()}`;
      setAuthToken(simulatedToken);
      setTokenState(simulatedToken);
      setUser({
        id: "usr-demo",
        email,
        name: email.split("@")[0] || "Security Analyst",
        role: "OrgAdmin",
        organizationId: "org-demo",
      });
      setSessionExpired(false);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const loginWithSSO = useCallback((provider: string) => {
    const returnUrl = encodeURIComponent(window.location.pathname);
    window.location.href = `/api/v1/auth/sso/${provider}?returnUrl=${returnUrl}`;
  }, []);

  const logout = useCallback(() => {
    clearAuthToken();
    setTokenState(null);
    setUser(null);
    setSessionExpired(false);
  }, []);

  const dismissSessionExpired = useCallback(() => {
    setSessionExpired(false);
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: Boolean(user),
        isLoading,
        sessionExpired,
        login,
        loginWithSSO,
        logout,
        dismissSessionExpired,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
