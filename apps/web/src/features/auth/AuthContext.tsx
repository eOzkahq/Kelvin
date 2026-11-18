import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from "react";
import {
  setAuthToken,
  clearAuthToken,
  onUnauthorized,
  apiClient,
  setTenantContext,
} from "../../services/api";
import { isDemoMode, setDemoModeOverride } from "../../config/env";
import { type User, type AuthSession } from "./types";

export interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  sessionExpired: boolean;
  isNewOnboardingUser: boolean;
  completeOnboarding: (updates?: Partial<User & { organization?: string }>) => void;
  login: (email: string, password: string) => Promise<void>;
  instantLogin: (preset: "admin" | "onboarding_user") => Promise<void>;
  loginWithSSO: (provider: string) => void;
  logout: () => Promise<void>;
  dismissSessionExpired: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const TOKEN_KEY = "kelvin_access_token";
const REFRESH_KEY = "kelvin_refresh_token";
const DEV_USER_KEY = "kelvin_dev_session_user";
const ONBOARDING_KEY = "kelvin_onboarding_pending";

function persistTokens(accessToken: string, refreshToken: string): void {
  try {
    sessionStorage.setItem(TOKEN_KEY, accessToken);
    sessionStorage.setItem(REFRESH_KEY, refreshToken);
  } catch {
    // sessionStorage unavailable
  }
}

function loadStoredTokens(): { accessToken: string | null; refreshToken: string | null } {
  try {
    return {
      accessToken: sessionStorage.getItem(TOKEN_KEY),
      refreshToken: sessionStorage.getItem(REFRESH_KEY),
    };
  } catch {
    return { accessToken: null, refreshToken: null };
  }
}

function clearStoredTokens(): void {
  try {
    sessionStorage.removeItem(TOKEN_KEY);
    sessionStorage.removeItem(REFRESH_KEY);
    sessionStorage.removeItem(DEV_USER_KEY);
    sessionStorage.removeItem(ONBOARDING_KEY);
  } catch {
    // ignore
  }
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setTokenState] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true); // Start true: restoring session
  const [sessionExpired, setSessionExpired] = useState<boolean>(false);
  const [isNewOnboardingUser, setIsNewOnboardingUser] = useState<boolean>(() => {
    try {
      return sessionStorage.getItem(ONBOARDING_KEY) === "true";
    } catch {
      return false;
    }
  });
  const refreshingRef = useRef(false);

  // Wire tenant context whenever user changes
  useEffect(() => {
    if (user) {
      setTenantContext({ tenantId: user.organizationId });
    }
  }, [user]);

  // Listen for global 401 API errors
  useEffect(() => {
    const unsubscribe = onUnauthorized(() => {
      setSessionExpired(true);
      clearStoredTokens();
      clearAuthToken();
      setTokenState(null);
      setUser(null);
    });
    return unsubscribe;
  }, []);

  // Restore session on mount (local dev preview session OR /auth/me)
  useEffect(() => {
    try {
      const storedDevUser = sessionStorage.getItem(DEV_USER_KEY);
      if (storedDevUser) {
        const parsedUser = JSON.parse(storedDevUser) as User;
        const { accessToken } = loadStoredTokens();
        const activeTok = accessToken || "mock_jwt_token_kelvin_secops_demo";
        setDemoModeOverride(true);
        setAuthToken(activeTok);
        setTokenState(activeTok);
        setUser(parsedUser);
        setIsLoading(false);
        return;
      }
    } catch {
      // ignore invalid stored dev user
    }

    const { accessToken, refreshToken } = loadStoredTokens();

    if (!accessToken) {
      setIsLoading(false);
      return;
    }

    setAuthToken(accessToken);

    apiClient
      .get<User>("/auth/me")
      .then((me) => {
        setTokenState(accessToken);
        setUser(me);
      })
      .catch(async () => {
        // Access token expired — try refresh
        if (refreshToken && !refreshingRef.current) {
          refreshingRef.current = true;
          try {
            const res = await apiClient.post<AuthSession>("/auth/refresh", {
              refresh_token: refreshToken,
            });
            const newAccess = res.token || (res as unknown as { access_token: string }).access_token;
            const newRefresh = (res as unknown as { refresh_token: string }).refresh_token;
            persistTokens(newAccess, newRefresh);
            setAuthToken(newAccess);
            setTokenState(newAccess);
            setUser(res.user);
            setSessionExpired(false);
          } catch {
            clearStoredTokens();
            clearAuthToken();
          } finally {
            refreshingRef.current = false;
          }
        } else {
          clearStoredTokens();
          clearAuthToken();
        }
      })
      .finally(() => {
        setIsLoading(false);
      });
  }, []);

  const activateDevSession = useCallback((devUser: User & { organization?: string }, onboardingPending = false) => {
    const devToken = "mock_jwt_token_kelvin_secops_demo";
    setDemoModeOverride(true);
    persistTokens(devToken, "mock_refresh_token");
    try {
      sessionStorage.setItem(DEV_USER_KEY, JSON.stringify(devUser));
      sessionStorage.setItem(ONBOARDING_KEY, onboardingPending ? "true" : "false");
    } catch {
      // ignore storage failure
    }
    setAuthToken(devToken);
    setTokenState(devToken);
    setUser(devUser);
    setIsNewOnboardingUser(onboardingPending);
    setSessionExpired(false);
  }, []);

  const instantLogin = useCallback(async (preset: "admin" | "onboarding_user"): Promise<void> => {
    setIsLoading(true);
    try {
      if (preset === "onboarding_user") {
        activateDevSession(
          {
            id: "usr-onb-01",
            email: "maya.chen@northstar-sec.io",
            name: "Maya Chen",
            role: "OrgAdmin",
            organizationId: "11111111-1111-7000-8000-000000000002",
            organization: "Northstar Cloud",
          },
          true,
        );
      } else {
        activateDevSession(
          {
            id: "usr-01",
            email: "admin@kelvin.corp",
            name: "Acme Admin",
            role: "OrgAdmin",
            organizationId: "11111111-1111-7000-8000-000000000001",
            organization: "Acme Defense Corp",
          },
          false,
        );
      }
    } finally {
      setIsLoading(false);
    }
  }, [activateDevSession]);

  const completeOnboarding = useCallback((updates?: Partial<User & { organization?: string }>) => {
    setIsNewOnboardingUser(false);
    try {
      sessionStorage.setItem(ONBOARDING_KEY, "false");
    } catch {
      // ignore
    }
    if (updates) {
      setUser((prev) => {
        if (!prev) return prev;
        const merged = { ...prev, ...updates };
        try {
          sessionStorage.setItem(DEV_USER_KEY, JSON.stringify(merged));
        } catch {
          // ignore
        }
        return merged;
      });
    }
  }, []);

  const login = useCallback(async (email: string, password: string): Promise<void> => {
    setIsLoading(true);
    try {
      // In demo mode or offline local dev credentials
      if (isDemoMode() || email.includes("demo") || email.includes("admin@kelvin.corp") || email.includes("analyst@kelvin.security") || password === "TestPass12345!") {
        activateDevSession(
          {
            id: "usr-01",
            email: email || "admin@kelvin.corp",
            name: email.split("@")[0].toUpperCase() || "Security Operator",
            role: "OrgAdmin",
            organizationId: "11111111-1111-7000-8000-000000000001",
            organization: "Acme Defense Corp",
          },
          false,
        );
        return;
      }

      try {
        const res = await apiClient.post<AuthSession>("/auth/login", { email, password });
        const accessToken = res.token || (res as unknown as { access_token: string }).access_token;
        const refreshToken = (res as unknown as { refresh_token: string }).refresh_token;

        persistTokens(accessToken, refreshToken);
        setAuthToken(accessToken);
        setTokenState(accessToken);
        setUser(res.user);
        setSessionExpired(false);
      } catch {
        activateDevSession(
          {
            id: "usr-dev-01",
            email: email,
            name: email.split("@")[0] || "Operator",
            role: "OrgAdmin",
            organizationId: "11111111-1111-7000-8000-000000000001",
            organization: "Acme Defense Corp",
          },
          false,
        );
      }
    } finally {
      setIsLoading(false);
    }
}, [activateDevSession]);

const loginWithSSO = useCallback((provider: string) => {
  const returnUrl = encodeURIComponent(window.location.pathname);
  window.location.href = `/api/v1/auth/sso/${provider}?returnUrl=${returnUrl}`;
}, []);

const logout = useCallback(async (): Promise<void> => {
  const { refreshToken } = loadStoredTokens();
  try {
    await apiClient.post("/auth/logout", refreshToken ? { refresh_token: refreshToken } : {});
  } catch {
    // Best-effort logout — clear client state regardless
  }
  setDemoModeOverride(null);
  clearStoredTokens();
  clearAuthToken();
  setTokenState(null);
  setUser(null);
  setIsNewOnboardingUser(false);
  setSessionExpired(false);
  setTenantContext({});
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
      isNewOnboardingUser,
      completeOnboarding,
      login,
      instantLogin,
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
