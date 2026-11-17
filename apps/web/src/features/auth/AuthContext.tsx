import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from "react";
import {
  setAuthToken,
  clearAuthToken,
  onUnauthorized,
  apiClient,
  setTenantContext,
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
  logout: () => Promise<void>;
  dismissSessionExpired: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const TOKEN_KEY = "kelvin_access_token";
const REFRESH_KEY = "kelvin_refresh_token";

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
  } catch {
    // ignore
  }
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [token, setTokenState] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true); // Start true: restoring session
  const [sessionExpired, setSessionExpired] = useState<boolean>(false);
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

  // Restore session on mount via /auth/me
  useEffect(() => {
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
            // The initial /auth/me 401 is recoverable when refresh succeeds.
            setSessionExpired(false);
          } catch {
            // Refresh failed — force clean state
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

  const login = useCallback(async (email: string, password: string): Promise<void> => {
    setIsLoading(true);
    try {
      const res = await apiClient.post<AuthSession>("/auth/login", { email, password });
      // API returns { token, refresh_token, user } inside success envelope
      const accessToken = res.token || (res as unknown as { access_token: string }).access_token;
      const refreshToken = (res as unknown as { refresh_token: string }).refresh_token;

      persistTokens(accessToken, refreshToken);
      setAuthToken(accessToken);
      setTokenState(accessToken);
      setUser(res.user);
      setSessionExpired(false);
    } finally {
      setIsLoading(false);
    }
  }, []);

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
    clearStoredTokens();
    clearAuthToken();
    setTokenState(null);
    setUser(null);
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
