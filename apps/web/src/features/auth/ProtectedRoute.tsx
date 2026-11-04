import React from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "./AuthContext";

export interface ProtectedRouteProps {
  children: React.ReactNode;
  allowedRoles?: string[];
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children, allowedRoles }) => {
  const { isAuthenticated, user, isLoading } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <span className="text-xs text-zinc-500">Verifying security credentials…</span>
      </div>
    );
  }

  if (!isAuthenticated || !user) {
    const returnUrl = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/login?returnUrl=${returnUrl}`} replace />;
  }

  if (allowedRoles && allowedRoles.length > 0 && !allowedRoles.includes(user.role)) {
    return (
      <div className="p-8 text-center border border-red-900/50 bg-red-950/20 rounded-lg max-w-md mx-auto mt-12">
        <h3 className="text-base font-semibold text-red-300">Access Denied (403)</h3>
        <p className="text-xs text-zinc-400 mt-2">
          Your account role (<span className="font-mono text-cyan-400">{user.role}</span>) does not possess authorization to view this resource.
        </p>
      </div>
    );
  }

  return <>{children}</>;
};
