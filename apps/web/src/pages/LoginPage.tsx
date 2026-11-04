import React, { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAuth } from "../features/auth/AuthContext";
import { Button, Input, Card } from "../components/ui";

export default function LoginPage() {
  const { login, loginWithSSO, isLoading } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const returnUrl = searchParams.get("returnUrl") || "/dashboard";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!email || !password) {
      setError("Please provide both email address and password.");
      return;
    }

    try {
      await login(email, password);
      navigate(returnUrl);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Authentication failed");
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950 px-4 py-12">
      <div className="w-full max-w-md space-y-6">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 to-cyan-700 font-bold text-xl text-black shadow-lg shadow-cyan-950/60">
            K
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
            Sign in to KELVIN
          </h1>
          <p className="text-xs text-zinc-400">
            Enterprise Security Assessment & Vulnerability Platform
          </p>
        </div>

        {/* Card */}
        <Card variant="accent" className="p-6">
          {error && (
            <div className="mb-4 rounded-md border border-red-800 bg-red-950/50 p-3 text-xs text-red-300">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <Input
              label="Work Email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@enterprise.com"
              required
              autoComplete="email"
            />

            <Input
              label="Password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              required
              autoComplete="current-password"
            />

            <div className="flex items-center justify-between text-xs">
              <label className="flex items-center gap-2 text-zinc-400">
                <input type="checkbox" className="rounded border-zinc-700 bg-zinc-800" />
                <span>Remember this workstation</span>
              </label>
              <a href="#reset" className="text-cyan-400 hover:text-cyan-300">
                Forgot password?
              </a>
            </div>

            <Button
              type="submit"
              variant="primary"
              className="w-full justify-center"
              isLoading={isLoading}
            >
              Sign in with Credentials
            </Button>
          </form>

          {/* SSO Separator */}
          <div className="relative my-6">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-zinc-800" />
            </div>
            <div className="relative flex justify-center text-[10px] uppercase">
              <span className="bg-zinc-900 px-2 text-zinc-500">Or continue with enterprise sso</span>
            </div>
          </div>

          <div className="space-y-2">
            <Button
              type="button"
              variant="secondary"
              className="w-full justify-center text-xs"
              onClick={() => loginWithSSO("saml")}
            >
              🔐 Sign in with Okta / SAML 2.0
            </Button>
            <Button
              type="button"
              variant="secondary"
              className="w-full justify-center text-xs"
              onClick={() => loginWithSSO("google")}
            >
              🌐 Sign in with Google Workspace (OIDC)
            </Button>
          </div>
        </Card>

        {/* Security Notice */}
        <p className="text-center text-[11px] text-zinc-500">
          Strictly authorized personnel only. All access is cryptographically signed and audit logged.
        </p>
      </div>
    </div>
  );
}
