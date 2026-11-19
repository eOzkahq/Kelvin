import React, { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAuth } from "../features/auth/AuthContext";
import { Button, Input, Card, BrandMark } from "../components/ui";
import { LockIcon } from "../components/ui/Icons";

export default function LoginPage() {
  const { login, instantLogin, loginWithSSO, isLoading } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const rawReturnUrl = searchParams.get("returnUrl") || "/dashboard";
  const basename = (import.meta.env.VITE_ROUTER_BASENAME ?? import.meta.env.BASE_URL ?? "/services/kelvin").replace(/\/+$/, "");
  let returnUrl = rawReturnUrl;
  if (basename && basename !== "/" && returnUrl.startsWith(basename)) {
    returnUrl = returnUrl.slice(basename.length) || "/dashboard";
  }
  // Enforce local relative path to prevent open redirect vulnerabilities
  if (!returnUrl.startsWith("/") || returnUrl.startsWith("//")) {
    returnUrl = "/dashboard";
  }

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
      navigate(returnUrl, { replace: true });
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Authentication failed. Check your email and password.");
    }
  };

  return (
    <div className="relative min-h-screen w-full bg-zinc-950 text-zinc-100 flex items-center justify-center px-4 py-10">
      <div className="w-full max-w-4xl grid grid-cols-1 lg:grid-cols-12 gap-10 items-center">
        {/* Left Brand & Workspace Overview */}
        <div className="hidden lg:flex lg:col-span-5 flex-col justify-between space-y-8">
            <div className="space-y-5">
              <BrandMark variant="full" />

                <p className="text-[15px] text-zinc-300 leading-relaxed">
                  Verify target ownership, run isolated vulnerability scans, and generate signed executive security reports across your organization.
                </p>
            </div>

            <div className="border-t border-zinc-800/80 pt-5 space-y-3 text-xs text-zinc-400">
              <div className="flex items-center justify-between">
                <span className="text-zinc-200 font-medium">Supported Scanners</span>
                <span className="font-mono text-zinc-400">Nmap · Nuclei · Trivy · ZAP</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-zinc-200 font-medium">Scope Verification</span>
                <span className="font-mono text-zinc-400">DNS TXT / HTTP Well-Known</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-zinc-200 font-medium">Free Tier Coupon</span>
                <span className="font-mono text-[var(--brand-text)] font-medium">eozka100 (All Paid Tiers)</span>
              </div>
            </div>
          </div>

          {/* Right Sign-In Form */}
          <div className="lg:col-span-7 w-full max-w-md mx-auto space-y-4">
            {/* Mobile Brand Header */}
            <div className="flex flex-col items-center text-center space-y-2 lg:hidden">
              <BrandMark variant="compact" />
              <h1 className="text-xl font-bold tracking-tight text-zinc-100 font-display pt-1">
                Sign in to Kelvin
              </h1>
            </div>

            <Card variant="default" className="p-6 sm:p-7">
              <div className="mb-5 hidden lg:block">
                <h1 className="text-lg font-semibold tracking-tight text-zinc-100 font-display">
                  Sign in
                </h1>
                <p className="text-xs text-zinc-400 mt-1">
                  Enter your workspace credentials or authenticate via SSO.
                </p>
              </div>

              {error && (
                <div className="mb-4 rounded-lg border border-red-800/80 bg-red-950/50 p-3 text-xs text-red-300">
                  {error}
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-4">
                <Input
                  label="Work Email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@kelvin.com"
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
                  <label className="flex items-center gap-2 text-zinc-400 cursor-pointer">
                    <input type="checkbox" className="rounded border-zinc-700 bg-zinc-900" />
                    <span>Remember workstation</span>
                  </label>
                  <a href="#reset" className="text-[var(--brand-text)] hover:underline transition-colors">
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

                {/* Instant Preview Access */}
                <div className="pt-3 border-t border-zinc-800/70 space-y-2">
                  <p className="text-[10px] font-mono uppercase tracking-wider text-zinc-500">
                    Instant Workspace Access
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="w-full justify-center text-xs"
                      onClick={() => {
                        void instantLogin("onboarding_user").then(() => {
                          navigate("/onboarding", { replace: true });
                        });
                      }}
                    >
                      User + Onboarding
                    </Button>
                    <Button
                      type="button"
                      variant="secondary"
                      size="sm"
                      className="w-full justify-center text-xs"
                      onClick={() => {
                        void instantLogin("admin").then(() => {
                          navigate(returnUrl, { replace: true });
                        });
                      }}
                    >
                      Admin Workspace
                    </Button>
                  </div>
                </div>
              </form>

              {/* SSO Separator */}
              <div className="relative my-5">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-zinc-800/90" />
                </div>
                <div className="relative flex justify-center text-[10px] font-mono uppercase tracking-wider">
                  <span className="bg-zinc-900 px-2.5 text-zinc-500">Single Sign-On</span>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-2">
                <Button
                  type="button"
                  variant="secondary"
                  className="w-full justify-center text-xs"
                  leftIcon={<LockIcon size={14} className="text-[var(--brand-text)]" />}
                  onClick={() => loginWithSSO("saml")}
                >
                  Continue with Okta / SAML 2.0
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  className="w-full justify-center text-xs"
                  onClick={() => loginWithSSO("google")}
                >
                  Continue with Google Workspace
                </Button>
              </div>
            </Card>
          </div>
        </div>
      </div>
      );
}
