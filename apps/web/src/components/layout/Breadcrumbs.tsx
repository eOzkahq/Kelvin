import React from "react";
import { Link, useLocation } from "react-router-dom";
import { ChevronRightIcon } from "../ui/Icons";

const routeLabels: Record<string, string> = {
  dashboard: "Dashboard",
  assessments: "Assessments",
  new: "New Assessment",
  findings: "Findings Workspace",
  remediation: "Remediation",
  targets: "Targets & Scope",
  reports: "Report Center",
  compare: "Assessment Comparison",
  audit: "Audit Logs",
  account: "Account Profile",
  profile: "Account Profile",
  admin: "Administration",
  org: "Organization",
  team: "Team & Members",
  roles: "Roles & Permissions",
  integrations: "Integrations",
  settings: "Settings",
  onboarding: "Workspace Onboarding",
  plans: "Plans & Billing",
  checkout: "Checkout",
};

export const Breadcrumbs: React.FC = () => {
  const location = useLocation();
  const pathnames = location.pathname.split("/").filter((x) => x);

  if (pathnames.length === 0) {
    return null;
  }

  return (
    <nav aria-label="Breadcrumb" className="flex items-center text-[11px] font-mono text-zinc-500 py-1">
      <ol className="flex items-center space-x-1.5">
        <li>
          <Link to="/" className="hover:text-zinc-200 transition-colors uppercase tracking-wider">
            Kelvin
          </Link>
        </li>
        {pathnames.map((segment, index) => {
          const to = `/${pathnames.slice(0, index + 1).join("/")}`;
          const isLast = index === pathnames.length - 1;
          const label = routeLabels[segment] || segment;

          return (
            <li key={to} className="flex items-center space-x-1.5">
              <ChevronRightIcon size={11} className="text-zinc-600" />
              {isLast ? (
                  <span className="font-medium text-[var(--brand-text)]" aria-current="page">
                    {label}
                  </span>
                  ) : (
                    <Link to={to} className="hover:text-zinc-100 transition-colors">
                      {label}
                    </Link>
              )}
                  </li>
                  );
        })}
                </ol>
    </nav>
          );
        };
