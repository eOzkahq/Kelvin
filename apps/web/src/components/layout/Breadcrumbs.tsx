import React from "react";
import { Link, useLocation } from "react-router-dom";

const routeLabels: Record<string, string> = {
  dashboard: "Dashboard",
  assessments: "Assessments",
  findings: "Findings Workspace",
  remediation: "Remediation",
  targets: "Targets & Scope",
  reports: "Report Center",
  compare: "Assessment Comparison",
  audit: "Audit Logs",
  admin: "Administration",
  org: "Organization",
  team: "Team & Members",
  roles: "Roles & Permissions",
  integrations: "Integrations",
  settings: "Settings",
};

export const Breadcrumbs: React.FC = () => {
  const location = useLocation();
  const pathnames = location.pathname.split("/").filter((x) => x);

  if (pathnames.length === 0) {
    return null;
  }

  return (
    <nav aria-label="Breadcrumb" className="flex items-center text-xs text-zinc-400 py-2">
      <ol className="flex items-center space-x-1.5">
        <li>
          <Link to="/" className="hover:text-zinc-200 transition-colors">
            Home
          </Link>
        </li>
        {pathnames.map((segment, index) => {
          const to = `/${pathnames.slice(0, index + 1).join("/")}`;
          const isLast = index === pathnames.length - 1;
          const label = routeLabels[segment] || segment.charAt(0).toUpperCase() + segment.slice(1);

          return (
            <li key={to} className="flex items-center space-x-1.5">
              <span className="text-zinc-600" aria-hidden="true">
                /
              </span>
              {isLast ? (
                <span className="font-medium text-cyan-400" aria-current="page">
                  {label}
                </span>
              ) : (
                <Link to={to} className="hover:text-zinc-200 transition-colors">
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
