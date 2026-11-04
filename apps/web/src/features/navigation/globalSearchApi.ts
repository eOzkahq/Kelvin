import type { SearchResultItem, SearchGroup, SearchCategory } from "./types";

export const STATIC_NAVIGATION_ITEMS: SearchResultItem[] = [
  {
    id: "nav-dashboard",
    title: "Security Dashboard",
    subtitle: "Real-time posture, KPI metrics, active workers",
    category: "navigation",
    url: "/dashboard",
    shortcut: "G D",
    icon: "📊",
  },
  {
    id: "nav-assessments",
    title: "Assessments Catalog",
    subtitle: "Active security scans, scheduled jobs, historical runs",
    category: "navigation",
    url: "/assessments",
    shortcut: "G A",
    icon: "🛡️",
  },
  {
    id: "nav-new-assessment",
    title: "Launch New Assessment",
    subtitle: "7-step assessment configuration and execution wizard",
    category: "action",
    url: "/assessments/new",
    shortcut: "N A",
    icon: "🚀",
  },
  {
    id: "nav-findings",
    title: "Findings Workspace",
    subtitle: "Explore triaged vulnerabilities, CVEs, and CVSS scores",
    category: "navigation",
    url: "/findings",
    shortcut: "G F",
    icon: "🔍",
  },
  {
    id: "nav-remediation",
    title: "Remediation Workspace",
    subtitle: "Interactive Kanban board, SLA timers, and verification triggers",
    category: "navigation",
    url: "/remediation",
    shortcut: "G R",
    icon: "🔧",
  },
  {
    id: "nav-targets",
    title: "Targets & Scope Management",
    subtitle: "Scope boundaries, DNS verification, and asset registry",
    category: "navigation",
    url: "/targets",
    shortcut: "G T",
    icon: "🎯",
  },
  {
    id: "nav-reports",
    title: "Assessment Report Center",
    subtitle: "Executive summaries, PDF downloads, SHA-256 seal verification",
    category: "navigation",
    url: "/reports",
    shortcut: "G P",
    icon: "📄",
  },
  {
    id: "nav-compare",
    title: "Assessment Comparison",
    subtitle: "Diff two historical assessment runs side-by-side",
    category: "navigation",
    url: "/compare",
    icon: "⚖️",
  },
  {
    id: "nav-audit",
    title: "Audit Trail Explorer",
    subtitle: "Tamper-evident cryptographically sealed event logs",
    category: "navigation",
    url: "/audit",
    icon: "📜",
  },
  {
    id: "nav-admin-org",
    title: "Organization Administration",
    subtitle: "Tenant licensing, workspace quotas, tier management",
    category: "navigation",
    url: "/admin/org",
    icon: "🏢",
  },
  {
    id: "nav-admin-team",
    title: "Team Members & Access",
    subtitle: "User roster, functional squad assignments, invitations",
    category: "navigation",
    url: "/admin/team",
    icon: "👥",
  },
  {
    id: "nav-admin-roles",
    title: "Roles, Permissions & SSO",
    subtitle: "RBAC matrix, SAML 2.0 / OIDC identity, SCIM tokens",
    category: "navigation",
    url: "/admin/roles",
    icon: "🔑",
  },
  {
    id: "nav-admin-integrations",
    title: "Integrations & Webhooks",
    subtitle: "Jira Cloud, Slack, SIEM forwarders, webhook subscriptions",
    category: "navigation",
    url: "/admin/integrations",
    icon: "🔌",
  },
  {
    id: "nav-admin-settings",
    title: "Platform & Workspace Settings",
    subtitle: "Execution defaults, data retention rules, scanner controls",
    category: "navigation",
    url: "/admin/settings",
    icon: "⚙️",
  },
  {
    id: "nav-profile",
    title: "User Profile & Security Keys",
    subtitle: "Personal MFA settings, API access tokens, session manager",
    category: "navigation",
    url: "/profile",
    icon: "👤",
  },
];

export const MOCK_ENTITY_ITEMS: SearchResultItem[] = [
  // Targets
  {
    id: "target-api-prod",
    title: "api.kelvin.internal",
    subtitle: "Production Gateway | 10.0.12.50 | Verified DNS TXT",
    category: "target",
    url: "/targets",
    badge: "Production",
    icon: "🌐",
  },
  {
    id: "target-staging-auth",
    title: "staging.auth.kelvin.internal",
    subtitle: "Staging Auth Service | 10.0.14.88 | Scoped",
    category: "target",
    url: "/targets",
    badge: "Staging",
    icon: "🌐",
  },
  {
    id: "target-customer-portal",
    title: "portal.kelvin.internal",
    subtitle: "Customer Web Portal | 10.0.18.22 | Active Scope",
    category: "target",
    url: "/targets",
    badge: "Production",
    icon: "🌐",
  },
  // Assessments
  {
    id: "asm-prod-001",
    title: "ASM-PROD-2026-11-01",
    subtitle: "Production Perimeter Penetration Scan | Status: Running",
    category: "assessment",
    url: "/assessments/asm-prod-001",
    badge: "In Progress",
    icon: "⚡",
  },
  {
    id: "asm-auth-002",
    title: "ASM-STG-AUTH-FULL",
    subtitle: "Staging OAuth & SAML Compliance Assessment | Status: Completed",
    category: "assessment",
    url: "/assessments/asm-auth-002",
    badge: "Completed",
    icon: "✅",
  },
  {
    id: "asm-api-003",
    title: "ASM-API-OWASP-ZAP",
    subtitle: "Continuous Microservices DAST Pipeline | Status: Completed",
    category: "assessment",
    url: "/assessments/asm-api-003",
    badge: "Completed",
    icon: "🛡️",
  },
  // Findings
  {
    id: "fnd-sqli-01",
    title: "SQL Injection in User Authentication Endpoint",
    subtitle: "CVE-2026-4412 | CVSS 9.8 | Target: api.kelvin.internal",
    category: "finding",
    url: "/findings/fnd-sqli-01",
    badge: "CRITICAL",
    icon: "💥",
  },
  {
    id: "fnd-rce-02",
    title: "Remote Code Execution via Report PDF Generator",
    subtitle: "CVE-2026-3891 | CVSS 9.1 | Target: portal.kelvin.internal",
    category: "finding",
    url: "/findings/fnd-rce-02",
    badge: "CRITICAL",
    icon: "💥",
  },
  {
    id: "fnd-ssrf-03",
    title: "Server-Side Request Forgery in Webhook Dispatcher",
    subtitle: "CWE-918 | CVSS 8.2 | Target: staging.auth.kelvin.internal",
    category: "finding",
    url: "/findings/fnd-ssrf-03",
    badge: "HIGH",
    icon: "⚠️",
  },
  {
    id: "fnd-tls-04",
    title: "Deprecated TLS 1.0/1.1 Cipher Suites Enabled",
    subtitle: "CWE-327 | CVSS 5.3 | Target: api.kelvin.internal",
    category: "finding",
    url: "/findings/fnd-tls-04",
    badge: "MEDIUM",
    icon: "⚠️",
  },
];

/**
 * Escapes regex special characters to prevent RegExp injection when searching.
 */
export function escapeRegex(string: string): string {
  return string.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Performs a fast, multi-entity search across static navigation and indexed entities.
 */
export async function searchPlatform(query: string): Promise<SearchResultItem[]> {
  const trimmed = query.trim();
  const allItems = [...STATIC_NAVIGATION_ITEMS, ...MOCK_ENTITY_ITEMS];

  if (!trimmed) {
    // Return recommended quick actions and navigation items when empty
    return allItems.slice(0, 8);
  }

  const escaped = escapeRegex(trimmed);
  const regex = new RegExp(escaped, "i");

  return allItems.filter((item) => {
    return (
      regex.test(item.title) ||
      (item.subtitle && regex.test(item.subtitle)) ||
      (item.badge && regex.test(item.badge))
    );
  });
}

/**
 * Groups search result items by category for hierarchical display.
 */
export function groupSearchResults(items: SearchResultItem[]): SearchGroup[] {
  const categoryOrder: { category: SearchCategory; title: string }[] = [
    { category: "action", title: "Quick Actions" },
    { category: "navigation", title: "Pages & Navigation" },
    { category: "finding", title: "Security Findings" },
    { category: "assessment", title: "Assessments" },
    { category: "target", title: "Targets & Assets" },
  ];

  const groups: SearchGroup[] = [];

  for (const { category, title } of categoryOrder) {
    const matchedItems = items.filter((item) => item.category === category);
    if (matchedItems.length > 0) {
      groups.push({
        category,
        title,
        items: matchedItems,
      });
    }
  }

  return groups;
}
