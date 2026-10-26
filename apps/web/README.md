# Kelvin Web — Frontend SPA

The React/TypeScript single-page application dashboard serving the Junior AppSec Analyst, Senior Security Engineer, and Compliance & Platform Administrator personas.

**Technology:** React + TypeScript + Tailwind CSS + shadcn/ui (ADR-0004)

| Directory | Purpose |
| :--- | :--- |
| `src/components/` | Shared UI components (design system) |
| `src/pages/` | Route page components |
| `src/hooks/` | Custom React hooks |
| `src/services/` | API client services |
| `src/store/` | Client-side state |
| `public/` | Static assets |

**Role-scoped views (PERSONAS.md §5.1):**
* Analyst → assessments, findings, remediation
* Engineer → worker fleet, scan profiles, adapters
* Admin → audit trail, authorization register, reports

**Accessibility:** WCAG 2.1 AA conformance required on all UI (PERSONAS.md §6.1).
