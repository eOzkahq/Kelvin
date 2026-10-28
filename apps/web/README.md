# Kelvin Web — Frontend SPA

The React/TypeScript single-page application dashboard serving the Junior AppSec Analyst, Senior Security Engineer, and Compliance & Platform Administrator personas.

**Technology:** React 18+ + TypeScript + Vite + Tailwind CSS + Radix UI (ADR-0004)  
**Server State:** TanStack Query (React Query)  
**Live Streaming:** WebSocket (WSS) to API Gateway

| Directory | Purpose |
| :--- | :--- |
| `src/components/` | Shared UI components & design system |
| `src/pages/` | Route page components (code-split) |
| `src/hooks/` | Custom React hooks |
| `src/services/` | Typed API client services |
| `src/store/` | Client-side transient UI state |
| `public/` | Static assets |

**Role-scoped views (`docs/product/PERSONAS.md` § 5.1):**
* **Analyst:** Assessments, findings matrix, evidence inspector, remediation tickets
* **Engineer:** Worker fleet health, scan profiles, scanner adapters
* **Admin:** Organization settings, audit trail, authorization register, reports

**Accessibility:** WCAG 2.1 AA conformance required on all UI views (`docs/product/PERSONAS.md` § 6.1).
