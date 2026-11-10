import { request } from "../../services/api";
import { isDemoMode } from "../../config/env";
import { demoRemediationProvider, INITIAL_TASKS } from "./demoProvider";
import type {
  RemediationFilterParams,
  RemediationNote,
  RemediationStatus,
  RemediationTask,
  VerificationStatus,
} from "./types";

export type {
  RemediationFilterParams,
  RemediationNote,
  RemediationStatus,
  RemediationTask,
  VerificationStatus,
};

const INITIAL_TASKS: RemediationTask[] = [
  {
    id: "rem-101",
    findingId: "fnd-001",
    findingTitle: "Apache Log4j Remote Code Execution (Log4Shell)",
    title: "Remediate Log4Shell RCE in auth service",
    severity: "CRITICAL",
    target: "api.staging.kelvin-sec.internal",
    affectedEndpoint: "https://api.staging.kelvin-sec.internal:8443/auth/ldap",
    assignee: "alice@kelvin.io",
    team: "Security Infrastructure",
    status: "IN_PROGRESS",
    verificationStatus: "UNVERIFIED",
    dueDate: "2026-11-04T12:00:00Z",
    slaHoursRemaining: 18,
    isOverdue: false,
    remediationGuidance: "Bump log4j-core dependency to >= 2.17.1 across microservice POMs and Docker base images.",
    prUrl: "https://github.com/Inkesk-Dozing/Kelvin/pull/432",
    commitSha: "1056b5a",
    notes: [
      {
        id: "not-01",
        author: "alice@kelvin.io",
        content: "Drafted dependency upgrade PR. Testing compatibility in staging integration cluster.",
        createdAt: "2026-11-03T10:00:00Z",
      },
    ],
    createdAt: "2026-11-01T08:00:00Z",
    updatedAt: "2026-11-03T10:00:00Z",
  },
  {
    id: "rem-102",
    findingId: "fnd-002",
    findingTitle: "SQL Injection in Search Query Handler",
    title: "Parameterize SQL query in search handler",
    severity: "CRITICAL",
    target: "app.staging.kelvin-sec.internal",
    affectedEndpoint: "https://app.staging.kelvin-sec.internal/api/v1/search?q=",
    assignee: "bob@kelvin.io",
    team: "Application Security",
    status: "OPEN",
    dueDate: "2026-11-02T18:00:00Z",
    slaHoursRemaining: -26,
    isOverdue: true,
    remediationGuidance: "Migrate raw string concatenation query in search repo to parameterized prepared statement.",
    notes: [],
    verificationStatus: "UNVERIFIED",
    createdAt: "2026-10-30T09:00:00Z",
    updatedAt: "2026-11-02T08:00:00Z",
  },
  {
    id: "rem-103",
    findingId: "fnd-003",
    findingTitle: "Spring Framework Remote Code Execution (Spring4Shell)",
    title: "Upgrade Spring Framework version",
    severity: "HIGH",
    target: "portal.staging.kelvin-sec.internal",
    affectedEndpoint: "https://portal.staging.kelvin-sec.internal/helloworld",
    assignee: "carol@kelvin.io",
    team: "Backend Engineering",
    status: "BLOCKED",
    dueDate: "2026-11-08T10:00:00Z",
    slaHoursRemaining: 112,
    isOverdue: false,
    remediationGuidance: "Upgrade org.springframework:spring-webmvc to version 5.3.18 or higher.",
    prUrl: "",
    notes: [
      {
        id: "not-02",
        author: "carol@kelvin.io",
        content: "Blocked by legacy JDK 8 runtime deprecation in portal service.",
        createdAt: "2026-11-02T15:30:00Z",
      },
    ],
    verificationStatus: "UNVERIFIED",
    createdAt: "2026-11-02T10:00:00Z",
    updatedAt: "2026-11-02T15:30:00Z",
  },
  {
    id: "rem-104",
    findingId: "fnd-004",
    findingTitle: "Expired TLS/SSL Certificate on Edge Router",
    title: "Renew edge router TLS certificate",
    severity: "HIGH",
    target: "edge-router-01.kelvin-sec.internal",
    affectedEndpoint: "edge-router-01.kelvin-sec.internal:443",
    assignee: "dave@kelvin.io",
    team: "Site Reliability",
    status: "VERIFICATION_PENDING",
    dueDate: "2026-11-03T08:00:00Z",
    slaHoursRemaining: 0,
    isOverdue: false,
    remediationGuidance: "Renew and install valid Let's Encrypt or corporate CA signed wildcard certificate.",
    notes: [
      {
        id: "not-03",
        author: "dave@kelvin.io",
        content: "New certificate provisioned via automated Vault PKI engine.",
        createdAt: "2026-11-03T07:45:00Z",
      },
    ],
    verificationStatus: "VERIFYING",
    createdAt: "2026-11-01T12:00:00Z",
    updatedAt: "2026-11-03T07:45:00Z",
  },
  {
    id: "rem-105",
    findingId: "fnd-005",
    findingTitle: "Container Image Base OS CVE in OpenSSL",
    title: "Patch container base OS OpenSSL",
    severity: "HIGH",
    target: "registry.kelvin-sec.internal/kelvin-core:v2.1",
    affectedEndpoint: "docker-image://kelvin-core:v2.1",
    assignee: "eve@kelvin.io",
    team: "DevSecOps",
    status: "RESOLVED",
    dueDate: "2026-11-02T14:00:00Z",
    slaHoursRemaining: 24,
    isOverdue: false,
    remediationGuidance: "Update base Dockerfile from alpine:3.17 to alpine:3.19.1 containing patched OpenSSL 3.1.4.",
    prUrl: "https://github.com/Inkesk-Dozing/Kelvin/pull/429",
    commitSha: "88ab12e",
    notes: [
      {
        id: "not-04",
        author: "eve@kelvin.io",
        content: "Verified image scan in Harbor CI pipeline. Vulnerability confirmed absent.",
        createdAt: "2026-11-02T12:00:00Z",
      },
    ],
    verificationStatus: "VERIFIED",
    createdAt: "2026-10-31T09:00:00Z",
    updatedAt: "2026-11-02T12:00:00Z",
  },
  {
    id: "rem-106",
    findingId: "fnd-006",
    findingTitle: "Cross-Origin Resource Sharing (CORS) Overly Permissive Wildcard",
    title: "Restrict CORS origin allowlist",
    severity: "MEDIUM",
    target: "api.staging.kelvin-sec.internal",
    affectedEndpoint: "https://api.staging.kelvin-sec.internal/graphql",
    assignee: "frank@kelvin.io",
    team: "Frontend Engineering",
    status: "ACCEPTED_RISK",
    dueDate: "2026-11-10T18:00:00Z",
    slaHoursRemaining: 172,
    isOverdue: false,
    remediationGuidance: "Remove wildcard origin from API gateway CORS configuration and whitelist valid domains.",
    notes: [
      {
        id: "not-05",
        author: "frank@kelvin.io",
        content: "Risk accepted by Head of Security for staging sandbox environment exclusively.",
        createdAt: "2026-11-03T08:30:00Z",
      },
    ],
    verificationStatus: "UNVERIFIED",
    createdAt: "2026-11-01T14:00:00Z",
    updatedAt: "2026-11-03T08:30:00Z",
  },
];

let mockTasksStore: RemediationTask[] = JSON.parse(JSON.stringify(INITIAL_TASKS));

export async function fetchRemediationTasks(
  filters?: RemediationFilterParams
): Promise<RemediationTask[]> {
  try {
    const q = new URLSearchParams();
    if (filters?.status) {
      q.set("status", Array.isArray(filters.status) ? filters.status.join(",") : filters.status);
    }
    if (filters?.assignee) q.set("assignee", filters.assignee);
    if (filters?.search) q.set("q", filters.search);
    const queryStr = q.toString() ? `?${q.toString()}` : "";
    const res = await request<RemediationTask[]>(`/remediation/tasks${queryStr}`);
    if (res && Array.isArray(res)) return res;
  } catch {
    // Fall back to client-side fixture store
  }

  let tasks = [...mockTasksStore];

  if (filters?.status) {
    const statuses = Array.isArray(filters.status) ? filters.status : [filters.status];
    tasks = tasks.filter((t) => statuses.includes(t.status));
  }

  if (filters?.priority) {
    tasks = tasks.filter((t) => t.severity && filters.priority!.includes(t.severity));
  }

  if (filters?.assignee) {
    tasks = tasks.filter((t) => t.assignee === filters.assignee);
  }

  if (filters?.search) {
    const q = filters.search.toLowerCase();
    tasks = tasks.filter(
      (t) =>
        t.title?.toLowerCase().includes(q) ||
        t.findingTitle?.toLowerCase().includes(q) ||
        t.target?.toLowerCase().includes(q)
    );
  }

  if (filters?.slaStatus) {
    if (filters.slaStatus === "OVERDUE") {
      tasks = tasks.filter((t) => t.isOverdue);
    } else if (filters.slaStatus === "HEALTHY") {
      tasks = tasks.filter((t) => !t.isOverdue && (t.slaHoursRemaining ?? 0) > 48);
    }
  }

  return tasks;
}

export async function updateTaskStatus(
  taskId: string,
  newStatus: RemediationStatus,
  note?: string
): Promise<RemediationTask> {
  if (isDemoMode()) {
    return demoRemediationProvider.updateTaskStatus(taskId, newStatus, note);
  }

  return request<RemediationTask>(`/remediation/tasks/${taskId}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status: newStatus, note }),
  });
}

export async function triggerVerificationScan(
  taskId: string
): Promise<{ verificationJobId: string; status: VerificationStatus }> {
  if (isDemoMode()) {
    return demoRemediationProvider.triggerVerificationScan(taskId);
  }

  return request<{ verificationJobId: string; status: VerificationStatus }>(
    `/remediation/tasks/${taskId}/verify`,
    { method: "POST" }
  );
}

export async function addRemediationNote(
  taskId: string,
  author: string,
  content: string
): Promise<RemediationNote> {
  if (isDemoMode()) {
    return demoRemediationProvider.addRemediationNote(taskId, author, content);
  }

  return request<RemediationNote>(`/remediation/tasks/${taskId}/notes`, {
    method: "POST",
    body: JSON.stringify({ author, content }),
  });
}

export function resetMockRemediation(): void {
  mockTasksStore = JSON.parse(JSON.stringify(INITIAL_TASKS));
}
