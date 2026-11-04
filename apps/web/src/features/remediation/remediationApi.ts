import { request } from "../../services/api";
import type {
  RemediationFilterParams,
  RemediationNote,
  RemediationStatus,
  RemediationTask,
  VerificationStatus,
} from "./types";

let mockTasksStore: RemediationTask[] = [
  {
    id: "rem-101",
    findingId: "fnd-001",
    findingTitle: "Apache Log4j Remote Code Execution (Log4Shell)",
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
    updatedAt: "2026-11-03T10:00:00Z",
  },
  {
    id: "rem-102",
    findingId: "fnd-002",
    findingTitle: "SQL Injection in Search Query Handler",
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
    updatedAt: "2026-11-02T08:00:00Z",
  },
  {
    id: "rem-103",
    findingId: "fnd-003",
    findingTitle: "Spring Framework Remote Code Execution (Spring4Shell)",
    severity: "HIGH",
    target: "portal.staging.kelvin-sec.internal",
    affectedEndpoint: "https://portal.staging.kelvin-sec.internal/helloworld",
    assignee: "carol@kelvin.io",
    team: "Backend Engineering",
    status: "VERIFICATION_PENDING",
    verificationStatus: "VERIFICATION_QUEUED",
    dueDate: "2026-11-07T00:00:00Z",
    slaHoursRemaining: 84,
    isOverdue: false,
    remediationGuidance: "Upgrade spring-framework to >= 5.3.18 or apply system properties disallowing ClassLoader bindings.",
    prUrl: "https://github.com/Inkesk-Dozing/Kelvin/pull/425",
    commitSha: "a91b2c3",
    notes: [
      {
        id: "not-02",
        author: "carol@kelvin.io",
        content: "Hotfix deployed to staging. Queued automated follow-up verification scan.",
        createdAt: "2026-11-03T14:30:00Z",
      },
    ],
    updatedAt: "2026-11-03T14:30:00Z",
  },
  {
    id: "rem-104",
    findingId: "fnd-004",
    findingTitle: "Expired TLS/SSL Certificate on Edge Router",
    severity: "HIGH",
    target: "edge-router-01.kelvin-sec.internal",
    affectedEndpoint: "edge-router-01.kelvin-sec.internal:443",
    assignee: "dave@kelvin.io",
    team: "Network Operations",
    status: "BLOCKED",
    dueDate: "2026-11-05T09:00:00Z",
    slaHoursRemaining: 36,
    isOverdue: false,
    remediationGuidance: "Renew external CA wildcard certificate through DigiCert portal.",
    notes: [
      {
        id: "not-03",
        author: "dave@kelvin.io",
        content: "Waiting on corporate domain validation approval from enterprise DNS admin team.",
        createdAt: "2026-11-03T09:15:00Z",
      },
    ],
    verificationStatus: "UNVERIFIED",
    updatedAt: "2026-11-03T09:15:00Z",
  },
  {
    id: "rem-105",
    findingId: "fnd-007",
    findingTitle: "Exposed SSH Daemon on Public Cloud Interface",
    severity: "MEDIUM",
    target: "198.51.100.42",
    affectedEndpoint: "198.51.100.42:22",
    assignee: "dave@kelvin.io",
    team: "Network Operations",
    status: "RESOLVED",
    verificationStatus: "VERIFIED_RESOLVED",
    dueDate: "2026-11-12T00:00:00Z",
    slaHoursRemaining: 210,
    isOverdue: false,
    remediationGuidance: "Restrict security group ingress rule on TCP 22 to corporate bastion CIDR.",
    notes: [
      {
        id: "not-04",
        author: "scanner:nmap",
        content: "Automated scan #41 confirmed TCP port 22 is closed/filtered to outside scanners.",
        createdAt: "2026-10-27T18:00:00Z",
      },
    ],
    updatedAt: "2026-10-27T18:00:00Z",
  },
  {
    id: "rem-106",
    findingId: "fnd-010",
    findingTitle: "Verbose Server Banner in HTTP Response Headers",
    severity: "INFO",
    target: "portal.staging.kelvin-sec.internal",
    affectedEndpoint: "https://portal.staging.kelvin-sec.internal/api/version",
    assignee: "alice@kelvin.io",
    team: "Security Infrastructure",
    status: "ACCEPTED_RISK",
    verificationStatus: "UNVERIFIED",
    dueDate: "2026-11-30T00:00:00Z",
    slaHoursRemaining: 648,
    isOverdue: false,
    remediationGuidance: "Turn server_tokens off in nginx ingress config.",
    notes: [
      {
        id: "not-05",
        author: "alice@kelvin.io",
        content: "Low risk information leakage inside internal staging network. Accepted by CISO exception #EX-2026-44.",
        createdAt: "2026-10-29T10:00:00Z",
      },
    ],
    updatedAt: "2026-10-29T10:00:00Z",
  },
];

export async function fetchRemediationTasks(
  filters?: RemediationFilterParams
): Promise<RemediationTask[]> {
  const query = new URLSearchParams();
  if (filters?.search) query.set("search", filters.search);
  if (filters?.status) query.set("status", filters.status);
  if (filters?.severity) query.set("severity", filters.severity);
  if (filters?.assignee) query.set("assignee", filters.assignee);
  if (filters?.slaStatus) query.set("slaStatus", filters.slaStatus);
  if (filters?.target) query.set("target", filters.target);

  try {
    const res = await request<RemediationTask[]>(`/remediation/tasks?${query.toString()}`);
    if (res && Array.isArray(res)) return res;
  } catch {
    // Client-side fallback filter
  }

  let tasks = [...mockTasksStore];

  if (filters?.search) {
    const q = filters.search.toLowerCase();
    tasks = tasks.filter(
      (t) =>
        t.findingTitle.toLowerCase().includes(q) ||
        t.target.toLowerCase().includes(q) ||
        t.assignee.toLowerCase().includes(q) ||
        t.affectedEndpoint.toLowerCase().includes(q)
    );
  }

  if (filters?.status) {
    tasks = tasks.filter((t) => t.status === filters.status);
  }

  if (filters?.severity) {
    tasks = tasks.filter((t) => t.severity === filters.severity);
  }

  if (filters?.assignee) {
    tasks = tasks.filter((t) => t.assignee === filters.assignee);
  }

  if (filters?.target) {
    tasks = tasks.filter((t) => t.target.toLowerCase().includes(filters.target!.toLowerCase()));
  }

  if (filters?.slaStatus) {
    if (filters.slaStatus === "OVERDUE") {
      tasks = tasks.filter((t) => t.isOverdue);
    } else if (filters.slaStatus === "BREACH_RISK") {
      tasks = tasks.filter((t) => !t.isOverdue && t.slaHoursRemaining <= 48 && t.status !== "RESOLVED");
    } else if (filters.slaStatus === "HEALTHY") {
      tasks = tasks.filter((t) => !t.isOverdue && t.slaHoursRemaining > 48);
    }
  }

  return tasks;
}

export async function updateTaskStatus(
  taskId: string,
  newStatus: RemediationStatus,
  note?: string
): Promise<RemediationTask> {
  try {
    const res = await request<RemediationTask>(`/remediation/tasks/${taskId}/status`, {
      method: "PATCH",
      body: JSON.stringify({ status: newStatus, note }),
    });
    if (res && res.id) return res;
  } catch {
    // Local fallback update
  }

  const taskIndex = mockTasksStore.findIndex((t) => t.id === taskId);
  if (taskIndex === -1) throw new Error(`Task ${taskId} not found`);

  const task = { ...mockTasksStore[taskIndex], status: newStatus, updatedAt: new Date().toISOString() };
  if (note) {
    task.notes = [
      ...task.notes,
      {
        id: `not-${Date.now()}`,
        author: "analyst@kelvin.io",
        content: note,
        createdAt: new Date().toISOString(),
      },
    ];
  }
  mockTasksStore[taskIndex] = task;
  return task;
}

export async function triggerVerificationScan(
  taskId: string
): Promise<{ verificationJobId: string; status: VerificationStatus }> {
  try {
    const res = await request<{ verificationJobId: string; status: VerificationStatus }>(
      `/remediation/tasks/${taskId}/verify`,
      { method: "POST" }
    );
    if (res && res.verificationJobId) return res;
  } catch {
    // Local fallback simulation
  }

  const taskIndex = mockTasksStore.findIndex((t) => t.id === taskId);
  if (taskIndex !== -1) {
    mockTasksStore[taskIndex] = {
      ...mockTasksStore[taskIndex],
      status: "VERIFICATION_PENDING",
      verificationStatus: "VERIFYING",
      updatedAt: new Date().toISOString(),
    };
  }

  return {
    verificationJobId: `vjob-${Date.now()}`,
    status: "VERIFYING",
  };
}

export async function addRemediationNote(
  taskId: string,
  author: string,
  content: string
): Promise<RemediationNote> {
  const newNote: RemediationNote = {
    id: `not-${Date.now()}`,
    author,
    content,
    createdAt: new Date().toISOString(),
  };

  const taskIndex = mockTasksStore.findIndex((t) => t.id === taskId);
  if (taskIndex !== -1) {
    mockTasksStore[taskIndex].notes.push(newNote);
  }

  return newNote;
}

export function resetMockRemediation(): void {
  mockTasksStore = mockTasksStore.map((t) => ({ ...t, notes: [...t.notes] }));
}
