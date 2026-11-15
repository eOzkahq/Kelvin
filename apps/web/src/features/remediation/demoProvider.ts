import type {
  RemediationFilterParams,
  RemediationNote,
  RemediationStatus,
  RemediationTask,
  VerificationStatus,
} from "./types";

export const INITIAL_TASKS: RemediationTask[] = [
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
    prUrl: "https://github.com/eOzkull/Kelvin/pull/432",
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
    team: "Network Operations",
    status: "OPEN",
    dueDate: "2026-11-03T16:00:00Z",
    slaHoursRemaining: -8,
    isOverdue: true,
    remediationGuidance: "Generate CSR, issue new wildcard cert, and deploy to router termination profile.",
    notes: [],
    verificationStatus: "UNVERIFIED",
    createdAt: "2026-11-01T04:30:00Z",
    updatedAt: "2026-11-01T04:30:00Z",
  },
  {
    id: "rem-105",
    findingId: "fnd-005",
    findingTitle: "Cleartext Transmission of Sensitive Information (HTTP)",
    title: "Enforce HTTPS redirect and HSTS on legacy admin",
    severity: "MEDIUM",
    target: "legacy-admin.staging.kelvin-sec.internal",
    affectedEndpoint: "http://legacy-admin.staging.kelvin-sec.internal:80/status",
    assignee: "eve@kelvin.io",
    team: "DevOps",
    status: "RESOLVED",
    dueDate: "2026-11-05T12:00:00Z",
    slaHoursRemaining: 48,
    isOverdue: false,
    remediationGuidance: "Configure Nginx server block to return 301 HTTPS redirect and Strict-Transport-Security header.",
    notes: [
      {
        id: "not-03",
        author: "eve@kelvin.io",
        content: "Nginx configuration patch applied. Port 80 now forcefully redirects to 443 with HSTS 31536000.",
        createdAt: "2026-11-02T11:45:00Z",
      },
    ],
    verificationStatus: "VERIFIED",
    createdAt: "2026-10-28T10:00:00Z",
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

export const demoRemediationProvider = {
  fetchRemediationTasks(filters?: RemediationFilterParams): Promise<RemediationTask[]> {
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

    if (filters?.target) {
      tasks = tasks.filter((t) => t.target.toLowerCase().includes(filters.target!.toLowerCase()));
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

    return Promise.resolve(tasks);
  },

  updateTaskStatus(
    taskId: string,
    newStatus: RemediationStatus,
    note?: string
  ): Promise<RemediationTask> {
    const taskIndex = mockTasksStore.findIndex((t) => t.id === taskId);
    if (taskIndex === -1) return Promise.reject(new Error(`Task ${taskId} not found`));

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
    return Promise.resolve(task);
  },

  triggerVerificationScan(
    taskId: string
  ): Promise<{ verificationJobId: string; status: VerificationStatus }> {
    const taskIndex = mockTasksStore.findIndex((t) => t.id === taskId);
    if (taskIndex !== -1) {
      mockTasksStore[taskIndex] = {
        ...mockTasksStore[taskIndex],
        status: "VERIFICATION_PENDING",
        verificationStatus: "VERIFYING",
        updatedAt: new Date().toISOString(),
      };
    }

    return Promise.resolve({
      verificationJobId: `vjob-${Date.now()}`,
      status: "VERIFYING",
    });
  },

  addRemediationNote(
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

    return Promise.resolve(newNote);
  },

  resetMockRemediation(): void {
    mockTasksStore = JSON.parse(JSON.stringify(INITIAL_TASKS));
  },
};
