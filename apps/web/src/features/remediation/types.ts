export interface RemediationTask {
  id: string;
  findingId: string;
  title: string;
  status: "BACKLOG" | "IN_PROGRESS" | "VERIFYING" | "RESOLVED";
  assignee?: string;
  dueDate?: string;
}
