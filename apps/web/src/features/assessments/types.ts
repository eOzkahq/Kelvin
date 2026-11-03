export interface Assessment {
  id: string;
  name: string;
  targetId: string;
  profileId: string;
  status: "PENDING" | "RUNNING" | "COMPLETED" | "FAILED" | "CANCELLED";
  createdAt: string;
  completedAt?: string;
}
