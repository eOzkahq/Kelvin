import React from "react";

export type ExecutionStatus =
  | "PENDING"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED"
  | "OPEN"
  | "CONFIRMED"
  | "IN_PROGRESS"
  | "RESOLVED"
  | "FALSE_POSITIVE"
  | "ACCEPTED_RISK";

export interface StatusPillProps {
  status: ExecutionStatus | string;
}

const statusConfig: Record<
  string,
  { label: string; bg: string; text: string; border: string; animate?: boolean }
> = {
  PENDING: {
    label: "Queued",
    bg: "bg-zinc-900",
    text: "text-zinc-400",
    border: "border-zinc-700",
  },
  RUNNING: {
    label: "Running",
    bg: "bg-cyan-950/70",
    text: "text-cyan-300",
    border: "border-cyan-700/80",
    animate: true,
  },
  COMPLETED: {
    label: "Completed",
    bg: "bg-emerald-950/60",
    text: "text-emerald-300",
    border: "border-emerald-800/80",
  },
  FAILED: {
    label: "Failed",
    bg: "bg-red-950/60",
    text: "text-red-300",
    border: "border-red-800/80",
  },
  CANCELLED: {
    label: "Cancelled",
    bg: "bg-zinc-900",
    text: "text-zinc-500",
    border: "border-zinc-800",
  },
  // Findings Lifecycle Statuses
  OPEN: {
    label: "Open",
    bg: "bg-red-950/40",
    text: "text-red-400",
    border: "border-red-800/60",
  },
  CONFIRMED: {
    label: "Confirmed",
    bg: "bg-amber-950/40",
    text: "text-amber-300",
    border: "border-amber-800/60",
  },
  IN_PROGRESS: {
    label: "In Progress",
    bg: "bg-cyan-950/40",
    text: "text-cyan-300",
    border: "border-cyan-800/60",
    animate: true,
  },
  RESOLVED: {
    label: "Resolved",
    bg: "bg-emerald-950/50",
    text: "text-emerald-300",
    border: "border-emerald-800/60",
  },
  FALSE_POSITIVE: {
    label: "False Positive",
    bg: "bg-zinc-900/80",
    text: "text-zinc-400",
    border: "border-zinc-700/60",
  },
  ACCEPTED_RISK: {
    label: "Risk Accepted",
    bg: "bg-purple-950/40",
    text: "text-purple-300",
    border: "border-purple-800/60",
  },
};

export const StatusPill: React.FC<StatusPillProps> = ({ status }) => {
  const normalized = (status.toUpperCase() as ExecutionStatus) || "PENDING";
  const config = statusConfig[normalized] ?? statusConfig.PENDING;

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border font-sans ${config.bg} ${config.text} ${config.border}`}
      role="status"
      aria-label={`Status: ${config.label}`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${
          config.animate ? "bg-cyan-400 animate-ping" : "bg-current opacity-70"
        }`}
        aria-hidden="true"
      />
      <span>{config.label}</span>
    </span>
  );
};
