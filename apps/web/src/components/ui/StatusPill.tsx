import React from "react";

export type ExecutionStatus =
  | "PENDING"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED"
  | "CANCELLED"
  | "TIMED_OUT"
  | "OPEN"
  | "CONFIRMED"
  | "IN_PROGRESS"
  | "RESOLVED"
  | "FALSE_POSITIVE"
  | "ACCEPTED_RISK"
  | "BLOCKED"
  | "VERIFICATION_PENDING"
  | "VERIFIED"
  | "READY"
  | "ACTIVE";

export interface StatusPillProps {
  status: ExecutionStatus | string;
}

const statusConfig: Record<
  ExecutionStatus,
  { label: string; bg: string; text: string; border: string; dot: string; animate?: boolean }
> = {
  PENDING: {
    label: "Queued",
    bg: "bg-zinc-900/90",
    text: "text-zinc-300",
    border: "border-zinc-700/80",
    dot: "bg-zinc-400",
  },
  RUNNING: {
    label: "Running",
    bg: "bg-[var(--brand-bg)]",
    text: "text-[var(--brand-text)]",
    border: "border-[var(--brand-border)]",
    dot: "bg-[var(--brand)]",
    animate: true,
  },
  COMPLETED: {
    label: "Completed",
    bg: "bg-emerald-950/60",
    text: "text-emerald-300",
    border: "border-emerald-800/70",
    dot: "bg-emerald-400",
  },
  FAILED: {
    label: "Failed",
    bg: "bg-red-950/60",
    text: "text-red-300",
    border: "border-red-800/70",
    dot: "bg-red-400",
  },
  TIMED_OUT: {
    label: "Timed Out",
    bg: "bg-red-950/60",
    text: "text-red-300",
    border: "border-red-800/70",
    dot: "bg-red-400",
  },
  CANCELLED: {
    label: "Cancelled",
    bg: "bg-zinc-900/90",
    text: "text-zinc-400",
    border: "border-zinc-800",
    dot: "bg-zinc-500",
  },
  OPEN: {
    label: "Open",
    bg: "bg-amber-950/50",
    text: "text-amber-300",
    border: "border-amber-800/60",
    dot: "bg-amber-400",
  },
  CONFIRMED: {
    label: "Confirmed",
    bg: "bg-orange-950/50",
    text: "text-orange-300",
    border: "border-orange-800/60",
    dot: "bg-orange-400",
  },
  IN_PROGRESS: {
    label: "In Progress",
    bg: "bg-[var(--brand-bg)]",
    text: "text-[var(--brand-text)]",
    border: "border-[var(--brand-border)]",
    dot: "bg-[var(--brand)]",
    animate: true,
  },
  RESOLVED: {
    label: "Resolved",
    bg: "bg-emerald-950/60",
    text: "text-emerald-300",
    border: "border-emerald-800/70",
    dot: "bg-emerald-400",
  },
  FALSE_POSITIVE: {
    label: "False Positive",
    bg: "bg-zinc-900/90",
    text: "text-zinc-400",
    border: "border-zinc-700/80",
    dot: "bg-zinc-500",
  },
  ACCEPTED_RISK: {
    label: "Risk Accepted",
    bg: "bg-slate-900/80",
    text: "text-slate-300",
    border: "border-slate-700/80",
    dot: "bg-slate-400",
  },
  BLOCKED: {
    label: "Blocked",
    bg: "bg-red-950/60",
    text: "text-red-300",
    border: "border-red-800/70",
    dot: "bg-red-400",
  },
  VERIFICATION_PENDING: {
    label: "Verifying",
    bg: "bg-purple-950/50",
    text: "text-purple-300",
    border: "border-purple-800/60",
    dot: "bg-purple-400",
    animate: true,
  },
  VERIFIED: {
    label: "Verified",
    bg: "bg-emerald-950/60",
    text: "text-emerald-300",
    border: "border-emerald-800/70",
    dot: "bg-emerald-400",
  },
  READY: {
    label: "Ready",
    bg: "bg-emerald-950/60",
    text: "text-emerald-300",
    border: "border-emerald-800/70",
    dot: "bg-emerald-400",
  },
  ACTIVE: {
    label: "Active",
    bg: "bg-emerald-950/60",
    text: "text-emerald-300",
    border: "border-emerald-800/70",
    dot: "bg-emerald-400",
  },
};

export const StatusPill: React.FC<StatusPillProps> = ({ status }) => {
  const normalized = (status?.toUpperCase() as ExecutionStatus) || "PENDING";
  const config = statusConfig[normalized] ?? {
    label: status.replace(/_/g, " "),
    bg: "bg-zinc-900",
    text: "text-zinc-300",
    border: "border-zinc-700",
    dot: "bg-zinc-400",
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-medium border font-mono tracking-wide uppercase shadow-xs ${config.bg} ${config.text} ${config.border}`}
      role="status"
      aria-label={`Status: ${config.label}`}
    >
      <span className="relative flex h-1.5 w-1.5" aria-hidden="true">
        {config.animate && (
          <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping ${config.dot}`} />
        )}
        <span className={`relative inline-flex rounded-full h-1.5 w-1.5 ${config.dot}`} />
      </span>
      <span>{config.label}</span>
    </span>
  );
};
