import React from "react";

export type FindingSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface SeverityBadgeProps {
  severity: FindingSeverity | string;
  size?: "sm" | "md";
  showDot?: boolean;
}

const severityConfig: Record<
  FindingSeverity,
  { label: string; bg: string; text: string; border: string; dot: string }
> = {
  CRITICAL: {
    label: "Critical",
    bg: "bg-red-950/60",
    text: "text-red-300",
    border: "border-red-800/80",
    dot: "bg-red-500",
  },
  HIGH: {
    label: "High",
    bg: "bg-orange-950/60",
    text: "text-orange-300",
    border: "border-orange-800/80",
    dot: "bg-orange-500",
  },
  MEDIUM: {
    label: "Medium",
    bg: "bg-amber-950/60",
    text: "text-amber-300",
    border: "border-amber-800/80",
    dot: "bg-amber-500",
  },
  LOW: {
    label: "Low",
    bg: "bg-blue-950/60",
    text: "text-blue-300",
    border: "border-blue-800/80",
    dot: "bg-blue-500",
  },
  INFO: {
    label: "Info",
    bg: "bg-zinc-900",
    text: "text-zinc-400",
    border: "border-zinc-700",
    dot: "bg-zinc-500",
  },
};

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = "md",
  showDot = true,
}) => {
  const normalized = (severity.toUpperCase() as FindingSeverity) || "INFO";
  const config = severityConfig[normalized] ?? severityConfig.INFO;

  const sizeClass = size === "sm" ? "px-1.5 py-0.5 text-[10px]" : "px-2.5 py-1 text-xs";

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-medium border rounded-full font-mono uppercase tracking-wider ${config.bg} ${config.text} ${config.border} ${sizeClass}`}
      role="status"
      aria-label={`Severity: ${config.label}`}
    >
      {showDot && (
        <span
          className={`h-1.5 w-1.5 rounded-full ${config.dot}`}
          aria-hidden="true"
        />
      )}
      <span>{config.label}</span>
    </span>
  );
};
