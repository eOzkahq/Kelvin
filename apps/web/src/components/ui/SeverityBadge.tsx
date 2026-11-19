import React from "react";

export type FindingSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface SeverityBadgeProps {
  severity: FindingSeverity | string;
  size?: "sm" | "md";
  showDot?: boolean;
}

const severityConfig: Record<
  FindingSeverity,
  { label: string; bg: string; text: string; border: string; dot: string; pulse?: boolean }
> = {
  CRITICAL: {
    label: "Critical",
    bg: "bg-red-950/70 shadow-[inset_0_0_12px_rgba(239,68,68,0.12)]",
    text: "text-red-300",
    border: "border-red-700/70",
    dot: "bg-red-400",
    pulse: true,
  },
  HIGH: {
    label: "High",
    bg: "bg-orange-950/65 shadow-[inset_0_0_10px_rgba(249,115,22,0.1)]",
    text: "text-orange-300",
    border: "border-orange-700/70",
    dot: "bg-orange-400",
  },
  MEDIUM: {
    label: "Medium",
    bg: "bg-amber-950/60",
    text: "text-amber-300",
    border: "border-amber-700/65",
    dot: "bg-amber-400",
  },
  LOW: {
    label: "Low",
    bg: "bg-sky-950/60",
    text: "text-sky-300",
    border: "border-sky-800/70",
    dot: "bg-sky-400",
  },
  INFO: {
    label: "Info",
    bg: "bg-zinc-900/90",
    text: "text-zinc-400",
    border: "border-zinc-700/80",
    dot: "bg-zinc-500",
  },
};

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = "md",
  showDot = true,
}) => {
  const normalized = (severity?.toUpperCase() as FindingSeverity) || "INFO";
  const config = severityConfig[normalized] ?? severityConfig.INFO;

  const sizeClass = size === "sm" ? "px-2 py-0.5 text-[10px]" : "px-2.5 py-0.5 text-[11px]";

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-medium border rounded-full font-mono uppercase tracking-wider ${config.bg} ${config.text} ${config.border} ${sizeClass}`}
      role="status"
      aria-label={`Severity: ${config.label}`}
    >
      {showDot && (
        <span className="relative flex h-1.5 w-1.5" aria-hidden="true">
          {config.pulse && (
            <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 animate-ping ${config.dot}`} />
          )}
          <span className={`relative inline-flex rounded-full h-1.5 w-1.5 ${config.dot}`} />
        </span>
      )}
      <span>{config.label}</span>
    </span>
  );
};
