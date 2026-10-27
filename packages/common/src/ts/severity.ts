export const SEVERITIES = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

export type Severity = (typeof SEVERITIES)[number];

const SEVERITY_RANK: Record<Severity, number> = {
  INFORMATIONAL: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

export function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && (SEVERITIES as readonly string[]).includes(value);
}

export function severityRank(value: Severity): number {
  return SEVERITY_RANK[value];
}
