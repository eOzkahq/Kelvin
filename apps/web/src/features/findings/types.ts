export interface FindingSummary {
  id: string;
  fingerprint: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  status: "OPEN" | "CONFIRMED" | "IN_REVIEW" | "RESOLVED" | "SUPPRESSED" | "FALSE_POSITIVE";
  target: string;
  scanner: string;
  cvssScore: number;
}
