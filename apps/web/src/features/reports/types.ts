export type ReportTemplateType =
  | "EXECUTIVE_SUMMARY"
  | "TECHNICAL_FINDINGS"
  | "COMPLIANCE_AUDIT";

export type ReportFormat = "PDF" | "HTML";
export type ReportStatus = "READY" | "GENERATING" | "FAILED";

export interface ReportItem {
  id: string;
  assessmentId: string;
  targetHost: string;
  templateType: ReportTemplateType;
  format: ReportFormat;
  title: string;
  status: ReportStatus;
  createdAt: string;
  sha256Digest: string;
  sizeBytes: number;
  downloadUrl: string;
  redacted: boolean;
}

export interface GenerateReportPayload {
  assessmentId: string;
  targetHost: string;
  templateType: ReportTemplateType;
  format: ReportFormat;
  redactSensitiveData: boolean;
  title?: string;
}
