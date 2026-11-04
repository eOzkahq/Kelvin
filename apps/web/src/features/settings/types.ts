export interface GeneralSettings {
  workspaceName: string;
  slug: string;
  timezone: string;
  contactEmail: string;
}

export interface AssessmentDefaults {
  maxRequestsPerSecond: number;
  timeoutMinutes: number;
  maxConcurrency: number;
  maxRetries: number;
}

export interface RetentionSettings {
  retentionDays: 30 | 90 | 180 | 365;
  autoRedactionEnabled: boolean;
  hardDeleteAfterExpiry: boolean;
}

export interface ScannerEngineConfig {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
}

export interface QuotaUsage {
  monthlyAssessmentsUsed: number;
  monthlyAssessmentsLimit: number;
  concurrencySlotsUsed: number;
  concurrencySlotsLimit: number;
  storageUsedBytes: number;
  storageLimitBytes: number;
}

export interface PlatformWorkspaceSettings {
  general: GeneralSettings;
  assessmentDefaults: AssessmentDefaults;
  retention: RetentionSettings;
  scanners: ScannerEngineConfig[];
  quotas: QuotaUsage;
}
