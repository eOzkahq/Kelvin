export type TargetType = "DOMAIN" | "IP" | "CIDR" | "URL";
export type TargetEnvironment = "PRODUCTION" | "STAGING" | "DEVELOPMENT";
export type TargetCriticality = "TIER_1" | "TIER_2" | "TIER_3" | "TIER_4";
export type TargetVerificationStatus = "VERIFIED" | "PENDING_VERIFICATION" | "VERIFICATION_FAILED";

export interface TargetScopeConfig {
  allowedPorts: string;
  excludedPaths: string[];
  maxRequestsPerSecond: number;
}

export interface VerificationChallenge {
  type: "DNS_TXT" | "HTTP_META";
  token: string;
  recordName: string;
  verifiedAt?: string;
}

export interface TargetAsset {
  id: string;
  name: string;
  host: string;
  type: TargetType;
  environment: TargetEnvironment;
  criticality: TargetCriticality;
  verificationStatus: TargetVerificationStatus;
  verificationChallenge: VerificationChallenge;
  scopeConfig: TargetScopeConfig;
  openFindingsCount: number;
  lastAssessedAt?: string;
  createdAt: string;
}

export interface RegisterTargetPayload {
  name: string;
  host: string;
  type: TargetType;
  environment: TargetEnvironment;
  criticality: TargetCriticality;
  allowedPorts?: string;
  excludedPaths?: string[];
  maxRequestsPerSecond?: number;
}

export interface TargetFilterParams {
  search?: string;
  environment?: TargetEnvironment | "";
  verificationStatus?: TargetVerificationStatus | "";
  criticality?: TargetCriticality | "";
}
