export type IntegrationType = "JIRA" | "SLACK" | "TEAMS" | "WEBHOOK" | "SIEM";
export type IntegrationStatus = "CONNECTED" | "DISCONNECTED" | "ERROR" | "CONFIGURING";

export interface IntegrationConnector {
  id: string;
  type: IntegrationType;
  name: string;
  description: string;
  status: IntegrationStatus;
  iconText: string;
  lastSyncAt?: string;
  errorDetail?: string;
  config: Record<string, any>;
}

export interface WebhookSubscription {
  id: string;
  name: string;
  endpointUrl: string;
  secret: string; // HMAC signing key
  events: string[];
  active: boolean;
  lastDeliveryStatus?: number;
  lastDeliveryAt?: string;
  createdAt: string;
}

export interface NotificationPreferenceItem {
  id: string;
  event: string;
  description: string;
  inApp: boolean;
  email: boolean;
  slack: boolean;
}

export interface TestDeliveryResponse {
  success: boolean;
  statusCode: number;
  latencyMs: number;
  message: string;
  timestamp: string;
}
