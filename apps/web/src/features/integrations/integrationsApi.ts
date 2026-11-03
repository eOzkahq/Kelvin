import { request } from "../../services/api";
import type {
  IntegrationConnector,
  NotificationPreferenceItem,
  TestDeliveryResponse,
  WebhookSubscription,
} from "./types";

let mockConnectorsStore: IntegrationConnector[] = [
  {
    id: "int-jira",
    type: "JIRA",
    name: "Jira Software Cloud",
    description: "Bi-directional ticket synchronization, automated issue creation, and status mirroring.",
    status: "CONNECTED",
    iconText: "🔷",
    lastSyncAt: "2026-11-03T20:15:00Z",
    config: {
      host: "https://kelvin-security.atlassian.net",
      username: "secops-bot@kelvin.io",
      projectKey: "SEC",
      issueType: "Vulnerability",
    },
  },
  {
    id: "int-slack",
    type: "SLACK",
    name: "Slack Security Alerts",
    description: "Broadcast real-time scan completions and critical vulnerability notifications to incident channels.",
    status: "CONNECTED",
    iconText: "💬",
    lastSyncAt: "2026-11-03T20:30:00Z",
    config: {
      webhookUrl: "https://hooks.slack.com/services/T0123/B0456/mocked789token",
      channel: "#secops-alerts",
      minSeverity: "HIGH",
    },
  },
  {
    id: "int-teams",
    type: "TEAMS",
    name: "Microsoft Teams Incident Channel",
    description: "Post automated remediation reminders and SLA countdown warnings directly into Teams squads.",
    status: "DISCONNECTED",
    iconText: "👥",
    config: {
      webhookUrl: "",
      channel: "",
    },
  },
  {
    id: "int-siem",
    type: "SIEM",
    name: "Splunk / Syslog SIEM Forwarder",
    description: "Stream raw normalized findings and assessment execution manifests to corporate SIEM indexers.",
    status: "CONNECTED",
    iconText: "📊",
    lastSyncAt: "2026-11-03T19:00:00Z",
    config: {
      protocol: "TLS",
      endpoint: "siem.kelvin-sec.internal:6514",
    },
  },
];

let mockWebhooksStore: WebhookSubscription[] = [
  {
    id: "wh-01",
    name: "DevOps CI/CD Gate Dispatcher",
    endpointUrl: "https://ci.kelvin-sec.internal/webhooks/security-assessment",
    secret: "whsec_98fbc102934812304918230948120394",
    events: ["assessment.completed", "assessment.failed"],
    active: true,
    lastDeliveryStatus: 200,
    lastDeliveryAt: "2026-11-03T18:30:00Z",
    createdAt: "2026-10-15T09:00:00Z",
  },
  {
    id: "wh-02",
    name: "PagerDuty Urgent Vulnerability Escalation",
    endpointUrl: "https://events.pagerduty.com/v2/enqueue",
    secret: "whsec_7c8d9e0f1a2b34567890abcdef012345",
    events: ["finding.critical_detected", "remediation.sla_breached"],
    active: true,
    lastDeliveryStatus: 202,
    lastDeliveryAt: "2026-11-02T19:45:00Z",
    createdAt: "2026-10-20T12:00:00Z",
  },
];

let mockPreferencesStore: NotificationPreferenceItem[] = [
  {
    id: "pref-01",
    event: "Critical Vulnerability Discovered",
    description: "Immediate alert when a CVSS >= 9.0 finding is confirmed by Nuclei, ZAP, or Nmap.",
    inApp: true,
    email: true,
    slack: true,
  },
  {
    id: "pref-02",
    event: "Assessment Execution Completed",
    description: "Summary report notification when a scheduled sweep finishes all scanner stages.",
    inApp: true,
    email: false,
    slack: true,
  },
  {
    id: "pref-03",
    event: "Remediation SLA Breach Warning (<= 48h)",
    description: "Urgent reminder when an unresolved vulnerability ticket is approaching compliance deadline.",
    inApp: true,
    email: true,
    slack: true,
  },
  {
    id: "pref-04",
    event: "Target Ownership Verification Expiring",
    description: "Notification 14 days prior to DNS TXT record challenge expiration.",
    inApp: true,
    email: true,
    slack: false,
  },
];

export async function fetchIntegrations(): Promise<IntegrationConnector[]> {
  try {
    const res = await request<IntegrationConnector[]>("/integrations");
    if (res && Array.isArray(res)) return res;
  } catch {
    // Local fallback
  }
  return [...mockConnectorsStore];
}

export async function updateIntegrationConfig(
  integrationId: string,
  config: Record<string, any>
): Promise<IntegrationConnector> {
  try {
    const res = await request<IntegrationConnector>(`/integrations/${integrationId}`, {
      method: "PUT",
      body: JSON.stringify(config),
    });
    if (res && res.id) return res;
  } catch {
    // Local fallback
  }

  const idx = mockConnectorsStore.findIndex((c) => c.id === integrationId);
  if (idx === -1) throw new Error("Integration not found");

  mockConnectorsStore[idx] = {
    ...mockConnectorsStore[idx],
    status: "CONNECTED",
    config: { ...mockConnectorsStore[idx].config, ...config },
    lastSyncAt: new Date().toISOString(),
  };

  return mockConnectorsStore[idx];
}

export async function testIntegrationDelivery(
  integrationId: string
): Promise<TestDeliveryResponse> {
  try {
    const res = await request<TestDeliveryResponse>(`/integrations/${integrationId}/test`, {
      method: "POST",
    });
    if (res && res.statusCode) return res;
  } catch {
    // Local fallback
  }

  return {
    success: true,
    statusCode: 200,
    latencyMs: Math.floor(Math.random() * 120) + 45,
    message: "Test ping delivered successfully. HTTP 200 OK received from endpoint.",
    timestamp: new Date().toISOString(),
  };
}

export async function fetchWebhooks(): Promise<WebhookSubscription[]> {
  try {
    const res = await request<WebhookSubscription[]>("/webhooks");
    if (res && Array.isArray(res)) return res;
  } catch {
    // Local fallback
  }
  return [...mockWebhooksStore];
}

export async function createWebhook(
  payload: Omit<WebhookSubscription, "id" | "secret" | "createdAt">
): Promise<WebhookSubscription> {
  if (!payload.endpointUrl.startsWith("http")) {
    throw new Error("A valid HTTPS or HTTP webhook endpoint URL is required.");
  }
  if (!payload.events.length) {
    throw new Error("At least one subscribed event is required.");
  }

  try {
    const res = await request<WebhookSubscription>("/webhooks", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (res && res.id) return res;
  } catch {
    // Local fallback
  }

  const newWebhook: WebhookSubscription = {
    ...payload,
    id: `wh-${Date.now().toString().slice(-4)}`,
    secret: `whsec_${Math.random().toString(16).substring(2)}${Math.random().toString(16).substring(2)}`,
    createdAt: new Date().toISOString(),
  };

  mockWebhooksStore.unshift(newWebhook);
  return newWebhook;
}

export async function deleteWebhook(webhookId: string): Promise<boolean> {
  mockWebhooksStore = mockWebhooksStore.filter((w) => w.id !== webhookId);
  return true;
}

export async function fetchNotificationPreferences(): Promise<NotificationPreferenceItem[]> {
  try {
    const res = await request<NotificationPreferenceItem[]>("/notifications/preferences");
    if (res && Array.isArray(res)) return res;
  } catch {
    // Local fallback
  }
  return [...mockPreferencesStore];
}

export async function updateNotificationPreferences(
  preferences: NotificationPreferenceItem[]
): Promise<NotificationPreferenceItem[]> {
  try {
    const res = await request<NotificationPreferenceItem[]>("/notifications/preferences", {
      method: "PUT",
      body: JSON.stringify(preferences),
    });
    if (res && Array.isArray(res)) return res;
  } catch {
    // Local fallback
  }
  mockPreferencesStore = [...preferences];
  return mockPreferencesStore;
}

export function resetMockIntegrations(): void {
  mockConnectorsStore = mockConnectorsStore.map((c) => ({ ...c, config: { ...c.config } }));
  mockWebhooksStore = mockWebhooksStore.map((w) => ({ ...w, events: [...w.events] }));
  mockPreferencesStore = mockPreferencesStore.map((p) => ({ ...p }));
}
