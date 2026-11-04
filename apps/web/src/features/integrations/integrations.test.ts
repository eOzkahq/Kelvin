import { describe, it, expect, beforeEach } from "vitest";
import {
  fetchIntegrations,
  updateIntegrationConfig,
  testIntegrationDelivery,
  fetchWebhooks,
  createWebhook,
  deleteWebhook,
  fetchNotificationPreferences,
  updateNotificationPreferences,
  resetMockIntegrations,
} from "./integrationsApi";

describe("Integrations Hub & Notification Center (FE-15)", () => {
  beforeEach(() => {
    resetMockIntegrations();
  });

  it("retrieves enterprise connectors with connection states", async () => {
    const connectors = await fetchIntegrations();
    expect(connectors).toBeDefined();
    expect(connectors.length).toBeGreaterThanOrEqual(4);

    const jira = connectors.find((c) => c.type === "JIRA");
    expect(jira?.status).toBe("CONNECTED");
    expect(jira?.config.host).toBeDefined();
  });

  it("updates connector configuration parameters", async () => {
    const updated = await updateIntegrationConfig("int-slack", {
      channel: "#urgent-secops",
      minSeverity: "CRITICAL",
    });

    expect(updated.config.channel).toBe("#urgent-secops");
    expect(updated.config.minSeverity).toBe("CRITICAL");
  });

  it("executes delivery test ping and returns latency diagnostics", async () => {
    const res = await testIntegrationDelivery("int-jira");
    expect(res.success).toBe(true);
    expect(res.statusCode).toBe(200);
    expect(res.latencyMs).toBeGreaterThan(0);
    expect(res.message).toContain("delivered successfully");
  });

  it("registers outbound webhook subscription with generated HMAC secret", async () => {
    const webhook = await createWebhook({
      name: "Security SOAR Automated Playbook",
      endpointUrl: "https://soar.kelvin-sec.internal/v1/playbooks",
      events: ["finding.critical_detected", "assessment.completed"],
      active: true,
    });

    expect(webhook.id).toBeDefined();
    expect(webhook.secret).toContain("whsec_");
    expect(webhook.events).toContain("finding.critical_detected");

    const webhooks = await fetchWebhooks();
    expect(webhooks.some((w) => w.id === webhook.id)).toBe(true);
  });

  it("rejects webhook subscription with invalid URL or missing events", async () => {
    await expect(
      createWebhook({
        name: "Invalid URL",
        endpointUrl: "not-a-url",
        events: ["assessment.completed"],
        active: true,
      })
    ).rejects.toThrow("valid HTTPS or HTTP");

    await expect(
      createWebhook({
        name: "No Events",
        endpointUrl: "https://api.kelvin.io/hook",
        events: [],
        active: true,
      })
    ).rejects.toThrow("At least one subscribed event");
  });

  it("deletes webhook subscription", async () => {
    const initial = await fetchWebhooks();
    const idToDelete = initial[0].id;

    await deleteWebhook(idToDelete);
    const after = await fetchWebhooks();
    expect(after.some((w) => w.id === idToDelete)).toBe(false);
  });

  it("manages multi-channel notification delivery matrix", async () => {
    const prefs = await fetchNotificationPreferences();
    expect(prefs.length).toBeGreaterThan(0);

    prefs[0].email = false;
    prefs[0].slack = true;

    const saved = await updateNotificationPreferences(prefs);
    expect(saved[0].email).toBe(false);
    expect(saved[0].slack).toBe(true);
  });
});
