import React, { useEffect, useState, useCallback } from "react";
import {
  fetchIntegrations,
  updateIntegrationConfig,
  testIntegrationDelivery,
  fetchWebhooks,
  createWebhook,
  deleteWebhook,
  fetchNotificationPreferences,
  updateNotificationPreferences,
  type IntegrationConnector,
  type WebhookSubscription,
  type NotificationPreferenceItem,
  type TestDeliveryResponse,
} from "../features/integrations";
import {
  Button,
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  EmptyState,
  Input,
  Modal,
  SkeletonLoader,
} from "../components/ui";

type ActiveTab = "connectors" | "webhooks" | "notifications";

const ALL_WEBHOOK_EVENTS = [
  { id: "assessment.completed", label: "Assessment Sweep Completed" },
  { id: "assessment.failed", label: "Scanner Execution Failure / Timeout" },
  { id: "finding.critical_detected", label: "Critical Vulnerability Discovered (CVSS >= 9.0)" },
  { id: "remediation.sla_breached", label: "Remediation Ticket SLA Breach" },
];

export default function IntegrationsNotificationPage() {
  const [connectors, setConnectors] = useState<IntegrationConnector[]>([]);
  const [webhooks, setWebhooks] = useState<WebhookSubscription[]>([]);
  const [preferences, setPreferences] = useState<NotificationPreferenceItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<ActiveTab>("connectors");
  const [notification, setNotification] = useState<string | null>(null);

  // Connector Config Modal
  const [selectedConnector, setSelectedConnector] = useState<IntegrationConnector | null>(null);
  const [connectorConfig, setConnectorConfig] = useState<Record<string, any>>({});
  const [isSavingConnector, setIsSavingConnector] = useState(false);

  // Test Delivery Feedback
  const [testResult, setTestResult] = useState<{ id: string; res: TestDeliveryResponse } | null>(null);
  const [testingId, setTestingId] = useState<string | null>(null);

  // Webhook Modal State
  const [isWebhookModalOpen, setIsWebhookModalOpen] = useState(false);
  const [whName, setWhName] = useState("");
  const [whUrl, setWhUrl] = useState("");
  const [whEvents, setWhEvents] = useState<string[]>(["assessment.completed", "finding.critical_detected"]);
  const [isCreatingWebhook, setIsCreatingWebhook] = useState(false);

  // Preferences Saving State
  const [isSavingPrefs, setIsSavingPrefs] = useState(false);

  const loadData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [c, w, p] = await Promise.all([
        fetchIntegrations(),
        fetchWebhooks(),
        fetchNotificationPreferences(),
      ]);
      setConnectors(c);
      setWebhooks(w);
      setPreferences(p);
    } catch (err) {
      console.error("Failed to load integrations data:", err);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleTestConnection = async (connector: IntegrationConnector) => {
    setTestingId(connector.id);
    setTestResult(null);
    try {
      const res = await testIntegrationDelivery(connector.id);
      setTestResult({ id: connector.id, res });
    } catch (err) {
      alert(`Test ping failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setTestingId(null);
    }
  };

  const handleSaveConnector = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedConnector) return;

    setIsSavingConnector(true);
    try {
      const updated = await updateIntegrationConfig(selectedConnector.id, connectorConfig);
      setConnectors((prev) => prev.map((c) => (c.id === updated.id ? updated : c)));
      setSelectedConnector(null);
      setNotification(`${updated.name} configuration updated.`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Save failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsSavingConnector(false);
    }
  };

  const handleCreateWebhookSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!whName.trim() || !whUrl.trim()) return;

    setIsCreatingWebhook(true);
    try {
      const created = await createWebhook({
        name: whName,
        endpointUrl: whUrl,
        events: whEvents,
        active: true,
      });
      setWebhooks((prev) => [created, ...prev]);
      setIsWebhookModalOpen(false);
      setWhName("");
      setWhUrl("");
      setNotification(`Webhook "${created.name}" subscribed.`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Webhook creation failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsCreatingWebhook(false);
    }
  };

  const handleDeleteWebhook = async (id: string, name: string) => {
    if (!confirm(`Delete webhook subscription "${name}"?`)) return;
    try {
      await deleteWebhook(id);
      setWebhooks((prev) => prev.filter((w) => w.id !== id));
      setNotification(`Webhook "${name}" deleted.`);
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Delete failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleTogglePref = (index: number, channel: "inApp" | "email" | "slack") => {
    setPreferences((prev) =>
      prev.map((item, i) => (i === index ? { ...item, [channel]: !item[channel] } : item))
    );
  };

  const handleSavePreferences = async () => {
    setIsSavingPrefs(true);
    try {
      const updated = await updateNotificationPreferences(preferences);
      setPreferences(updated);
      setNotification("Notification delivery preferences saved.");
      setTimeout(() => setNotification(null), 3000);
    } catch (err) {
      alert(`Save failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsSavingPrefs(false);
    }
  };

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="h-6 w-32 bg-zinc-800 animate-pulse rounded" />
        <Card className="p-6">
          <SkeletonLoader lines={6} />
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
            Integrations &amp; Notification Center
          </h1>
          <p className="mt-1 text-sm text-zinc-400">
            Enterprise ticketing connectors, incident channels, outbound webhooks, and alert routing preferences.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {notification && (
            <span className="rounded bg-emerald-950/60 border border-emerald-800 px-3 py-1 text-xs text-emerald-400 animate-in fade-in">
              {notification}
            </span>
          )}
          {activeTab === "webhooks" && (
            <Button variant="primary" onClick={() => setIsWebhookModalOpen(true)}>
              + New Webhook Subscription
            </Button>
          )}
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="flex border-b border-zinc-800 gap-2">
        <button
          onClick={() => setActiveTab("connectors")}
          className={`px-4 py-2 text-xs font-semibold border-b-2 transition-colors ${
            activeTab === "connectors"
              ? "border-cyan-500 text-cyan-400"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          Enterprise Connectors ({connectors.length})
        </button>
        <button
          onClick={() => setActiveTab("webhooks")}
          className={`px-4 py-2 text-xs font-semibold border-b-2 transition-colors ${
            activeTab === "webhooks"
              ? "border-cyan-500 text-cyan-400"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          Outbound Webhooks ({webhooks.length})
        </button>
        <button
          onClick={() => setActiveTab("notifications")}
          className={`px-4 py-2 text-xs font-semibold border-b-2 transition-colors ${
            activeTab === "notifications"
              ? "border-cyan-500 text-cyan-400"
              : "border-transparent text-zinc-400 hover:text-zinc-200"
          }`}
        >
          Notification Routing Matrix
        </button>
      </div>

      {/* Tab 1: Connectors Grid */}
      {activeTab === "connectors" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {connectors.map((connector) => {
            const hasTest = testResult && testResult.id === connector.id;
            return (
              <Card key={connector.id} className="p-6 space-y-4">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-3xl">{connector.iconText}</span>
                    <div>
                      <h3 className="text-base font-bold text-zinc-100">{connector.name}</h3>
                      <span
                        className={`inline-block rounded px-2 py-0.5 text-[10px] font-mono mt-1 ${
                          connector.status === "CONNECTED"
                            ? "bg-emerald-950/60 border border-emerald-800 text-emerald-400"
                            : "bg-zinc-800 border border-zinc-700 text-zinc-400"
                        }`}
                      >
                        {connector.status}
                      </span>
                    </div>
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      setSelectedConnector(connector);
                      setConnectorConfig({ ...connector.config });
                    }}
                  >
                    Configure
                  </Button>
                </div>

                <p className="text-xs text-zinc-400 line-clamp-2">{connector.description}</p>

                {connector.lastSyncAt && (
                  <div className="text-[11px] text-zinc-500 font-mono">
                    Last Verified: {new Date(connector.lastSyncAt).toLocaleString()}
                  </div>
                )}

                {hasTest && (
                  <div className="rounded border border-emerald-800 bg-emerald-950/40 p-2.5 text-xs text-emerald-300 font-mono space-y-1">
                    <div>✓ {testResult.res.message}</div>
                    <div className="text-[10px] text-emerald-400">
                      HTTP {testResult.res.statusCode} OK • Roundtrip: {testResult.res.latencyMs}ms
                    </div>
                  </div>
                )}

                <div className="pt-2 border-t border-zinc-800/80 flex justify-end">
                  <Button
                    size="sm"
                    variant="secondary"
                    onClick={() => handleTestConnection(connector)}
                    isLoading={testingId === connector.id}
                  >
                    Test Connection
                  </Button>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      {/* Tab 2: Outbound Webhooks */}
      {activeTab === "webhooks" && (
        <div className="space-y-6">
          <div className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-900/60">
            <table className="w-full text-left text-sm text-zinc-300">
              <thead className="border-b border-zinc-800 bg-zinc-900 text-xs uppercase text-zinc-400">
                <tr>
                  <th className="px-4 py-3">Subscription Name</th>
                  <th className="px-4 py-3">Destination URL</th>
                  <th className="px-4 py-3">Subscribed Events</th>
                  <th className="px-4 py-3">Signing Secret</th>
                  <th className="px-4 py-3">Last Delivery</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60">
                {webhooks.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="p-8">
                      <EmptyState
                        title="No Webhook Subscriptions"
                        description="Subscribe external endpoints to KELVIN security assessment lifecycle events."
                        actionLabel="New Webhook"
                        onAction={() => setIsWebhookModalOpen(true)}
                      />
                    </td>
                  </tr>
                ) : (
                  webhooks.map((wh) => (
                    <tr key={wh.id} className="hover:bg-zinc-800/30">
                      <td className="px-4 py-3 font-semibold text-zinc-100">{wh.name}</td>
                      <td className="px-4 py-3 font-mono text-xs text-cyan-400 max-w-xs truncate">
                        {wh.endpointUrl}
                      </td>
                      <td className="px-4 py-3 text-xs">
                        <div className="flex flex-wrap gap-1">
                          {wh.events.map((ev) => (
                            <span
                              key={ev}
                              className="rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] font-mono text-zinc-300"
                            >
                              {ev}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs text-zinc-500">
                        <code>{wh.secret.slice(0, 12)}...</code>
                      </td>
                      <td className="px-4 py-3 text-xs">
                        {wh.lastDeliveryStatus ? (
                          <span className="rounded bg-emerald-950/60 border border-emerald-800 px-1.5 py-0.5 text-[10px] text-emerald-400 font-mono">
                            HTTP {wh.lastDeliveryStatus}
                          </span>
                        ) : (
                          <span className="text-zinc-500">Pending</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => handleDeleteWebhook(wh.id, wh.name)}
                          className="text-zinc-500 hover:text-red-400"
                        >
                          Delete
                        </Button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 3: Notification Delivery Matrix */}
      {activeTab === "notifications" && (
        <Card className="p-6 space-y-4">
          <CardHeader>
            <CardTitle>Security Notification Delivery Channels</CardTitle>
            <CardDescription>
              Control multi-channel delivery rules for in-app toasts, email digests, and chat alerts.
            </CardDescription>
          </CardHeader>

          <div className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-950">
            <table className="w-full text-left text-sm text-zinc-300">
              <thead className="border-b border-zinc-800 bg-zinc-900 text-xs uppercase text-zinc-400">
                <tr>
                  <th className="px-4 py-3">Security Event</th>
                  <th className="px-4 py-3 text-center">In-App Notification</th>
                  <th className="px-4 py-3 text-center">Corporate Email</th>
                  <th className="px-4 py-3 text-center">Slack / Teams Alert</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60">
                {preferences.map((pref, i) => (
                  <tr key={pref.id} className="hover:bg-zinc-900/40">
                    <td className="px-4 py-3">
                      <div className="font-semibold text-zinc-200 text-xs">{pref.event}</div>
                      <div className="text-[11px] text-zinc-400">{pref.description}</div>
                    </td>
                    <td className="px-4 py-3 text-center">
                      <input
                        type="checkbox"
                        checked={pref.inApp}
                        onChange={() => handleTogglePref(i, "inApp")}
                        className="h-4 w-4 rounded border-zinc-700 bg-zinc-800 text-cyan-500"
                      />
                    </td>
                    <td className="px-4 py-3 text-center">
                      <input
                        type="checkbox"
                        checked={pref.email}
                        onChange={() => handleTogglePref(i, "email")}
                        className="h-4 w-4 rounded border-zinc-700 bg-zinc-800 text-cyan-500"
                      />
                    </td>
                    <td className="px-4 py-3 text-center">
                      <input
                        type="checkbox"
                        checked={pref.slack}
                        onChange={() => handleTogglePref(i, "slack")}
                        className="h-4 w-4 rounded border-zinc-700 bg-zinc-800 text-cyan-500"
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="flex justify-end pt-2">
            <Button variant="primary" onClick={handleSavePreferences} isLoading={isSavingPrefs}>
              Save Notification Preferences
            </Button>
          </div>
        </Card>
      )}

      {/* Configure Connector Modal */}
      {selectedConnector && (
        <Modal
          isOpen={Boolean(selectedConnector)}
          onClose={() => setSelectedConnector(null)}
          title={`Configure: ${selectedConnector.name}`}
        >
          <form onSubmit={handleSaveConnector} className="space-y-4">
            {selectedConnector.type === "JIRA" && (
              <>
                <div>
                  <label className="block text-xs font-medium text-zinc-300 mb-1">
                    Jira Cloud Host URL
                  </label>
                  <Input
                    type="url"
                    value={connectorConfig.host || ""}
                    onChange={(e) =>
                      setConnectorConfig({ ...connectorConfig, host: e.target.value })
                    }
                    placeholder="https://company.atlassian.net"
                    required
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-zinc-300 mb-1">
                    API Username / Service Email
                  </label>
                  <Input
                    type="email"
                    value={connectorConfig.username || ""}
                    onChange={(e) =>
                      setConnectorConfig({ ...connectorConfig, username: e.target.value })
                    }
                    placeholder="bot@company.com"
                    required
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-zinc-300 mb-1">
                      Project Key
                    </label>
                    <Input
                      type="text"
                      value={connectorConfig.projectKey || ""}
                      onChange={(e) =>
                        setConnectorConfig({ ...connectorConfig, projectKey: e.target.value })
                      }
                      placeholder="SEC"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-zinc-300 mb-1">
                      Issue Type
                    </label>
                    <Input
                      type="text"
                      value={connectorConfig.issueType || ""}
                      onChange={(e) =>
                        setConnectorConfig({ ...connectorConfig, issueType: e.target.value })
                      }
                      placeholder="Vulnerability"
                      required
                    />
                  </div>
                </div>
              </>
            )}

            {(selectedConnector.type === "SLACK" || selectedConnector.type === "TEAMS") && (
              <>
                <div>
                  <label className="block text-xs font-medium text-zinc-300 mb-1">
                    Incoming Webhook URL
                  </label>
                  <Input
                    type="url"
                    value={connectorConfig.webhookUrl || ""}
                    onChange={(e) =>
                      setConnectorConfig({ ...connectorConfig, webhookUrl: e.target.value })
                    }
                    placeholder="https://hooks.slack.com/services/..."
                    required
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-zinc-300 mb-1">
                    Channel Identifier
                  </label>
                  <Input
                    type="text"
                    value={connectorConfig.channel || ""}
                    onChange={(e) =>
                      setConnectorConfig({ ...connectorConfig, channel: e.target.value })
                    }
                    placeholder="#secops-alerts"
                  />
                </div>
              </>
            )}

            {selectedConnector.type === "SIEM" && (
              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1">
                  Syslog / Splunk TLS Endpoint
                </label>
                <Input
                  type="text"
                  value={connectorConfig.endpoint || ""}
                  onChange={(e) =>
                    setConnectorConfig({ ...connectorConfig, endpoint: e.target.value })
                  }
                  placeholder="siem.company.internal:6514"
                  required
                />
              </div>
            )}

            <div className="flex justify-end gap-2 pt-2">
              <Button variant="secondary" onClick={() => setSelectedConnector(null)} type="button">
                Cancel
              </Button>
              <Button variant="primary" type="submit" isLoading={isSavingConnector}>
                Save Configuration
              </Button>
            </div>
          </form>
        </Modal>
      )}

      {/* New Webhook Modal */}
      <Modal
        isOpen={isWebhookModalOpen}
        onClose={() => setIsWebhookModalOpen(false)}
        title="Subscribe New Outbound Webhook"
      >
        <form onSubmit={handleCreateWebhookSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Subscription Name <span className="text-red-400">*</span>
            </label>
            <Input
              type="text"
              placeholder="e.g. CI/CD Security Gate Trigger"
              value={whName}
              onChange={(e) => setWhName(e.target.value)}
              required
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-zinc-300 mb-1">
              Webhook Endpoint URL <span className="text-red-400">*</span>
            </label>
            <Input
              type="url"
              placeholder="https://ci.company.com/webhooks/kelvin"
              value={whUrl}
              onChange={(e) => setWhUrl(e.target.value)}
              required
            />
          </div>

          <div className="space-y-2">
            <span className="text-xs font-semibold uppercase text-zinc-400">
              Subscribed Event Types
            </span>
            <div className="space-y-1.5 border border-zinc-800 rounded-lg p-3 bg-zinc-950">
              {ALL_WEBHOOK_EVENTS.map((ev) => (
                <label key={ev.id} className="flex items-center gap-2 cursor-pointer text-xs">
                  <input
                    type="checkbox"
                    checked={whEvents.includes(ev.id)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setWhEvents([...whEvents, ev.id]);
                      } else {
                        setWhEvents(whEvents.filter((x) => x !== ev.id));
                      }
                    }}
                    className="rounded border-zinc-700 bg-zinc-800 text-cyan-500"
                  />
                  <span className="text-zinc-200">{ev.label}</span>
                  <code className="text-[10px] text-zinc-500 font-mono">({ev.id})</code>
                </label>
              ))}
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="secondary" onClick={() => setIsWebhookModalOpen(false)} type="button">
              Cancel
            </Button>
            <Button variant="primary" type="submit" isLoading={isCreatingWebhook}>
              Create Webhook
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  );
}
