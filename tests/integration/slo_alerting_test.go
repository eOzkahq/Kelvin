package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSLOAndAlertingConfigurations validates the Prometheus alerting rules syntax,
// Grafana dashboard JSON schema, and SLO documentation.
func TestSLOAndAlertingConfigurations(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))

	// 1. Verify Prometheus Alert Rules
	alertsPath := filepath.Join(repoRoot, "deploy", "monitoring", "alerts", "kelvin-slo-alerts.yml")
	alertData, err := os.ReadFile(alertsPath)
	if err != nil {
		t.Fatalf("Missing deploy/monitoring/alerts/kelvin-slo-alerts.yml: %v", err)
	}
	alerts := string(alertData)

	expectedAlerts := []string{
		"alert: APIHighErrorRate",
		"alert: APIHighLatency",
		"alert: QueueSaturation",
		"alert: DatabasePoolStarvation",
		"alert: WorkerFleetUnhealthy",
		"alert: ScannerInternalFailureSpike",
	}
	for _, a := range expectedAlerts {
		if !strings.Contains(alerts, a) {
			t.Errorf("kelvin-slo-alerts.yml missing alert rule: %s", a)
		}
	}

	// 2. Verify Grafana Dashboard JSON
	dashPath := filepath.Join(repoRoot, "deploy", "monitoring", "dashboards", "kelvin-overview.json")
	dashData, err := os.ReadFile(dashPath)
	if err != nil {
		t.Fatalf("Missing deploy/monitoring/dashboards/kelvin-overview.json: %v", err)
	}

	var dash map[string]interface{}
	if err := json.Unmarshal(dashData, &dash); err != nil {
		t.Fatalf("Failed to parse Grafana dashboard JSON: %v", err)
	}

	if dash["title"] != "KELVIN Production SLO & Reliability Dashboard" {
		t.Errorf("Unexpected dashboard title: %v", dash["title"])
	}

	// 3. Verify Operational Documentation
	docPath := filepath.Join(repoRoot, "docs", "observability", "SLOS_DASHBOARDS_AND_ALERTING_POLICIES.md")
	if _, err := os.Stat(docPath); os.IsNotExist(err) {
		t.Errorf("Missing SLOS_DASHBOARDS_AND_ALERTING_POLICIES.md documentation")
	}
}
