import { describe, it, expect, beforeEach } from "vitest";
import {
  fetchFindings,
  batchUpdateFindings,
  exportFindings,
  resetMockFindings,
} from "./findingsApi";

describe("Findings Management & Search API Engine (FE-08)", () => {
  beforeEach(() => {
    resetMockFindings();
  });

  it("retrieves default findings list with pagination meta", async () => {
    const result = await fetchFindings({ page: 1, limit: 10 });
    expect(result.items).toBeDefined();
    expect(result.items.length).toBeGreaterThan(0);
    expect(result.total).toBeGreaterThanOrEqual(result.items.length);
    expect(result.page).toBe(1);
    expect(result.limit).toBe(10);
  });

  it("filters findings by search query matching title or CVE", async () => {
    // Match by title keyword
    const log4jResult = await fetchFindings({ search: "log4j" });
    expect(log4jResult.items.length).toBeGreaterThan(0);
    expect(log4jResult.items.some((f) => f.title.toLowerCase().includes("log4j"))).toBe(true);

    // Match by CVE ID
    const cveResult = await fetchFindings({ search: "CVE-2021-44228" });
    expect(cveResult.items.length).toBeGreaterThan(0);
    expect(cveResult.items[0].cveIds).toContain("CVE-2021-44228");
  });

  it("filters findings by severity accurately", async () => {
    const criticals = await fetchFindings({ severity: "CRITICAL" });
    expect(criticals.items.length).toBeGreaterThan(0);
    criticals.items.forEach((f) => {
      expect(f.severity).toBe("CRITICAL");
    });

    const lows = await fetchFindings({ severity: "LOW" });
    expect(lows.items.length).toBeGreaterThan(0);
    lows.items.forEach((f) => {
      expect(f.severity).toBe("LOW");
    });
  });

  it("filters findings by status accurately", async () => {
    const openFindings = await fetchFindings({ status: "OPEN" });
    expect(openFindings.items.length).toBeGreaterThan(0);
    openFindings.items.forEach((f) => {
      expect(f.status).toBe("OPEN");
    });
  });

  it("filters findings by scanner engine", async () => {
    const nucleiFindings = await fetchFindings({ scanner: "Nuclei" });
    expect(nucleiFindings.items.length).toBeGreaterThan(0);
    nucleiFindings.items.forEach((f) => {
      expect(f.scanner).toBe("Nuclei");
    });
  });

  it("sorts findings by risk score descending by default and ascending when requested", async () => {
    const descResult = await fetchFindings({ sortBy: "riskScore", sortOrder: "desc" });
    for (let i = 0; i < descResult.items.length - 1; i++) {
      expect(descResult.items[i].riskScore).toBeGreaterThanOrEqual(descResult.items[i + 1].riskScore);
    }

    const ascResult = await fetchFindings({ sortBy: "riskScore", sortOrder: "asc" });
    for (let i = 0; i < ascResult.items.length - 1; i++) {
      expect(ascResult.items[i].riskScore).toBeLessThanOrEqual(ascResult.items[i + 1].riskScore);
    }
  });

  it("sorts findings by title alphabetically", async () => {
    const result = await fetchFindings({ sortBy: "title", sortOrder: "asc" });
    for (let i = 0; i < result.items.length - 1; i++) {
      expect(result.items[i].title.localeCompare(result.items[i + 1].title)).toBeLessThanOrEqual(0);
    }
  });

  it("performs batch update transitions on selected findings", async () => {
    const targetIds = ["fnd-001", "fnd-002"];
    const updateResult = await batchUpdateFindings({
      findingIds: targetIds,
      status: "RESOLVED",
      assignee: "security-lead@kelvin.io",
      justification: "Mitigated via emergency hotfix deployment",
    });

    expect(updateResult.success).toBe(true);
    expect(updateResult.updatedCount).toBe(2);

    // Verify state reflected in subsequent fetch
    const refreshed = await fetchFindings();
    const updated1 = refreshed.items.find((f) => f.id === "fnd-001");
    const updated2 = refreshed.items.find((f) => f.id === "fnd-002");
    expect(updated1?.status).toBe("RESOLVED");
    expect(updated1?.assignee).toBe("security-lead@kelvin.io");
    expect(updated2?.status).toBe("RESOLVED");
    expect(updated2?.assignee).toBe("security-lead@kelvin.io");
  });

  it("exports findings as valid JSON payload", async () => {
    const jsonStr = await exportFindings("json", { severity: "CRITICAL" });
    const parsed = JSON.parse(jsonStr);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBeGreaterThan(0);
    parsed.forEach((f: { severity: string }) => {
      expect(f.severity).toBe("CRITICAL");
    });
  });

  it("exports findings as formatted CSV data", async () => {
    const csvStr = await exportFindings("csv");
    const lines = csvStr.split("\n");
    expect(lines.length).toBeGreaterThan(1);
    expect(lines[0]).toContain("ID");
    expect(lines[0]).toContain("Title");
    expect(lines[0]).toContain("Severity");
    expect(lines[0]).toContain("Status");
    expect(lines[0]).toContain("Risk Score");
  });

  it("strictly enforces assessmentId scope isolation and prevents finding leakage across assessments", async () => {
    // 1. Existing default assessment returns its scoped findings
    const asmt1 = await fetchFindings({ assessmentId: "asmt-2026-001" });
    expect(asmt1.items.length).toBeGreaterThan(0);
    asmt1.items.forEach((f) => {
      expect(f.assessmentId).toBe("asmt-2026-001");
    });

    // 2. An unrelated or newly queued assessment with no findings returns empty list (zero cross-target leakage)
    const unrelatedAsmt = await fetchFindings({ assessmentId: "asmt-devbuildz-custom-999" });
    expect(unrelatedAsmt.items).toHaveLength(0);
    expect(unrelatedAsmt.total).toBe(0);

    // 3. Querying by target host ensures strict domain isolation
    const netlifyFindings = await fetchFindings({ target: "devbuildz.netlify.app" });
    expect(netlifyFindings.items).toHaveLength(0);
    expect(netlifyFindings.total).toBe(0);
  });
});
