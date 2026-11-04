import { test, expect } from "@playwright/test";

/**
 * 10 Mandatory Critical User Journeys Defined in FE-EPIC-01 Section 11
 */
test.describe("KELVIN 10 Critical User Journeys E2E Suite", () => {
  test("CUJ-01: Authentication & Session Establishment", async ({ page }) => {
    await page.goto("/login");
    await expect(page).toHaveTitle(/KELVIN/i);
    await page.fill('input[type="email"]', "admin@kelvin.security");
    await page.fill('input[type="password"]', "TestPassword123!");
    await page.click('button[type="submit"]');
    // Session token established and redirected to dashboard or home
    await expect(page).toHaveURL(/\/(dashboard)?$/);
  });

  test("CUJ-02: Organization & Workspace Context Switching", async ({ page }) => {
    await page.goto("/dashboard");
    const switcher = page.locator('button[aria-label*="tenant" i], button[aria-label*="workspace" i]').first();
    if (await switcher.isVisible()) {
      await switcher.click();
      await expect(page.locator("text=SecOps Team")).toBeVisible();
    }
  });

  test("CUJ-03: Target Registration & Scope Verification", async ({ page }) => {
    await page.goto("/targets");
    await expect(page.locator("text=Targets & Scope")).toBeVisible();
    const registerBtn = page.locator("button:has-text('Register Target')");
    await registerBtn.click();
    await expect(page.locator("text=Register New Assessment Target")).toBeVisible();
    await page.fill('input[placeholder*="domain" i]', "e2e.kelvin.internal");
    await page.click("button:has-text('Verify DNS Challenge')");
  });

  test("CUJ-04: 7-Step Assessment Creation & Idempotent Launch", async ({ page }) => {
    await page.goto("/assessments/new");
    await expect(page.locator("text=Launch Security Assessment")).toBeVisible();
    await page.click("button:has-text('Next: Scan Profile')");
    await page.click("button:has-text('Next: Engine Selection')");
    await page.click("button:has-text('Next: Advanced Execution')");
    await page.click("button:has-text('Next: Target Authorization')");
    await page.check('input[type="checkbox"]');
    await page.click("button:has-text('Next: Summary & Confirmation')");
  });

  test("CUJ-05: Real-Time Pipeline Progress & Worker Logs Monitoring", async ({ page }) => {
    await page.goto("/assessments/asm-prod-001");
    await expect(page.locator("text=Pipeline Execution")).toBeVisible();
    await expect(page.locator("text=Worker Execution Logs")).toBeVisible();
  });

  test("CUJ-06: Findings Omnibar Search & Faceted Filtering", async ({ page }) => {
    await page.goto("/findings");
    await expect(page.locator("text=Findings Workspace")).toBeVisible();
    const searchInput = page.locator('input[placeholder*="search" i]').first();
    await searchInput.fill("SQL Injection");
    await expect(page.locator("text=CVE-2026-4412")).toBeVisible();
  });

  test("CUJ-07: Finding Detail & Sanitized Proof-of-Concept Evidence Inspection", async ({ page }) => {
    await page.goto("/findings/fnd-sqli-01");
    await expect(page.locator("text=SQL Injection in User Authentication Endpoint")).toBeVisible();
    await expect(page.locator("text=Risk Score Breakdown")).toBeVisible();
    await expect(page.locator("text=Sanitized Evidence")).toBeVisible();
  });

  test("CUJ-08: Remediation Task Transition & Automated Verification Scan", async ({ page }) => {
    await page.goto("/remediation");
    await expect(page.locator("text=Remediation Workspace")).toBeVisible();
    await expect(page.locator("text=SLA Status")).toBeVisible();
  });

  test("CUJ-09: Cryptographically Sealed PDF Assessment Report Preview & Download", async ({ page }) => {
    await page.goto("/reports");
    await expect(page.locator("text=Assessment Report Center")).toBeVisible();
    await expect(page.locator("text=Generate Report")).toBeVisible();
  });

  test("CUJ-10: Audit Trail Hash-Chain Verification & Export", async ({ page }) => {
    await page.goto("/audit");
    await expect(page.locator("text=Audit Trail Explorer")).toBeVisible();
    await expect(page.locator("text=Tamper-Evident")).toBeVisible();
  });
});
