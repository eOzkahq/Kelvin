import { describe, it, expect } from "vitest";
import * as assessments from "./assessments";
import * as findings from "./findings";
import * as remediation from "./remediation";
import type {
  AssessmentRecord,
  AssessmentDetail,
  AssessmentStatus,
  CreateAssessmentPayload,
} from "./assessments";
import type {
  Finding,
  FindingDetail,
  FindingSeverity,
  FindingStatus,
  FindingsListResponse,
  BatchUpdatePayload,
} from "./findings";
import type {
  RemediationTask,
  RemediationStatus,
  VerificationStatus,
  RemediationNote,
} from "./remediation";

describe("FE-25: Frontend Contract Reconciliation Suite", () => {
  describe("Assessments Barrel & Type Alignment", () => {
    it("exports all required assessment API functions and types", () => {
      expect(typeof assessments.fetchAssessments).toBe("function");
      expect(typeof assessments.fetchAssessmentDetail).toBe("function");
      expect(typeof assessments.createAssessment).toBe("function");
      expect(typeof assessments.cancelAssessment).toBe("function");
      expect(typeof assessments.fetchProfiles).toBe("function");
      expect(typeof assessments.fetchTargets).toBe("function");
    });

    it("verifies AssessmentRecord and AssessmentDetail shape against Go DTOs", () => {
      const status: AssessmentStatus = "RUNNING";
      expect(status).toBe("RUNNING");

      const payload: CreateAssessmentPayload = {
        name: "Test",
        profileId: "prof-01",
        authorizedScopeConfirmed: true,
        idempotencyKey: "key-1",
      };
      expect(payload.name).toBe("Test");

      const record: AssessmentRecord = {
        id: "asmt-001",
        name: "Test Run",
        targetAddress: "api.example.com",
        profileId: "prof-01",
        profileName: "Baseline",
        status,
        criticalCount: 0,
        highCount: 1,
        totalFindings: 5,
        createdAt: new Date().toISOString(),
      };
      expect(record.id).toBe("asmt-001");

      const detail: AssessmentDetail = {
        ...record,
        currentStage: "SCANNING",
        scanners: [
          {
            id: "sc-1",
            scanner: "Nuclei",
            status: "RUNNING",
            findingsCount: 2,
          },
        ],
        logs: [
          {
            id: "log-1",
            timestamp: new Date().toISOString(),
            level: "INFO",
            message: "Running scan",
          },
        ],
      };
      expect(detail.currentStage).toBe("SCANNING");
      expect(detail.scanners.length).toBe(1);
    });
  });

  describe("Findings Barrel & Type Alignment", () => {
    it("exports all required findings API functions and sanitizers", () => {
      expect(typeof findings.fetchFindings).toBe("function");
      expect(typeof findings.getFindingDetail).toBe("function");
      expect(typeof findings.transitionFindingStatus).toBe("function");
      expect(typeof findings.batchUpdateFindings).toBe("function");
      expect(typeof findings.exportFindings).toBe("function");
      expect(typeof findings.sanitizeEvidence).toBe("function");
    });

    it("verifies Finding and FindingDetail shape against Go PersistentFinding models", () => {
      const sev: FindingSeverity = "CRITICAL";
      const stat: FindingStatus = "OPEN";
      expect(sev).toBe("CRITICAL");
      expect(stat).toBe("OPEN");

      const finding: Finding = {
        id: "fnd-100",
        fingerprint: "sha256:abc123",
        title: "SQL Injection",
        severity: sev,
        status: stat,
        target: "db.example.com",
        affectedEndpoint: "/query",
        scanner: "ZAP",
        riskScore: 9.5,
        firstSeenAt: new Date().toISOString(),
        lastSeenAt: new Date().toISOString(),
      };
      expect(finding.severity).toBe("CRITICAL");
      expect(finding.riskScore).toBe(9.5);

      const listRes: FindingsListResponse = {
        items: [finding],
        total: 1,
        page: 1,
        limit: 10,
        totalPages: 1,
      };
      expect(listRes.total).toBe(1);

      const batchPayload: BatchUpdatePayload = {
        findingIds: ["fnd-100"],
        action: "STATUS_TRANSITION",
        status: "RESOLVED",
      };
      expect(batchPayload.action).toBe("STATUS_TRANSITION");

      const detail: FindingDetail = {
        ...finding,
        riskExplainability: {
          formula: "base * multiplier",
          contributingFactors: [{ name: "Asset Exposure", weight: 1.2, impact: "+1.2x" }],
          baseCvss: 9.0,
          contextualScore: 9.5,
        },
        evidence: [
          {
            id: "ev-1",
            sha256: "hash123",
            sanitizedPayload: "SELECT * FROM users",
          },
        ],
        observations: [
          {
            id: "obs-1",
            scanner: "ZAP",
            observedAt: new Date().toISOString(),
          },
        ],
        auditTrail: [
          {
            id: "aud-1",
            timestamp: new Date().toISOString(),
            actor: "analyst",
            toStatus: "OPEN",
            justification: "Triaged",
          },
        ],
      };
      expect(detail.evidence.length).toBe(1);
      expect(detail.observations.length).toBe(1);
    });
  });

  describe("Remediation Barrel & Type Alignment", () => {
    it("exports all required remediation API functions and types", () => {
      expect(typeof remediation.fetchRemediationTasks).toBe("function");
      expect(typeof remediation.updateTaskStatus).toBe("function");
      expect(typeof remediation.triggerVerificationScan).toBe("function");
      expect(typeof remediation.addRemediationNote).toBe("function");
    });

    it("verifies RemediationTask and Note shape against Go Remediation models", () => {
      const remStatus: RemediationStatus = "IN_PROGRESS";
      const verStatus: VerificationStatus = "UNVERIFIED";
      expect(remStatus).toBe("IN_PROGRESS");
      expect(verStatus).toBe("UNVERIFIED");

      const note: RemediationNote = {
        id: "not-01",
        author: "analyst@kelvin.io",
        content: "Fix applied in PR #123",
        createdAt: new Date().toISOString(),
      };
      const task: RemediationTask = {
        id: "rem-001",
        findingId: "fnd-100",
        findingTitle: "SQL Injection",
        title: "Fix SQL injection in /query endpoint",
        status: remStatus,
        severity: "CRITICAL",
        target: "db.example.com",
        affectedEndpoint: "/query",
        verificationStatus: verStatus,
        slaHoursRemaining: 24,
        isOverdue: false,
        notes: [note],
        createdAt: new Date().toISOString(),
      };
      expect(task.status).toBe("IN_PROGRESS");
      expect(task.notes.length).toBe(1);
    });
  });
});
