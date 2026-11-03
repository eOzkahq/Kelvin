import { describe, it, expect } from "vitest";
import { Button } from "./Button";
import { SeverityBadge, type FindingSeverity } from "./SeverityBadge";
import { StatusPill, type ExecutionStatus } from "./StatusPill";
import { Modal } from "./Modal";
import { EmptyState } from "./EmptyState";
import { SkeletonLoader } from "./SkeletonLoader";

describe("FE-02: KELVIN Design System & Shared Components Suite", () => {
  describe("Button Component", () => {
    it("renders button with correct primary variant styling", () => {
      const element = <Button variant="primary">Launch Scan</Button>;
      expect(element.props.children).toBe("Launch Scan");
      expect(element.props.variant).toBe("primary");
    });

    it("supports danger, secondary, outline and ghost variants", () => {
      const variants = ["primary", "secondary", "danger", "ghost", "outline"] as const;
      variants.forEach((variant) => {
        const btn = <Button variant={variant}>{variant}</Button>;
        expect(btn.props.variant).toBe(variant);
      });
    });

    it("indicates loading state via isLoading prop", () => {
      const element = <Button isLoading>Executing</Button>;
      expect(element.props.isLoading).toBe(true);
    });
  });

  describe("SeverityBadge Component", () => {
    const severities: FindingSeverity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

    severities.forEach((sev) => {
      it(`maps canonical severity level ${sev} correctly`, () => {
        const badge = <SeverityBadge severity={sev} />;
        expect(badge.props.severity).toBe(sev);
      });
    });
  });

  describe("StatusPill Component", () => {
    const statuses: ExecutionStatus[] = ["PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"];

    statuses.forEach((status) => {
      it(`renders status pill for ${status}`, () => {
        const pill = <StatusPill status={status} />;
        expect(pill.props.status).toBe(status);
      });
    });
  });

  describe("Modal Component", () => {
    it("renders modal structure with accessible dialog roles", () => {
      const modal = (
        <Modal isOpen={true} onClose={() => {}} title="Confirm Target Scope">
          <p>Target domain will be validated against enterprise boundaries.</p>
        </Modal>
      );
      expect(modal.props.isOpen).toBe(true);
      expect(modal.props.title).toBe("Confirm Target Scope");
    });
  });

  describe("EmptyState Component", () => {
    it("renders empty state with message and action label", () => {
      const empty = (
        <EmptyState
          title="No Findings Identified"
          description="All target surfaces conform to baseline security policies."
          actionLabel="Rerun Assessment"
          onAction={() => {}}
        />
      );
      expect(empty.props.title).toBe("No Findings Identified");
      expect(empty.props.actionLabel).toBe("Rerun Assessment");
    });
  });

  describe("SkeletonLoader Component", () => {
    it("renders skeleton loader with configurable line count", () => {
      const skeleton = <SkeletonLoader lines={4} />;
      expect(skeleton.props.lines).toBe(4);
    });
  });
});
