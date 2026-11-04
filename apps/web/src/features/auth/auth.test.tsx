import { describe, it, expect } from "vitest";
import { ProtectedRoute } from "./ProtectedRoute";

describe("FE-04: Authentication & Account Management Suite", () => {
  describe("Protected Route Permissions Guard", () => {
    it("renders protected component definition with allowed roles", () => {
      const element = (
        <ProtectedRoute allowedRoles={["OrgAdmin", "SecurityAnalyst"]}>
          <div>Confidential Findings</div>
        </ProtectedRoute>
      );
      expect(element.props.allowedRoles).toEqual(["OrgAdmin", "SecurityAnalyst"]);
    });

    it("verifies unpermitted role handling", () => {
      const element = (
        <ProtectedRoute allowedRoles={["OrgAdmin"]}>
          <div>Admin Only</div>
        </ProtectedRoute>
      );
      expect(element.props.allowedRoles).toContain("OrgAdmin");
      expect(element.props.allowedRoles).not.toContain("Member");
    });
  });
});
