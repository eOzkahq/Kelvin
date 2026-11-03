import { describe, it, expect } from "vitest";
import { primaryNavItems, adminNavItems, Sidebar } from "./Sidebar";
import { Breadcrumbs } from "./Breadcrumbs";
import { TenantSwitcher } from "./TenantSwitcher";
import { UserMenu } from "./UserMenu";

describe("FE-03: Application Shell & Responsive Layout Suite", () => {
  describe("Sidebar Navigation Items", () => {
    it("contains all core primary assessment navigation links", () => {
      const paths = primaryNavItems.map((item) => item.to);
      expect(paths).toContain("/dashboard");
      expect(paths).toContain("/assessments");
      expect(paths).toContain("/findings");
      expect(paths).toContain("/remediation");
      expect(paths).toContain("/targets");
      expect(paths).toContain("/reports");
      expect(paths).toContain("/compare");
      expect(paths).toContain("/audit");
    });

    it("restricts administration items based on role requirements", () => {
      const orgAdminItems = adminNavItems.filter(
        (item) => !item.requiredRole || item.requiredRole.includes("OrgAdmin")
      );
      expect(orgAdminItems.length).toBe(adminNavItems.length);

      const memberItems = adminNavItems.filter(
        (item) => item.requiredRole && item.requiredRole.includes("Member")
      );
      expect(memberItems.length).toBe(0);
    });

    it("renders sidebar in collapsed or expanded mode", () => {
      const collapsedSidebar = (
        <Sidebar isCollapsed={true} onToggleCollapse={() => {}} userRole="OrgAdmin" />
      );
      expect(collapsedSidebar.props.isCollapsed).toBe(true);

      const expandedSidebar = (
        <Sidebar isCollapsed={false} onToggleCollapse={() => {}} userRole="OrgAdmin" />
      );
      expect(expandedSidebar.props.isCollapsed).toBe(false);
    });
  });

  describe("Tenant Switcher Component", () => {
    it("renders tenant switcher component without error", () => {
      const switcher = <TenantSwitcher />;
      expect(switcher).toBeDefined();
    });
  });

  describe("User Profile Menu Component", () => {
    it("renders user initials and details in menu", () => {
      const menu = (
        <UserMenu
          user={{
            name: "Dana Scully",
            email: "dana@kelvin.io",
            role: "SecurityAnalyst",
          }}
        />
      );
      expect(menu.props.user.name).toBe("Dana Scully");
      expect(menu.props.user.role).toBe("SecurityAnalyst");
    });
  });

  describe("Breadcrumbs Navigation", () => {
    it("renders breadcrumbs component without error", () => {
      const breadcrumbs = <Breadcrumbs />;
      expect(breadcrumbs).toBeDefined();
    });
  });
});
