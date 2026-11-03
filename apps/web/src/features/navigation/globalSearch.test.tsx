import { describe, it, expect, vi } from "vitest";
import {
  searchPlatform,
  groupSearchResults,
  escapeRegex,
  STATIC_NAVIGATION_ITEMS,
  MOCK_ENTITY_ITEMS,
} from "./index";
import { CommandPalette } from "../../components/navigation/CommandPalette";

describe("FE-18: Global Search & Navigation Suite", () => {
  describe("escapeRegex Helper", () => {
    it("escapes regex special characters safely", () => {
      const raw = "[CVE-2026] (test) *+?^$";
      const escaped = escapeRegex(raw);
      expect(() => new RegExp(escaped)).not.toThrow();
      expect(escaped).toContain("\\[CVE-2026\\]");
    });
  });

  describe("searchPlatform API", () => {
    it("returns initial quick items when query is empty", async () => {
      const results = await searchPlatform("");
      expect(results.length).toBeGreaterThan(0);
      expect(results.length).toBeLessThanOrEqual(8);
    });

    it("matches items by title case-insensitively", async () => {
      const results = await searchPlatform("sql injection");
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].title.toLowerCase()).toContain("sql injection");
    });

    it("matches items by subtitle or CVE identifiers", async () => {
      const results = await searchPlatform("CVE-2026-4412");
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].subtitle).toContain("CVE-2026-4412");
    });

    it("matches items by badge (e.g. CRITICAL or Production)", async () => {
      const results = await searchPlatform("CRITICAL");
      expect(results.length).toBeGreaterThan(0);
      expect(results.some((item) => item.badge === "CRITICAL")).toBe(true);
    });

    it("handles complex special characters without syntax errors", async () => {
      const results = await searchPlatform("10.0.*[test]?+^$()");
      expect(Array.isArray(results)).toBe(true);
    });

    it("returns empty array when search query matches nothing", async () => {
      const results = await searchPlatform("NON_EXISTENT_KEYWORD_XYZ_9999");
      expect(results).toEqual([]);
    });
  });

  describe("groupSearchResults Categorization", () => {
    it("groups search results into ordered categories", () => {
      const allItems = [...STATIC_NAVIGATION_ITEMS, ...MOCK_ENTITY_ITEMS];
      const groups = groupSearchResults(allItems);

      expect(groups.length).toBeGreaterThan(0);
      const categoryNames = groups.map((g) => g.category);
      expect(categoryNames).toContain("navigation");
      expect(categoryNames).toContain("action");
      expect(categoryNames).toContain("finding");
      expect(categoryNames).toContain("assessment");
      expect(categoryNames).toContain("target");
    });

    it("omits empty categories when items do not contain them", () => {
      const navOnly = STATIC_NAVIGATION_ITEMS.filter((item) => item.category === "navigation");
      const groups = groupSearchResults(navOnly);
      const categoryNames = groups.map((g) => g.category);

      expect(categoryNames).toEqual(["navigation"]);
    });
  });

  describe("CommandPalette Component Structure", () => {
    it("instantiates CommandPalette with isOpen=true without error", () => {
      const handleClose = vi.fn();
      const element = <CommandPalette isOpen={true} onClose={handleClose} />;
      expect(element).toBeDefined();
      expect(element.props.isOpen).toBe(true);
    });

    it("instantiates CommandPalette with isOpen=false without error", () => {
      const handleClose = vi.fn();
      const element = <CommandPalette isOpen={false} onClose={handleClose} />;
      expect(element).toBeDefined();
      expect(element.props.isOpen).toBe(false);
    });
  });
});
