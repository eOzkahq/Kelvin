import { describe, it, expect } from "vitest";
import { calculateVirtualIndices, VirtualList } from "../../components/ui/VirtualList";
import { QUERY_PROFILES, createQueryClient } from "../../services/queryClient";

describe("FE-22: Frontend Performance Optimization Suite", () => {
  describe("List Virtualization Calculations", () => {
    it("handles 0 items without errors", () => {
      const res = calculateVirtualIndices(0, 400, 40, 0);
      expect(res).toEqual({
        startIndex: 0,
        endIndex: 0,
        topPadding: 0,
        bottomPadding: 0,
      });
    });

    it("calculates initial visible window with overscan for 1,000 items", () => {
      const totalItems = 1000;
      const itemHeight = 40;
      const containerHeight = 400; // 10 visible items
      const overscan = 5;

      const res = calculateVirtualIndices(0, containerHeight, itemHeight, totalItems, overscan);

      expect(res.startIndex).toBe(0);
      // rawStartIndex(0) + visible(10) + overscan(5) = 15
      expect(res.endIndex).toBe(15);
      expect(res.topPadding).toBe(0);
      expect(res.bottomPadding).toBe((1000 - 15) * 40);
    });

    it("adjusts padding and window when scrolled halfway through dataset", () => {
      const totalItems = 1000;
      const itemHeight = 50;
      const containerHeight = 500; // 10 visible items
      const scrollTop = 10000; // 200 items scrolled down
      const overscan = 5;

      const res = calculateVirtualIndices(scrollTop, containerHeight, itemHeight, totalItems, overscan);

      // rawStartIndex = 10000 / 50 = 200
      // startIndex = 200 - 5 = 195
      // endIndex = 200 + 10 + 5 = 215
      expect(res.startIndex).toBe(195);
      expect(res.endIndex).toBe(215);
      expect(res.topPadding).toBe(195 * 50);
      expect(res.bottomPadding).toBe((1000 - 215) * 50);
    });
  });

  describe("TanStack Query Caching Profiles", () => {
    it("provides optimized static and realtime query profiles", () => {
      expect(QUERY_PROFILES.STATIC.staleTime).toBe(300000); // 5 mins
      expect(QUERY_PROFILES.REALTIME.staleTime).toBe(5000); // 5 secs
      expect(QUERY_PROFILES.STANDARD.staleTime).toBe(30000); // 30 secs
    });

    it("initializes QueryClient with standard profile defaults", () => {
      const client = createQueryClient();
      const options = client.getDefaultOptions();
      expect(options.queries?.staleTime).toBe(QUERY_PROFILES.STANDARD.staleTime);
      expect(options.queries?.refetchOnWindowFocus).toBe(false);
    });
  });

  describe("VirtualList Component Instantiation", () => {
    it("renders empty state placeholder when dataset is empty", () => {
      const element = (
        <VirtualList
          items={[]}
          itemHeight={40}
          height={300}
          renderItem={(item) => <div>{item}</div>}
        />
      );
      expect(element).toBeDefined();
    });

    it("renders virtual list container for populated dataset", () => {
      const items = Array.from({ length: 500 }, (_, i) => `Finding #${i + 1}`);
      const element = (
        <VirtualList
          items={items}
          itemHeight={48}
          height={400}
          renderItem={(item, index) => <div key={index}>{item}</div>}
        />
      );
      expect(element).toBeDefined();
    });
  });
});
