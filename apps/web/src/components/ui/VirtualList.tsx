import React, { useState, useRef, useMemo, useCallback } from "react";

export interface VirtualListProps<T> {
  items: T[];
  itemHeight: number;
  height: number;
  overscan?: number;
  renderItem: (item: T, index: number) => React.ReactNode;
  className?: string;
  emptyPlaceholder?: React.ReactNode;
}

export function calculateVirtualIndices(
  scrollTop: number,
  containerHeight: number,
  itemHeight: number,
  totalItems: number,
  overscan = 5
) {
  if (totalItems === 0 || itemHeight <= 0) {
    return { startIndex: 0, endIndex: 0, topPadding: 0, bottomPadding: 0 };
  }

  const rawStartIndex = Math.floor(scrollTop / itemHeight);
  const visibleCount = Math.ceil(containerHeight / itemHeight);

  const startIndex = Math.max(0, rawStartIndex - overscan);
  const endIndex = Math.min(totalItems, rawStartIndex + visibleCount + overscan);

  const topPadding = startIndex * itemHeight;
  const bottomPadding = Math.max(0, (totalItems - endIndex) * itemHeight);

  return { startIndex, endIndex, topPadding, bottomPadding };
}

export function VirtualList<T>({
  items,
  itemHeight,
  height,
  overscan = 5,
  renderItem,
  className = "",
  emptyPlaceholder,
}: VirtualListProps<T>) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);

  const handleScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    setScrollTop(e.currentTarget.scrollTop);
  }, []);

  const { startIndex, endIndex, topPadding, bottomPadding } = useMemo(() => {
    return calculateVirtualIndices(scrollTop, height, itemHeight, items.length, overscan);
  }, [scrollTop, height, itemHeight, items.length, overscan]);

  if (items.length === 0) {
    return (
      <div style={{ height }} className={`flex items-center justify-center ${className}`}>
        {emptyPlaceholder || <span className="text-xs text-zinc-500">No items available</span>}
      </div>
    );
  }

  const visibleItems = items.slice(startIndex, endIndex);

  return (
    <div
      ref={containerRef}
      onScroll={handleScroll}
      style={{ height, overflowY: "auto" }}
      className={`relative w-full ${className}`}
    >
      <div style={{ paddingTop: topPadding, paddingBottom: bottomPadding }}>
        {visibleItems.map((item, idx) => renderItem(item, startIndex + idx))}
      </div>
    </div>
  );
}
