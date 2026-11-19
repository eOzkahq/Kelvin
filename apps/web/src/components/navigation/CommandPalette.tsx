import React, { useState, useEffect, useRef, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { SearchIcon, FileTextIcon } from "../ui/Icons";
import {
  searchPlatform,
  groupSearchResults,
  type SearchResultItem,
} from "../../features/navigation";

export interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({ isOpen, onClose }) => {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResultItem[]>([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [recentSearches, setRecentSearches] = useState<string[]>(() => {
    try {
      const stored = localStorage.getItem("kelvin_recent_searches");
      return stored ? JSON.parse(stored) : [];
    } catch {
      return [];
    }
  });

  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();

  // Reset query and autofocus input when opened
  useEffect(() => {
    if (isOpen) {
      setQuery("");
      setSelectedIndex(0);
      searchPlatform("").then(setResults);
      // Small timeout to ensure DOM is ready
      setTimeout(() => {
        inputRef.current?.focus();
      }, 50);
    }
  }, [isOpen]);

  // Execute debounced search when query changes
  useEffect(() => {
    if (!isOpen) return;

    const timer = setTimeout(async () => {
      const items = await searchPlatform(query);
      setResults(items);
      setSelectedIndex(0);
    }, 80);

    return () => clearTimeout(timer);
  }, [query, isOpen]);

  // Grouped results
  const grouped = useMemo(() => groupSearchResults(results), [results]);

  // Flattened items for keyboard indexing
  const flattenedItems = useMemo(() => {
    return grouped.flatMap((g) => g.items);
  }, [grouped]);

  const recordSearchSelection = (item: SearchResultItem) => {
    try {
      const updated = [item.title, ...recentSearches.filter((s) => s !== item.title)].slice(0, 5);
      setRecentSearches(updated);
      localStorage.setItem("kelvin_recent_searches", JSON.stringify(updated));
    } catch {
      // Ignore storage errors
    }
  };

  const handleSelectItem = (item: SearchResultItem) => {
    recordSearchSelection(item);
    onClose();
    navigate(item.url);
  };

  // Keyboard navigation within command palette
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev + 1 < flattenedItems.length ? prev + 1 : 0));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIndex((prev) => (prev - 1 >= 0 ? prev - 1 : flattenedItems.length - 1));
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (flattenedItems[selectedIndex]) {
        handleSelectItem(flattenedItems[selectedIndex]);
      }
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    }
  };

  // Scroll active item into view
  useEffect(() => {
    if (listRef.current) {
      const activeEl = listRef.current.querySelector('[data-active="true"]');
      if (activeEl) {
        activeEl.scrollIntoView({ block: "nearest" });
      }
    }
  }, [selectedIndex]);

  if (!isOpen) return null;

  let currentItemCounter = 0;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-black/75 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label="Global Command Palette"
      onClick={onClose}
    >
      <div
        className="w-full max-w-2xl overflow-hidden rounded-2xl border border-zinc-800/80 bg-zinc-900/95 shadow-2xl shadow-black/80 backdrop-blur-md"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
      >
        {/* Search Input Bar */}
        <div className="relative flex items-center border-b border-zinc-800 px-4 py-3.5">
          <SearchIcon size={16} className="text-[var(--brand-text)] mr-3" />
          <input
            ref={inputRef}
            type="text"
            className="w-full bg-transparent text-sm text-zinc-100 placeholder-zinc-500 focus:outline-none"
            placeholder="Type a command or search targets, assessments, findings..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            aria-label="Search platform"
            role="combobox"
            aria-expanded="true"
            aria-controls="command-palette-results"
          />
          {query && (
            <button
              type="button"
              onClick={() => setQuery("")}
              className="text-zinc-500 hover:text-zinc-300 text-xs px-2 py-1 rounded"
              aria-label="Clear search query"
            >
              ✕
            </button>
          )}
          <kbd className="ml-2 rounded border border-zinc-700 bg-zinc-800 px-1.5 py-0.5 text-[10px] font-mono text-zinc-400">
            ESC
          </kbd>
        </div>

        {/* Results Container */}
        <div
          ref={listRef}
          id="command-palette-results"
          role="listbox"
          className="max-h-96 overflow-y-auto p-2"
        >
          {flattenedItems.length === 0 ? (
            <div className="py-8 text-center text-sm text-zinc-500">
              No matching assets, findings, or actions found for &ldquo;{query}&rdquo;
            </div>
          ) : (
            grouped.map((group) => (
              <div key={group.category} className="mb-3">
                <div className="px-3 py-1 text-[11px] font-semibold uppercase tracking-wider text-zinc-500">
                  {group.title}
                </div>
                <div className="space-y-1">
                  {group.items.map((item) => {
                    const itemIndex = currentItemCounter++;
                    const isSelected = itemIndex === selectedIndex;

                    return (
                      <div
                        key={item.id}
                        role="option"
                        aria-selected={isSelected}
                        data-active={isSelected}
                        onClick={() => handleSelectItem(item)}
                        onMouseEnter={() => setSelectedIndex(itemIndex)}
                        className={`flex items-center justify-between rounded-lg px-3 py-2 text-sm cursor-pointer transition-colors ${isSelected
                              ? "bg-[var(--brand-bg)] text-[var(--brand-strong)] border border-[var(--brand-border)]"
                              : "text-zinc-300 hover:bg-zinc-800/60 border border-transparent"
                        }`}
                      >
                        <div className="flex items-center gap-3 overflow-hidden">
                          <span className="text-zinc-400 flex-shrink-0" aria-hidden="true">
                            <FileTextIcon size={14} />
                          </span>
                          <div className="truncate">
                            <div className="font-medium truncate">{item.title}</div>
                            {item.subtitle && (
                              <div className="text-xs text-zinc-500 truncate">{item.subtitle}</div>
                            )}
                          </div>
                        </div>

                        <div className="flex items-center gap-2 flex-shrink-0 ml-4">
                          {item.badge && (
                            <span
                              className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${item.badge === "CRITICAL"
                                  ? "bg-red-950 text-red-400 border border-red-800"
                                  : item.badge === "HIGH"
                                    ? "bg-orange-950 text-orange-400 border border-orange-800"
                                    : item.badge === "Production"
                                      ? "bg-cyan-950 text-cyan-400 border border-cyan-800"
                                      : "bg-zinc-800 text-zinc-400 border border-zinc-700"
                                }`}
                            >
                              {item.badge}
                            </span>
                          )}
                          {item.shortcut && (
                            <kbd className="hidden sm:inline-block rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] font-mono text-zinc-400 border border-zinc-700">
                              {item.shortcut}
                            </kbd>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))
          )}
        </div>

        {/* Footer shortcuts hint */}
        <div className="flex items-center justify-between border-t border-zinc-800 bg-zinc-950/60 px-4 py-2 text-[11px] text-zinc-500">
          <div className="flex items-center gap-4">
            <span>
              <kbd className="rounded bg-zinc-800 px-1 py-0.5 font-mono text-zinc-400">↑</kbd>{" "}
              <kbd className="rounded bg-zinc-800 px-1 py-0.5 font-mono text-zinc-400">↓</kbd> to navigate
            </span>
            <span>
              <kbd className="rounded bg-zinc-800 px-1 py-0.5 font-mono text-zinc-400">↵</kbd> to select
            </span>
            <span>
              <kbd className="rounded bg-zinc-800 px-1 py-0.5 font-mono text-zinc-400">esc</kbd> to close
            </span>
          </div>
          <span className="font-mono text-[10px] text-zinc-500">
            <kbd className="rounded bg-zinc-800 px-1 py-0.5 text-zinc-400">Ctrl+Shift+P</kbd> · <kbd className="rounded bg-zinc-800 px-1 py-0.5 text-zinc-400">/</kbd>
          </span>
        </div>
      </div>
    </div>
  );
};
