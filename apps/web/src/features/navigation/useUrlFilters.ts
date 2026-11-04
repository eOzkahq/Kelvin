import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";

export type FilterValue = string | number | boolean | undefined;

export interface UseUrlFiltersReturn<T extends Record<string, FilterValue>> {
  filters: T;
  setFilter: <K extends keyof T>(key: K, value: T[K]) => void;
  setFilters: (updates: Partial<T>) => void;
  resetFilters: () => void;
  hasActiveFilters: boolean;
}

export function useUrlFilters<T extends Record<string, FilterValue>>(
  defaultValues: T
): UseUrlFiltersReturn<T> {
  const [searchParams, setSearchParams] = useSearchParams();

  const filters = useMemo(() => {
    const current: Record<string, FilterValue> = { ...defaultValues };

    for (const key of Object.keys(defaultValues)) {
      const paramVal = searchParams.get(key);
      if (paramVal !== null) {
        const defaultVal = defaultValues[key];
        if (typeof defaultVal === "number") {
          const parsed = Number(paramVal);
          current[key] = isNaN(parsed) ? defaultVal : parsed;
        } else if (typeof defaultVal === "boolean") {
          current[key] = paramVal === "true";
        } else {
          current[key] = paramVal;
        }
      }
    }

    return current as T;
  }, [searchParams, defaultValues]);

  const setFilter = useCallback(
    <K extends keyof T>(key: K, value: T[K]) => {
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (value === undefined || value === null || value === "" || value === defaultValues[key]) {
            next.delete(String(key));
          } else {
            next.set(String(key), String(value));
          }
          return next;
        },
        { replace: true }
      );
    },
    [setSearchParams, defaultValues]
  );

  const setFilters = useCallback(
    (updates: Partial<T>) => {
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          for (const [k, v] of Object.entries(updates)) {
            if (v === undefined || v === null || v === "" || v === defaultValues[k]) {
              next.delete(k);
            } else {
              next.set(k, String(v));
            }
          }
          return next;
        },
        { replace: true }
      );
    },
    [setSearchParams, defaultValues]
  );

  const resetFilters = useCallback(() => {
    setSearchParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        for (const key of Object.keys(defaultValues)) {
          next.delete(key);
        }
        return next;
      },
      { replace: true }
    );
  }, [setSearchParams, defaultValues]);

  const hasActiveFilters = useMemo(() => {
    for (const key of Object.keys(defaultValues)) {
      if (filters[key] !== defaultValues[key]) {
        return true;
      }
    }
    return false;
  }, [filters, defaultValues]);

  return {
    filters,
    setFilter,
    setFilters,
    resetFilters,
    hasActiveFilters,
  };
}
