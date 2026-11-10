import { QueryClient } from "@tanstack/react-query";
import { ApiError } from "./api";

export const QUERY_PROFILES = {
  STATIC: {
    staleTime: 300_000, // 5 mins
    gcTime: 10 * 60_000,
  },
  REALTIME: {
    staleTime: 5_000, // 5 secs
    gcTime: 60_000,
  },
  STANDARD: {
    staleTime: 30_000, // 30 secs
    gcTime: 5 * 60_000,
  },
} as const;

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // Data is considered fresh according to STANDARD profile
        staleTime: QUERY_PROFILES.STANDARD.staleTime,
        // Inactive cache garbage collected after 5 minutes
        gcTime: QUERY_PROFILES.STANDARD.gcTime,
        // Avoid automatic background refetches that might leak data or cause unintended server load
        refetchOnWindowFocus: false,
        refetchOnReconnect: true,
        // Smart retry: do not retry authentication errors or client not-found errors
        retry: (failureCount, error) => {
          if (error instanceof ApiError) {
            if (error.status === 401 || error.status === 403 || error.status === 404) {
              return false;
            }
          }
          return failureCount < 2;
        },
      },
      mutations: {
        retry: false,
      },
    },
  });
}

export const queryClient = createQueryClient();
