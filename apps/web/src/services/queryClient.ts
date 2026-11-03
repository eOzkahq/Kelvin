import { QueryClient } from "@tanstack/react-query";
import { ApiError } from "./api";

export const QUERY_PROFILES = {
  STATIC: {
    staleTime: 5 * 60_000,
    gcTime: 15 * 60_000,
    refetchOnWindowFocus: false,
  },
  STANDARD: {
    staleTime: 30_000,
    gcTime: 5 * 60_000,
    refetchOnWindowFocus: false,
    refetchOnReconnect: true,
  },
  REALTIME: {
    staleTime: 5_000,
    gcTime: 60_000,
    refetchInterval: 5_000,
    refetchOnWindowFocus: true,
  },
} as const;

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: QUERY_PROFILES.STANDARD.staleTime,
        gcTime: QUERY_PROFILES.STANDARD.gcTime,
        refetchOnWindowFocus: QUERY_PROFILES.STANDARD.refetchOnWindowFocus,
        refetchOnReconnect: QUERY_PROFILES.STANDARD.refetchOnReconnect,
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
