import { QueryClient } from "@tanstack/react-query";
import { ApiError } from "./api";

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // Data is considered fresh for 30 seconds
        staleTime: 30_000,
        // Inactive cache garbage collected after 5 minutes
        gcTime: 5 * 60_000,
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
