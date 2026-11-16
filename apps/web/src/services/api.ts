import { isProblem, type SuccessEnvelope } from "@kelvin/common";

export type HealthData = {
  status: string;
  apiVersion: string;
};

export type TenantContext = {
  tenantId?: string;
  workspaceId?: string;
};

export class ApiError extends Error {
  readonly status: number;
  readonly correlationId?: string;
  readonly code?: string;
  readonly details?: unknown;

  constructor(status: number, message: string, correlationId?: string, code?: string, details?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.correlationId = correlationId;
    this.code = code;
    this.details = details;
  }
}

// In-memory state for token and tenant context
let currentAuthToken: string | null = null;
let currentTenantContext: TenantContext = {};
const unauthorizedListeners = new Set<() => void>();

export function setAuthToken(token: string | null): void {
  currentAuthToken = token;
}

export function getAuthToken(): string | null {
  return currentAuthToken;
}

export function clearAuthToken(): void {
  currentAuthToken = null;
}

export function setTenantContext(context: TenantContext): void {
  currentTenantContext = { ...context };
}

export function getTenantContext(): TenantContext {
  return { ...currentTenantContext };
}

export function onUnauthorized(callback: () => void): () => void {
  unauthorizedListeners.add(callback);
  return () => unauthorizedListeners.delete(callback);
}

function notifyUnauthorized(): void {
  for (const listener of unauthorizedListeners) {
    try {
      listener();
    } catch {
      // Ignore listener error
    }
  }
}

export interface RequestOptions extends RequestInit {
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 30_000;

export function getApiBaseUrl(): string {
  const envUrl = (import.meta.env?.VITE_API_BASE_URL || import.meta.env?.VITE_API_BASE || "").trim();
  if (!envUrl) {
    return "/api/v1";
  }
  const clean = envUrl.replace(/\/+$/, "");
  if (clean.endsWith("/api/v1")) {
    return clean;
  }
  return `${clean}/api/v1`;
}

export async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, headers, signal, ...restInit } = options;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort(new Error(`Request timed out after ${timeoutMs}ms`));
  }, timeoutMs);

  // Link external signal if provided
  if (signal) {
    if (signal.aborted) {
      controller.abort(signal.reason);
    } else {
      signal.addEventListener("abort", () => controller.abort(signal.reason), { once: true });
    }
  }

  const requestHeaders: Record<string, string> = {
    Accept: "application/json",
    ...((headers as Record<string, string>) ?? {}),
  };

  // Content-Type default if body present
  if (restInit.body && !requestHeaders["Content-Type"]) {
    requestHeaders["Content-Type"] = "application/json";
  }

  // Interceptor: Inject Auth Token
  if (currentAuthToken && !requestHeaders["Authorization"]) {
    requestHeaders["Authorization"] = `Bearer ${currentAuthToken}`;
  }

  // Interceptor: Inject Tenant & Workspace Context
  if (currentTenantContext.tenantId && !requestHeaders["X-Tenant-ID"]) {
    requestHeaders["X-Tenant-ID"] = currentTenantContext.tenantId;
  }
  if (currentTenantContext.workspaceId && !requestHeaders["X-Workspace-ID"]) {
    requestHeaders["X-Workspace-ID"] = currentTenantContext.workspaceId;
  }

  const url = `${getApiBaseUrl()}${path.startsWith("/") ? path : `/${path}`}`;

  try {
    const res = await fetch(url, {
      ...restInit,
      headers: requestHeaders,
      signal: controller.signal,
    });

    const body: unknown = await res.json().catch(() => null);

    if (!res.ok) {
      if (res.status === 401) {
        notifyUnauthorized();
      }

      if (isProblem(body)) {
        throw new ApiError(
          res.status,
          body.detail ?? body.title,
          body.correlation_id,
          body.type,
          body.errors,
        );
      }

      if (typeof body === "object" && body !== null) {
        const anyBody = body as Record<string, unknown>;
        const message =
          (anyBody.detail as string) || (anyBody.title as string) || (anyBody.message as string);
        if (message) {
          throw new ApiError(
            res.status,
            message,
            anyBody.correlation_id as string | undefined,
            anyBody.type as string | undefined,
            anyBody.invalid_params ?? anyBody.errors,
          );
        }
      }

      throw new ApiError(res.status, `Request failed with status ${res.status}`);
    }

    // Kelvin standard success envelope: { success: true, data: T }
    const envelope = body as SuccessEnvelope<T>;
    if (envelope !== null && typeof envelope === "object" && envelope.success === true) {
      return envelope.data;
    }

    // If response is bare object (e.g. legacy/mock endpoint)
    return body as T;
  } finally {
    clearTimeout(timeoutId);
  }
}

// Typed convenience methods
export const apiClient = {
  get<T>(path: string, options?: RequestOptions): Promise<T> {
    return request<T>(path, { ...options, method: "GET" });
  },

  post<T>(path: string, data?: unknown, options?: RequestOptions): Promise<T> {
    return request<T>(path, {
      ...options,
      method: "POST",
      body: data !== undefined ? JSON.stringify(data) : undefined,
    });
  },

  put<T>(path: string, data?: unknown, options?: RequestOptions): Promise<T> {
    return request<T>(path, {
      ...options,
      method: "PUT",
      body: data !== undefined ? JSON.stringify(data) : undefined,
    });
  },

  patch<T>(path: string, data?: unknown, options?: RequestOptions): Promise<T> {
    return request<T>(path, {
      ...options,
      method: "PATCH",
      body: data !== undefined ? JSON.stringify(data) : undefined,
    });
  },

  delete<T>(path: string, options?: RequestOptions): Promise<T> {
    return request<T>(path, { ...options, method: "DELETE" });
  },
};

export function fetchHealth(signal?: AbortSignal): Promise<HealthData> {
  return apiClient.get<HealthData>("/health", { signal });
}
