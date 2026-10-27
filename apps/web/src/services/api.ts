import { isProblem, type SuccessEnvelope } from "@kelvin/common";

export type HealthData = {
  status: string;
  apiVersion: string;
};

const API_BASE = import.meta.env.VITE_API_BASE ?? "/api/v1";

export class ApiError extends Error {
  readonly status: number;
  readonly correlationId: string | undefined;

  constructor(status: number, message: string, correlationId?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.correlationId = correlationId;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...init?.headers,
    },
  });

  const body: unknown = await res.json().catch(() => null);

  if (!res.ok) {
    if (isProblem(body)) {
      throw new ApiError(res.status, body.detail ?? body.title, body.correlation_id);
    }
    throw new ApiError(res.status, `request failed with status ${res.status}`);
  }

  const envelope = body as SuccessEnvelope<T>;
  if (envelope === null || typeof envelope !== "object" || envelope.success !== true) {
    throw new ApiError(res.status, "response did not match the Kelvin success envelope");
  }
  return envelope.data;
}

export function fetchHealth(signal?: AbortSignal): Promise<HealthData> {
  return request<HealthData>("/health", { signal });
}
