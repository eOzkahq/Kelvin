export type Problem = {
  type: string;
  title: string;
  status: number;
  detail?: string;
  instance?: string;
  correlation_id: string;
  timestamp: string;
  errors?: Array<{
    field: string;
    code: string;
    message: string;
    allowed_values?: string[];
  }>;
  retry_after_seconds?: number;
};

export type SuccessEnvelope<T> = {
  success: true;
  data: T;
  meta?: {
    limit?: number;
    count?: number;
    next_cursor?: string | null;
    has_more?: boolean;
    total?: number;
  };
};

export function isProblem(body: unknown): body is Problem {
  return (
    typeof body === "object" &&
    body !== null &&
    "type" in body &&
    typeof (body as Problem).type === "string" &&
    (body as Problem).type.startsWith("urn:kelvin:problem:")
  );
}
