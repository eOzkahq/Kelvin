/**
 * Production-safe logger that suppresses debug noise and redacts secrets.
 */

const SENSITIVE_KEY_PATTERN = /(password|token|bearer|secret|authorization|cookie|apiKey)/i;

/**
 * Deeply redacts sensitive keys from objects before logging.
 */
export function sanitizeLogData(data: unknown): unknown {
  if (typeof data !== "object" || data === null) {
    if (typeof data === "string" && data.toLowerCase().includes("bearer ")) {
      return data.replace(/bearer\s+[a-zA-Z0-9._-]+/gi, "Bearer [REDACTED]");
    }
    return data;
  }

  if (Array.isArray(data)) {
    return data.map((item) => sanitizeLogData(item));
  }

  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
    if (SENSITIVE_KEY_PATTERN.test(key)) {
      sanitized[key] = "[REDACTED]";
    } else {
      sanitized[key] = sanitizeLogData(value);
    }
  }

  return sanitized;
}

export const logger = {
  debug: (...args: unknown[]) => {
    if (import.meta.env?.MODE !== "production") {
      // eslint-disable-next-line no-console
      console.debug(...args.map((a) => sanitizeLogData(a)));
    }
  },
  info: (...args: unknown[]) => {
    // eslint-disable-next-line no-console
    console.info(...args.map((a) => sanitizeLogData(a)));
  },
  warn: (...args: unknown[]) => {
    // eslint-disable-next-line no-console
    console.warn(...args.map((a) => sanitizeLogData(a)));
  },
  error: (...args: unknown[]) => {
    // eslint-disable-next-line no-console
    console.error(...args.map((a) => sanitizeLogData(a)));
  },
};
