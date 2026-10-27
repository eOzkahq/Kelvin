export const REDACTION_MARKER_PREFIX = "[REDACTED:";
export const REDACTION_MARKER_SUFFIX = "]";

export function redactionMarker(rule: string): string {
  return `${REDACTION_MARKER_PREFIX}${rule}${REDACTION_MARKER_SUFFIX}`;
}

export function redact(value: string, rule: string): string {
  if (value.length === 0) {
    return value;
  }
  return redactionMarker(rule);
}
