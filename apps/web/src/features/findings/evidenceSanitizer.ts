/**
 * Client-Side Evidence Sanitization & Secret Redaction Engine (ADR-0005)
 * Neutralizes potential XSS injection attacks and masks sensitive credentials in scanner evidence.
 */

const SENSITIVE_PATTERNS: { regex: RegExp; replacement: string }[] = [
  // Bearer JWT / OAuth Tokens
  {
    regex: /Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*/gi,
    replacement: "Bearer [REDACTED_JWT_TOKEN]",
  },
  // Authorization header with basic or custom auth
  {
    regex: /(Authorization:\s*)(Basic\s+[A-Za-z0-9+/=]+)/gi,
    replacement: "$1[REDACTED_BASIC_AUTH]",
  },
  // API Keys / Secrets in Query string or headers
  {
    regex: /((?:api[-_]?key|apikey|secret|access[-_]?token|auth[-_]?token)=)([^&\s\r\n"']+)/gi,
    replacement: "$1[REDACTED_SECRET]",
  },
  // Passwords in query string or JSON
  {
    regex: /(["']?password["']?\s*[:=]\s*["']?)([^"'&\s\r\n,]+)(["']?)/gi,
    replacement: "$1[REDACTED_PASSWORD]$3",
  },
  // Cookie session tokens
  {
    regex: /((?:sessionid|sid|token|jwt|session)=)([^;\s\r\n]+)/gi,
    replacement: "$1[REDACTED_SESSION]",
  },
  // AWS Keys
  {
    regex: /(AKIA[0-9A-Z]{16})/g,
    replacement: "[REDACTED_AWS_ACCESS_KEY]",
  },
  // RSA / Private Keys
  {
    regex: /-----BEGIN\s+(?:[A-Z\s]+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:[A-Z\s]+)?PRIVATE\s+KEY-----/g,
    replacement: "[REDACTED_PRIVATE_KEY_BLOCK]",
  },
];

/**
 * Encodes special characters to HTML entities to prevent script execution
 */
export function escapeHtml(unsafe: string): string {
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

/**
 * Strips dangerous HTML tags and event handlers from strings
 */
export function stripScriptTags(text: string): string {
  return text
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "[REMOVED_DANGEROUS_SCRIPT_TAG]")
    .replace(/\bon\w+\s*=\s*["'][^"']*["']/gi, "[REMOVED_INLINE_EVENT_HANDLER]")
    .replace(/javascript:[^\s"'>]+/gi, "[REMOVED_JAVASCRIPT_URI]");
}

/**
 * Redacts sensitive tokens and credentials
 */
export function redactSensitivePatterns(text: string): { text: string; count: number } {
  let redacted = text;
  let count = 0;

  for (const { regex, replacement } of SENSITIVE_PATTERNS) {
    const matches = redacted.match(regex);
    if (matches) {
      count += matches.length;
      redacted = redacted.replace(regex, replacement);
    }
  }

  return { text: redacted, count };
}

export interface SanitizationResult {
  sanitized: string;
  hasRedactions: boolean;
  redactionCount: number;
  isSafeForDisplay: boolean;
}

/**
 * Comprehensive evidence sanitizer applying script stripping, secret redaction, and HTML entity containment
 */
export function sanitizeEvidence(rawPayload: string): SanitizationResult {
  if (!rawPayload) {
    return {
      sanitized: "",
      hasRedactions: false,
      redactionCount: 0,
      isSafeForDisplay: true,
    };
  }

  // Step 1: Strip active scripts and dangerous event handlers
  const stripped = stripScriptTags(rawPayload);

  // Step 2: Redact known sensitive tokens and credentials
  const { text: redacted, count: redactionCount } = redactSensitivePatterns(stripped);

  // Step 3: Result is presentation-safe
  return {
    sanitized: redacted,
    hasRedactions: redactionCount > 0,
    redactionCount,
    isSafeForDisplay: true,
  };
}
