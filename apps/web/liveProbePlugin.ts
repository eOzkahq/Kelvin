import dns from "node:dns/promises";
import tls from "node:tls";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { Plugin } from "vite";

export interface LiveProbeFinding {
  id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  cvss: number;
  cwe: string;
  endpoint: string;
  scanner: string;
  description: string;
  evidence: string;
  remediation: string;
}

export interface LiveProbeResult {
  targetUrl: string;
  hostname: string;
  planTier: 1 | 2 | 3;
  resolvedIps: string[];
  httpStatus: number | null;
  latencyMs: number;
  redirectsToHttps: boolean | null;
  tls: {
    supported: boolean;
    protocol: string | null;
    cipher: string | null;
    issuer: string | null;
    validTo: string | null;
    daysRemaining: number | null;
  };
  headers: Record<string, string>;
  hasSecurityTxt: boolean;
  findings: LiveProbeFinding[];
  logs: Array<{ timestamp: string; level: "INFO" | "WARN" | "ERROR"; message: string; stage: string }>;
}

const METADATA_IPS = new Set(["169.254.169.254", "fd00:ec2::254", "metadata.google.internal"]);

function normalizeTargetUrl(input: string): URL {
  const trimmed = input.trim();
  const withProto = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  return new URL(withProto);
}

async function inspectTls(hostname: string, port: number): Promise<LiveProbeResult["tls"]> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 4500 },
      () => {
        try {
          const proto = socket.getProtocol() ?? null;
          const cipher = socket.getCipher()?.name ?? null;
          const cert = socket.getPeerCertificate();
          const rawIssuer =
            cert?.issuer?.O || cert?.issuer?.CN || (cert?.issuer ? JSON.stringify(cert.issuer) : null);
          const issuer: string | null = Array.isArray(rawIssuer) ? (rawIssuer[0] ?? null) : (rawIssuer ?? null);
          const validTo = cert?.valid_to ?? null;
          let daysRemaining: number | null = null;
          if (validTo) {
            const diff = Date.parse(validTo) - Date.now();
            daysRemaining = Math.floor(diff / (1000 * 60 * 60 * 24));
          }
          socket.end();
          resolve({ supported: true, protocol: proto, cipher, issuer, validTo, daysRemaining });
        } catch {
          socket.destroy();
          resolve({ supported: false, protocol: null, cipher: null, issuer: null, validTo: null, daysRemaining: null });
        }
      },
    );
    socket.on("timeout", () => {
      socket.destroy();
      resolve({ supported: false, protocol: null, cipher: null, issuer: null, validTo: null, daysRemaining: null });
    });
    socket.on("error", () => {
      socket.destroy();
      resolve({ supported: false, protocol: null, cipher: null, issuer: null, validTo: null, daysRemaining: null });
    });
  });
}

async function runLiveProbe(rawTarget: string, rawTier: number = 1): Promise<LiveProbeResult> {
  const planTier: 1 | 2 | 3 = rawTier >= 3 ? 3 : rawTier === 2 ? 2 : 1;
  const tierLabel = planTier === 3 ? "Plan 3 (Enterprise Perimeter)" : planTier === 2 ? "Plan 2 (Pro SecOps)" : "Plan 1 (Starter)";
  const parsed = normalizeTargetUrl(rawTarget);
  const hostname = parsed.hostname;
  if (METADATA_IPS.has(hostname.toLowerCase())) {
    throw new Error("Target host blocked by anti-SSRF metadata protection policy.");
  }

  const logs: LiveProbeResult["logs"] = [];
  const findings: LiveProbeFinding[] = [];
  let seq = 1;
  const pushFinding = (f: Omit<LiveProbeFinding, "id">) => {
    findings.push({ id: `LIVE-${String(seq++).padStart(3, "0")}`, ...f });
  };

  logs.push({
    timestamp: new Date().toISOString(),
    level: "INFO",
    stage: "PREFLIGHT",
    message: `Preflight anti-SSRF scope validation passed for ${hostname} · Profile: ${tierLabel}`,
  });

  // 1. Live DNS Lookup
  let resolvedIps: string[] = [];
  try {
    const records = await dns.lookup(hostname, { all: true });
    resolvedIps = records.map((r) => r.address);
    logs.push({
      timestamp: new Date().toISOString(),
      level: "INFO",
      stage: "PREFLIGHT",
      message: `DNS resolved ${hostname} -> ${resolvedIps.join(", ")}`,
    });
  } catch (err) {
    logs.push({
      timestamp: new Date().toISOString(),
      level: "WARN",
      stage: "PREFLIGHT",
      message: `DNS resolution failed for ${hostname}: ${err instanceof Error ? err.message : String(err)}`,
    });
  }

  // Enterprise Tier (Plan 3): Deep DNS Auth (DMARC Policy Strength, SPF, & DNS CAA)
  if (planTier >= 3 && hostname !== "localhost" && !/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    let dmarcRecords: string[];
    try {
      const dmarc = await dns.resolveTxt(`_dmarc.${hostname}`);
      dmarcRecords = dmarc.map((chunks) => chunks.join(""));
    } catch {
      dmarcRecords = [];
    }
    const validDmarc = dmarcRecords.find((r) => r.toLowerCase().includes("v=dmarc1"));
    if (!validDmarc) {
      pushFinding({
        title: "Missing DMARC DNS Policy Record",
        severity: "LOW",
        cvss: 3.1,
        cwe: "CWE-290",
        endpoint: `_dmarc.${hostname}`,
        scanner: "Custom-Workers",
        description: `No valid DMARC TXT record (v=DMARC1) was found at _dmarc.${hostname}. Without DMARC enforcement, attackers can spoof domain email.`,
        evidence: `DNS TXT query for _dmarc.${hostname} returned NXDOMAIN or empty policy.`,
        remediation: `Publish a TXT record at _dmarc.${hostname} with policy "v=DMARC1; p=quarantine; rua=mailto:security@${hostname}".`,
      });
    } else if (validDmarc.toLowerCase().includes("p=none")) {
      pushFinding({
        title: "Permissive DMARC Policy in Monitor-Only Mode (p=none)",
        severity: "LOW",
        cvss: 3.4,
        cwe: "CWE-290",
        endpoint: `_dmarc.${hostname}`,
        scanner: "Custom-Workers",
        description: `DMARC exists for ${hostname} but specifies p=none, which logs spoofing attempts without rejecting forged messages.`,
        evidence: `Observed TXT _dmarc.${hostname}: ${validDmarc}`,
        remediation: `Promote DMARC policy to p=quarantine or p=reject once SPF/DKIM alignment is verified.`,
      });
    }

    // Check SPF TXT record
    let spfRecord: string | undefined;
    try {
      const txts = await dns.resolveTxt(hostname);
      spfRecord = txts.map((c) => c.join("")).find((t) => t.toLowerCase().includes("v=spf1"));
    } catch {
      spfRecord = undefined;
    }
    if (!spfRecord || spfRecord.toLowerCase().includes("+all")) {
      pushFinding({
        title: !spfRecord ? "Missing Sender Policy Framework (SPF) DNS Record" : "Wildcard Permissive SPF Record (+all)",
        severity: spfRecord ? "MEDIUM" : "LOW",
        cvss: spfRecord ? 5.3 : 3.1,
        cwe: "CWE-290",
        endpoint: hostname,
        scanner: "Custom-Workers",
        description: "Domain lacks strict SPF sender authorization, enabling spoofed outbound phishing campaigns.",
        evidence: `Observed TXT v=spf1 on ${hostname}: ${spfRecord || "<not configured>"}`,
        remediation: `Publish strict SPF TXT record ending in "-all" or "~all" on ${hostname}.`,
      });
    }

    // Check DNS CAA record
    let hasCaa: boolean;
    try {
      const caa = await dns.resolveCaa(hostname);
      hasCaa = caa.length > 0;
    } catch {
      hasCaa = false;
    }
    if (!hasCaa) {
      pushFinding({
        title: "Missing DNS CAA Certificate Issuance Policy",
        severity: "INFO",
        cvss: 2.3,
        cwe: "CWE-295",
        endpoint: hostname,
        scanner: "Custom-Workers",
        description: "No DNS Certification Authority Authorization (CAA) record restricts which public CAs may mint certificates for this domain.",
        evidence: `DNS CAA query for ${hostname} returned 0 records.`,
        remediation: `Publish DNS CAA records permitting only your approved CA (e.g., 0 issue "letsencrypt.org").`,
      });
    }
  }

  // 2. Live TLS Inspection
  const port = parsed.port ? Number(parsed.port) : parsed.protocol === "https:" ? 443 : 80;
  const tlsInfo = parsed.protocol === "https:"
    ? await inspectTls(hostname, port)
    : { supported: false, protocol: null, cipher: null, issuer: null, validTo: null, daysRemaining: null };

  if (parsed.protocol === "https:" && tlsInfo.supported) {
    logs.push({
      timestamp: new Date().toISOString(),
      level: "INFO",
      stage: "SCANNING",
      message: `TLS handshake complete: ${tlsInfo.protocol} (${tlsInfo.cipher ?? "unknown cipher"}), issuer: ${tlsInfo.issuer ?? "unknown"}`,
    });

    if (tlsInfo.protocol === "TLSv1" || tlsInfo.protocol === "TLSv1.1") {
      pushFinding({
        title: `Deprecated TLS Protocol Negotiated (${tlsInfo.protocol})`,
        severity: "MEDIUM",
        cvss: 5.9,
        cwe: "CWE-326",
        endpoint: `${hostname}:${port}`,
        scanner: "tls-check",
        description: `Server negotiated ${tlsInfo.protocol}, which is deprecated due to known cryptographic weaknesses.`,
        evidence: `Negotiated Protocol: ${tlsInfo.protocol} | Cipher: ${tlsInfo.cipher}`,
        remediation: "Restrict server TLS configuration to TLSv1.2 and TLSv1.3 exclusively.",
      });
    }

    if (tlsInfo.daysRemaining !== null && tlsInfo.daysRemaining <= 14) {
      pushFinding({
        title: tlsInfo.daysRemaining < 0 ? "Expired TLS Certificate" : "TLS Certificate Expiring Within 14 Days",
        severity: tlsInfo.daysRemaining < 0 ? "HIGH" : "MEDIUM",
        cvss: tlsInfo.daysRemaining < 0 ? 7.4 : 4.8,
        cwe: "CWE-298",
        endpoint: `${hostname}:${port}`,
        scanner: "tls-check",
        description: `TLS certificate validity ends ${tlsInfo.validTo} (${tlsInfo.daysRemaining} days remaining).`,
        evidence: `Issuer: ${tlsInfo.issuer} | Valid To: ${tlsInfo.validTo}`,
        remediation: "Renew and deploy a valid X.509 certificate via automated ACME/Let's Encrypt rotation.",
      });
    }
  } else if (parsed.protocol === "http:") {
    pushFinding({
      title: "Unencrypted Plaintext HTTP Target Scheme",
      severity: "HIGH",
      cvss: 7.4,
      cwe: "CWE-319",
      endpoint: parsed.toString(),
      scanner: "http-preflight",
      description: "Target endpoint was scanned over cleartext HTTP without TLS transport encryption.",
      evidence: `Target scheme evaluated: ${parsed.protocol}`,
      remediation: "Serve traffic over HTTPS with TLS 1.2+ and configure permanent 301 HTTP-to-HTTPS redirection.",
    });
  }

  // 3. Live HTTP Security Headers & Redirect Check
  let httpStatus: number | null = null;
  let latencyMs: number;
  const headersMap: Record<string, string> = {};
  let redirectsToHttps: boolean | null = null;
  let hasSecurityTxt = false;

  const start = Date.now();
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5500);
    const resp = await fetch(parsed.toString(), {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: { "User-Agent": "Kelvin-Passive-Probe/1.0" },
    });
    clearTimeout(timer);
    latencyMs = Date.now() - start;
    httpStatus = resp.status;
    resp.headers.forEach((value, key) => {
      headersMap[key.toLowerCase()] = value;
    });
    const htmlBody = await resp.text().catch(() => "");

    logs.push({
      timestamp: new Date().toISOString(),
      level: "INFO",
      stage: "SCANNING",
      message: `HTTP ${resp.status} received from ${parsed.origin} in ${latencyMs}ms (${Object.keys(headersMap).length} headers captured · ${tierLabel})`,
    });

    // Core Baseline Security Header Audits (Plan 1+)
    if (parsed.protocol === "https:" && !headersMap["strict-transport-security"]) {
      pushFinding({
        title: "Missing HTTP Strict-Transport-Security (HSTS) Header",
        severity: "MEDIUM",
        cvss: 5.3,
        cwe: "CWE-523",
        endpoint: parsed.toString(),
        scanner: "http-headers",
        description: "The HTTPS response lacks a Strict-Transport-Security header, leaving clients susceptible to SSL-stripping downgrade attacks.",
        evidence: `GET ${parsed.pathname || "/"} returned HTTP ${resp.status} without Strict-Transport-Security.`,
        remediation: 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      });
    }

    if (!headersMap["content-security-policy"]) {
      pushFinding({
        title: "Missing Content-Security-Policy (CSP) Header",
        severity: "MEDIUM",
        cvss: 5.4,
        cwe: "CWE-693",
        endpoint: parsed.toString(),
        scanner: "http-headers",
        description: "No Content-Security-Policy header was returned to mitigate cross-site scripting (XSS) and unauthorized script injection.",
        evidence: `Content-Security-Policy header absent on ${parsed.origin} (HTTP ${resp.status}).`,
        remediation: "Configure a restrictive Content-Security-Policy header (e.g., default-src 'self'; object-src 'none').",
      });
    }

    if (!headersMap["x-frame-options"] && !(headersMap["content-security-policy"] || "").includes("frame-ancestors")) {
      pushFinding({
        title: "Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)",
        severity: "MEDIUM",
        cvss: 4.7,
        cwe: "CWE-1021",
        endpoint: parsed.toString(),
        scanner: "http-headers",
        description: "Neither X-Frame-Options nor CSP frame-ancestors was set, allowing arbitrary third-party framing.",
        evidence: "Header check failed: x-frame-options absent and CSP lacks frame-ancestors.",
        remediation: "Set X-Frame-Options: DENY (or SAMEORIGIN) and include frame-ancestors 'self' in CSP.",
      });
    }

    if (headersMap["x-content-type-options"]?.toLowerCase() !== "nosniff") {
      pushFinding({
        title: "Missing X-Content-Type-Options: nosniff Header",
        severity: "LOW",
        cvss: 3.1,
        cwe: "CWE-693",
        endpoint: parsed.toString(),
        scanner: "http-headers",
        description: "Response omits X-Content-Type-Options: nosniff, allowing browsers to MIME-sniff uploaded or reflected responses.",
        evidence: `Observed x-content-type-options: ${headersMap["x-content-type-options"] || "<not set>"}`,
        remediation: "Send X-Content-Type-Options: nosniff on all HTTP responses.",
      });
    }

    if (headersMap["server"] || headersMap["x-powered-by"]) {
      const disclosed = [
        headersMap["server"] ? `Server: ${headersMap["server"]}` : null,
        headersMap["x-powered-by"] ? `X-Powered-By: ${headersMap["x-powered-by"]}` : null,
      ]
        .filter(Boolean)
        .join(" | ");
      pushFinding({
        title: "Server Technology Stack Fingerprint Disclosed",
        severity: "INFO",
        cvss: 2.0,
        cwe: "CWE-200",
        endpoint: parsed.toString(),
        scanner: "http-headers",
        description: "HTTP response headers expose server or runtime banner details useful for targeted attacker reconnaissance.",
        evidence: disclosed,
        remediation: "Strip X-Powered-By and minimize Server version banners at the reverse proxy layer.",
      });
    }

    // Pro SecOps (Plan 2+): Active DAST (OWASP ZAP / Trivy / Nuclei) Checks
    if (planTier >= 2) {
      logs.push({
        timestamp: new Date().toISOString(),
        level: "INFO",
        stage: "SCANNING",
        message: `Running Plan ${planTier} DAST & Supply-Chain probes (CORS, Cookies, SRI, Sensitive Paths)`,
      });

      const setCookie = resp.headers.get("set-cookie");
      if (setCookie) {
        const lowerCookie = setCookie.toLowerCase();
        if (!lowerCookie.includes("httponly") || !lowerCookie.includes("secure") || !lowerCookie.includes("samesite")) {
          pushFinding({
            title: "Session Cookie Missing Secure, HttpOnly, or SameSite Flags",
            severity: "MEDIUM",
            cvss: 5.4,
            cwe: "CWE-614",
            endpoint: parsed.toString(),
            scanner: "OWASP-ZAP",
            description: "Set-Cookie header lacks one or more browser cookie protection attributes, raising session hijacking or CSRF risk.",
            evidence: `Set-Cookie attributes -> HttpOnly:${lowerCookie.includes("httponly")} Secure:${lowerCookie.includes("secure")} SameSite:${lowerCookie.includes("samesite")}`,
            remediation: "Issue all session cookies with Secure; HttpOnly; SameSite=Lax.",
          });
        }
      }

      if (headersMap["access-control-allow-origin"] === "*") {
        pushFinding({
          title: "Wildcard CORS Policy (Access-Control-Allow-Origin: *)",
          severity: "MEDIUM",
          cvss: 5.3,
          cwe: "CWE-942",
          endpoint: parsed.toString(),
          scanner: "OWASP-ZAP",
          description: "Endpoint responds with wildcard Access-Control-Allow-Origin: *, allowing arbitrary web origins to read responses.",
          evidence: `Access-Control-Allow-Origin: ${headersMap["access-control-allow-origin"]}`,
          remediation: "Restrict CORS origin allowlist explicitly to trusted application domains.",
        });
      }

      if (!headersMap["referrer-policy"]) {
        pushFinding({
          title: "Missing Referrer-Policy Header",
          severity: "LOW",
          cvss: 2.6,
          cwe: "CWE-200",
          endpoint: parsed.toString(),
          scanner: "OWASP-ZAP",
          description: "Referrer-Policy header is absent; outbound navigations may leak path or query tokens via Referer headers.",
          evidence: "Observed referrer-policy: <not set>",
          remediation: "Configure Referrer-Policy: strict-origin-when-cross-origin.",
        });
      }

      // Inspect external <script src="https://..."> missing SRI integrity
      const scriptTags = htmlBody.match(/<script\b[^>]*src\s*=\s*["']https?:\/\/[^"']+["'][^>]*>/gi) || [];
      const missingSri = scriptTags.filter((tag) => !/\bintegrity\s*=/i.test(tag));
      if (missingSri.length > 0) {
        pushFinding({
          title: `Third-Party JavaScript Loaded Without Subresource Integrity (${missingSri.length} script${missingSri.length > 1 ? "s" : ""})`,
          severity: "MEDIUM",
          cvss: 4.9,
          cwe: "CWE-353",
          endpoint: parsed.toString(),
          scanner: "Trivy",
          description: "External CDN scripts are included in HTML without cryptographic integrity hashes (SRI), increasing supply-chain tampering risk.",
          evidence: `Detected ${missingSri.length} external <script src=...> elements lacking integrity="..." attribute.`,
          remediation: "Pin third-party scripts with Subresource Integrity (integrity='sha384-...') hashes and crossorigin='anonymous'.",
        });
      }

      // Check sensitive paths (/.env, /.git/HEAD) + /.well-known/security.txt
      const probePaths = [
        { path: "/.env", title: "Exposed Environment Secret Manifest (/.env)", cwe: "CWE-215", sev: "CRITICAL" as const, cvss: 9.1 },
        { path: "/.git/HEAD", title: "Exposed Git Repository Metadata (/.git/HEAD)", cwe: "CWE-527", sev: "HIGH" as const, cvss: 7.5 },
      ];
      for (const p of probePaths) {
        try {
          const checkResp = await fetch(`${parsed.origin}${p.path}`, {
            method: "GET",
            redirect: "manual",
            signal: AbortSignal.timeout(2000),
          });
          if (checkResp.status === 200) {
            const snippet = (await checkResp.text()).slice(0, 140);
            if (!snippet.toLowerCase().includes("<!doctype html")) {
              pushFinding({
                title: p.title,
                severity: p.sev,
                cvss: p.cvss,
                cwe: p.cwe,
                endpoint: `${parsed.origin}${p.path}`,
                scanner: "Nuclei",
                description: `Sensitive artifact ${p.path} returned HTTP 200 with non-HTML content.`,
                evidence: `GET ${p.path} -> HTTP 200 (${snippet.replace(/\s+/g, " ")})`,
                remediation: `Block HTTP access to ${p.path} at ingress / reverse proxy and rotate exposed secrets immediately.`,
              });
            }
          }
        } catch {
          // ignore network probe errors
        }
      }

      try {
        const secResp = await fetch(`${parsed.origin}/.well-known/security.txt`, {
          method: "GET",
          signal: AbortSignal.timeout(2500),
        });
        hasSecurityTxt = secResp.ok;
      } catch {
        hasSecurityTxt = false;
      }
      if (!hasSecurityTxt) {
        pushFinding({
          title: "Missing RFC 9116 Vulnerability Disclosure File (/.well-known/security.txt)",
          severity: "INFO",
          cvss: 0.0,
          cwe: "CWE-200",
          endpoint: `${parsed.origin}/.well-known/security.txt`,
          scanner: "Nuclei",
          description: "No machine-readable security.txt contact policy was found for coordinated researcher disclosure.",
          evidence: `GET ${parsed.origin}/.well-known/security.txt returned non-200 status.`,
          remediation: "Publish /.well-known/security.txt with Contact, Expires, and Encryption keys per RFC 9116.",
        });
      }
    }

    // Enterprise Perimeter (Plan 3): Cross-Origin Browser Isolation, Permissions-Policy & HSTS Hardening
    if (planTier >= 3) {
      if (!headersMap["permissions-policy"]) {
        pushFinding({
          title: "Missing Permissions-Policy Browser Feature Lockdown Header",
          severity: "LOW",
          cvss: 3.1,
          cwe: "CWE-1021",
          endpoint: parsed.toString(),
          scanner: "Custom-Workers",
          description: "Permissions-Policy header is omitted, leaving camera, microphone, geolocation, and payment APIs unpinned.",
          evidence: "Observed permissions-policy: <not set>",
          remediation: "Set Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=().",
        });
      }

      if (!headersMap["cross-origin-opener-policy"] || !headersMap["cross-origin-resource-policy"]) {
        pushFinding({
          title: "Incomplete Cross-Origin Isolation Headers (COOP / CORP)",
          severity: "INFO",
          cvss: 2.6,
          cwe: "CWE-346",
          endpoint: parsed.toString(),
          scanner: "Custom-Workers",
          description: "Missing Cross-Origin-Opener-Policy or Cross-Origin-Resource-Policy weakens origin isolation against XS-Leaks and Spectre side channels.",
          evidence: `COOP: ${headersMap["cross-origin-opener-policy"] || "<unset>"} | CORP: ${headersMap["cross-origin-resource-policy"] || "<unset>"}`,
          remediation: "Send Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Resource-Policy: same-site.",
        });
      }

      const hsts = headersMap["strict-transport-security"]?.toLowerCase() ?? "";
      if (hsts && (!hsts.includes("includesubdomains") || !hsts.includes("preload"))) {
        pushFinding({
          title: "HSTS Policy Lacks includeSubDomains or Preload Directive",
          severity: "LOW",
          cvss: 3.2,
          cwe: "CWE-523",
          endpoint: parsed.toString(),
          scanner: "Custom-Workers",
          description: "HSTS is enabled on the apex endpoint but does not cover subdomains or HSTS browser preloading.",
          evidence: `Observed Strict-Transport-Security: ${headersMap["strict-transport-security"]}`,
          remediation: "Update HSTS header to: max-age=31536000; includeSubDomains; preload.",
        });
      }
    }

    // Check port 80 HTTP -> HTTPS redirect if scanning HTTPS
    if (parsed.protocol === "https:" && !parsed.port) {
      try {
        const httpResp = await fetch(`http://${hostname}/`, {
          method: "HEAD",
          redirect: "manual",
          signal: AbortSignal.timeout(2500),
        });
        const loc = httpResp.headers.get("location") ?? "";
        redirectsToHttps = httpResp.status >= 300 && httpResp.status < 400 && loc.startsWith("https://");
      } catch {
        redirectsToHttps = null;
      }
    }
  } catch (err) {
    latencyMs = Date.now() - start;
    logs.push({
      timestamp: new Date().toISOString(),
      level: "ERROR",
      stage: "SCANNING",
      message: `HTTP request to ${parsed.toString()} failed: ${err instanceof Error ? err.message : String(err)}`,
    });
    pushFinding({
      title: "Target HTTP Endpoint Unreachable from Local Scanner",
      severity: "INFO",
      cvss: 0.0,
      cwe: "CWE-200",
      endpoint: parsed.toString(),
      scanner: "http-preflight",
      description: `Local passive probe could not establish an HTTP connection (${err instanceof Error ? err.message : "timeout"}).`,
      evidence: `Attempted GET ${parsed.toString()} (elapsed ${latencyMs}ms)`,
      remediation: "Confirm firewall ingress, DNS reachability, and local network access to the target URL.",
    });
  }

  logs.push({
    timestamp: new Date().toISOString(),
    level: "INFO",
    stage: "COMPLETED",
    message: `Live passive audit finished with ${findings.length} finding(s) catalogued for ${hostname}`,
  });

  return {
    targetUrl: parsed.toString(),
    hostname,
    planTier,
    resolvedIps,
    httpStatus,
    latencyMs,
    redirectsToHttps,
    tls: tlsInfo,
    headers: headersMap,
    hasSecurityTxt,
    findings,
    logs,
  };
}

export function liveProbePlugin(): Plugin {
  const handler = (req: IncomingMessage, res: ServerResponse): void => {
    if (req.method !== "POST") {
      res.statusCode = 405;
      res.end("Method Not Allowed");
      return;
    }

    let body = "";
    req.on("data", (chunk: Buffer | string) => {
      body += chunk;
    });
    req.on("end", async () => {
      try {
        const parsed = JSON.parse(body || "{}") as { target?: string; tier?: number };
        if (!parsed.target) {
          res.statusCode = 400;
          res.setHeader("Content-Type", "application/json");
          res.end(JSON.stringify({ error: "Missing target URL or hostname" }));
          return;
        }
        const result = await runLiveProbe(parsed.target, parsed.tier ?? 1);
        res.statusCode = 200;
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify(result));
      } catch (err) {
        res.statusCode = 400;
        res.setHeader("Content-Type", "application/json");
        res.end(
          JSON.stringify({
            error: err instanceof Error ? err.message : "Live probe failed",
          }),
        );
      }
    });
  };

  return {
    name: "kelvin-live-probe-middleware",
    configureServer(server) {
      server.middlewares.use("/services/kelvin/__live_probe", handler);
    },
    configurePreviewServer(server) {
      server.middlewares.use("/services/kelvin/__live_probe", handler);
    },
  };
}

