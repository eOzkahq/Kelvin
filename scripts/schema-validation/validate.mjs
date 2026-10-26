import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const schemaPath = join(root, "packages", "schemas", "finding.v1.json");
const fixturesDir = join(root, "packages", "schemas", "fixtures");

const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
const ajv = new Ajv2020({ strict: true, allErrors: true, validateFormats: true });
addFormats(ajv);

let failures = 0;
const fail = (msg) => {
  failures += 1;
  console.error(`FAIL  ${msg}`);
};
const ok = (msg) => console.log(`ok    ${msg}`);

let validate;
try {
  validate = ajv.compile(schema);
  ok("schema compiles (ajv draft 2020-12, strict)");
} catch (err) {
  console.error(`FAIL  schema does not compile: ${err.message}`);
  process.exit(1);
}

const listFiles = (dir) =>
  readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .sort();

for (const file of listFiles(join(fixturesDir, "positive"))) {
  const payload = JSON.parse(readFileSync(join(fixturesDir, "positive", file), "utf8"));
  if (validate(payload)) {
    ok(`positive/${file} validates`);
  } else {
    fail(`positive/${file} unexpectedly invalid: ${ajv.errorsText(validate.errors, { separator: "; " })}`);
  }
}

for (const file of listFiles(join(fixturesDir, "negative"))) {
  const payload = JSON.parse(readFileSync(join(fixturesDir, "negative", file), "utf8"));
  if (!validate(payload)) {
    ok(`negative/${file} rejected as required`);
  } else {
    fail(`negative/${file} unexpectedly VALID — strict validation is not enforcing the contract`);
  }
}

const vectors = JSON.parse(readFileSync(join(fixturesDir, "fingerprint-vectors.json"), "utf8"));

function normalizeAsset(asset) {
  const a = String(asset).trim();
  const ipv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6ish = a.includes(":");
  if (ipv4.test(a)) return a.replace(/(^|\.)0+(\d)/g, "$1$2");
  if (ipv6ish) {
    return expandIPv6(a);
  }
  return a.toLowerCase().replace(/\.$/, "");
}

function expandIPv6(addr) {
  let head = addr;
  let zone = "";
  const pct = addr.indexOf("%");
  if (pct !== -1) {
    head = addr.slice(0, pct);
    zone = addr.slice(pct);
  }
  const [left, right] = head.split("::");
  const parseGroups = (s) => (s === "" ? [] : s.split(":"));
  const l = parseGroups(left);
  const r = parseGroups(right === undefined ? "" : right);
  const fill = 8 - (l.length + r.length);
  const groups = [...l, ...Array(Math.max(fill, 0)).fill("0"), ...r].map((g) => {
    const n = parseInt(g === "" ? "0" : g, 16);
    if (Number.isNaN(n) || n < 0 || n > 0xffff) throw new Error(`bad ipv6 group ${g}`);
    return n;
  });
  if (groups.length !== 8) throw new Error(`bad ipv6 ${addr}`);
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  const fmt = (i) => groups[i].toString(16);
  let out;
  if (bestLen >= 2) {
    const parts = [];
    for (let i = 0; i < 8; ) {
      if (i === bestStart) {
        parts.push("");
        i += bestLen;
        if (i >= 8) parts.push("");
      } else {
        parts.push(fmt(i));
        i++;
      }
    }
    out = parts.join(":");
  } else {
    out = groups.map(fmt).join(":");
  }
  return out + zone;
}

function removeDotSegments(path) {
  if (!path) return "/";
  const parts = [];
  for (const seg of path.split("/")) {
    if (seg === "." ) continue;
    if (seg === "..") {
      parts.pop();
      continue;
    }
    parts.push(seg);
  }
  let out = parts.join("/");
  if (!out.startsWith("/")) out = "/" + out;
  return out;
}

function normalizeEndpoint(endpoint) {
  if (endpoint === null || endpoint === undefined || endpoint === "") return "";
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/(.+)$/.exec(endpoint);
  if (!m) throw new Error(`unparseable endpoint ${endpoint}`);
  const scheme = m[1].toLowerCase();
  let rest = m[2];
  const hash = rest.indexOf("#");
  if (hash !== -1) rest = rest.slice(0, hash);
  const q = rest.indexOf("?");
  if (q !== -1) rest = rest.slice(0, q);
  const defaultPort = scheme === "http" ? "80" : scheme === "https" ? "443" : null;

  let host;
  let port = "";
  let remainder;
  if (rest.startsWith("[")) {
    const end = rest.indexOf("]");
    host = rest.slice(1, end);
    remainder = rest.slice(end + 1);
    if (remainder.startsWith(":")) {
      const slash = remainder.indexOf("/");
      if (slash === -1) {
        port = remainder.slice(1);
        remainder = "";
      } else {
        port = remainder.slice(1, slash);
        remainder = remainder.slice(slash);
      }
    }
  } else {
    const slash = rest.indexOf("/");
    const hostport = slash === -1 ? rest : rest.slice(0, slash);
    remainder = slash === -1 ? "" : rest.slice(slash);
    const colon = hostport.lastIndexOf(":");
    if (colon !== -1) {
      host = hostport.slice(0, colon);
      port = hostport.slice(colon + 1);
    } else {
      host = hostport;
    }
  }

  let hostNorm;
  try {
    hostNorm = normalizeAsset(host);
    if (hostNorm.includes(":")) hostNorm = `[${hostNorm}]`;
  } catch {
    hostNorm = host.toLowerCase().replace(/\.$/, "");
  }
  if (port === defaultPort) port = "";
  let path = removeDotSegments(remainder);
  path = path.replace(/%[0-9a-fA-F]{2}/g, (c) => c.toUpperCase());
  const netloc = hostNorm + (port ? `:${port}` : "");
  return `${scheme}://${netloc}${path}`;
}

function vulnerabilityKey(v, title) {
  if (v.template_id) return v.template_id.trim().toLowerCase();
  if (Array.isArray(v.cve_ids) && v.cve_ids.length > 0) {
    return [...v.cve_ids].sort()[0];
  }
  if (v.cwe_id) return v.cwe_id.toUpperCase();
  return title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

for (const vec of vectors.vectors) {
  try {
    const vkey = vulnerabilityKey(vec.vulnerability, vec.vulnerability.title ?? "");
    if (vkey !== vec.expected_vulnerability_key) {
      fail(`vector ${vec.name}: vulnerability key ${vkey} != ${vec.expected_vulnerability_key}`);
      continue;
    }
    const canonical = ["v1", normalizeAsset(vec.asset), normalizeEndpoint(vec.endpoint), vkey].join("\n");
    if (canonical !== vec.expected_canonical) {
      fail(`vector ${vec.name}: canonical mismatch\n  got:      ${JSON.stringify(canonical)}\n  expected: ${JSON.stringify(vec.expected_canonical)}`);
      continue;
    }
    const fp = createHash("sha256").update(canonical, "utf8").digest("hex");
    if (fp !== vec.expected_fingerprint) {
      fail(`vector ${vec.name}: fingerprint ${fp} != ${vec.expected_fingerprint}`);
      continue;
    }
    ok(`fingerprint vector ${vec.name}`);
  } catch (err) {
    fail(`vector ${vec.name}: ${err.message}`);
  }
}

if (failures > 0) {
  console.error(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nAll schema fixture and fingerprint vector checks passed.");
