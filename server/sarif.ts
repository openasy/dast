import { createHash } from "node:crypto";

export type Severity = "critical" | "high" | "medium" | "low";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export interface Finding {
  /** Stable across scans: the rule, the page without its query string, and the parameter. */
  fingerprint: string;
  ruleId: string;
  severity: Severity;
  /** The page, without query string or fragment. */
  url: string;
  param: string | null;
  message: string;
  /** What the engine saw or sent, masked before it is stored. */
  evidence: string | null;
}

export class SarifError extends Error {}

/** Most results one report may hold. */
export const MAX_RESULTS = 20_000;

type Obj = Record<string, any>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const text = (v: unknown, max: number) => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : null);

function fromScore(score: unknown): Severity | null {
  const n = typeof score === "string" ? Number(score) : score;
  if (typeof n !== "number" || !Number.isFinite(n) || n <= 0) return null;
  return n >= 9 ? "critical" : n >= 7 ? "high" : n >= 4 ? "medium" : "low";
}

const fromLevel = (level: unknown): Severity => (level === "error" ? "high" : level === "note" ? "low" : "medium");

/** Passwords, tokens and keys in what an engine saw are replaced before anything is stored (ADR 0037). */
export function mask(value: string): string {
  return value
    .replace(/((?:authorization|cookie|set-cookie|x-api-key|x-auth-token)\s*:\s*)[^\r\n]+/gi, "$1***")
    .replace(/((?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token|session(?:id)?)["']?\s*[=:]\s*["']?)[^\s&"',;]+/gi, "$1***")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g, "Bearer ***");
}

/** A page as the target knows it: no credentials, query string or fragment. Null for anything that is not http(s). */
export function pageOf(uri: string): URL | null {
  const url = URL.parse(uri);
  if (!url || (url.protocol !== "http:" && url.protocol !== "https:")) return null;
  url.username = "";
  url.password = "";
  url.search = "";
  url.hash = "";
  return url;
}

/** Reads the results of a SARIF 2.1.0 log from ZAP, Nuclei or another scanner of running applications. */
export function parseSarif(body: unknown): { tool: string; findings: Array<Finding & { page: URL }>; skipped: number } {
  if (!isObj(body) || !Array.isArray(body.runs))
    throw new SarifError("Send a SARIF 2.1.0 log: a JSON object with a runs array, for example from `nuclei -se results.sarif`.");
  if (typeof body.version === "string" && !body.version.startsWith("2.1")) throw new SarifError(`SARIF ${body.version} is not supported; send version 2.1.0.`);
  const tools: string[] = [];
  const found: Array<Omit<Finding, "fingerprint"> & { page: URL }> = [];
  let skipped = 0;
  for (const run of body.runs) {
    if (!isObj(run)) continue;
    const driver = isObj(run.tool) && isObj(run.tool.driver) ? run.tool.driver : {};
    const name = text(driver.name, 64);
    if (name && !tools.includes(name)) tools.push(name);
    const rules = new Map<string, Obj>();
    if (Array.isArray(driver.rules)) for (const r of driver.rules) if (isObj(r) && typeof r.id === "string") rules.set(r.id, r);
    for (const result of Array.isArray(run.results) ? run.results : []) {
      if (!isObj(result) || (Array.isArray(result.suppressions) && result.suppressions.length > 0)) continue;
      if (found.length >= MAX_RESULTS) throw new SarifError(`A report may hold at most ${MAX_RESULTS} results.`);
      const ruleId = text(result.ruleId ?? (isObj(result.rule) ? result.rule.id : undefined), 256) ?? "unknown";
      const rule = rules.get(ruleId);
      const location =
        Array.isArray(result.locations) && isObj(result.locations[0]) && isObj(result.locations[0].physicalLocation)
          ? result.locations[0].physicalLocation
          : {};
      const uri = text(isObj(location.artifactLocation) ? location.artifactLocation.uri : undefined, 2048);
      const page = uri ? pageOf(uri) : null;
      if (!page) {
        skipped++; // a finding without a web address cannot be followed from one scan to the next
        continue;
      }
      const props = isObj(result.properties) ? result.properties : {};
      const region = isObj(location.region) ? location.region : {};
      const evidence = text(props.evidence ?? props.attack ?? (isObj(region.snippet) ? region.snippet.text : undefined), 2000);
      found.push({
        ruleId,
        severity:
          fromScore(props["security-severity"]) ??
          fromScore(isObj(rule?.properties) ? rule!.properties["security-severity"] : undefined) ??
          fromLevel(result.level ?? (isObj(rule?.defaultConfiguration) ? rule!.defaultConfiguration.level : undefined)),
        url: page.origin + page.pathname,
        page,
        param: text(props.param ?? props.parameter, 128),
        message:
          text(isObj(result.message) ? (result.message.text ?? result.message.markdown) : undefined, 1000) ??
          text(isObj(rule?.shortDescription) ? rule!.shortDescription.text : undefined, 1000) ??
          ruleId,
        evidence: evidence ? mask(evidence) : null,
      });
    }
  }
  // A rule that fires twice on one page and parameter is still one finding.
  const seen = new Set<string>();
  const findings: Array<Finding & { page: URL }> = [];
  for (const f of found) {
    const fingerprint = createHash("sha256")
      .update(`${f.ruleId}\n${f.url}\n${f.param ?? ""}`)
      .digest("hex")
      .slice(0, 32);
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    findings.push({ ...f, fingerprint });
  }
  return { tool: tools.join(", ") || "unknown", findings, skipped };
}
