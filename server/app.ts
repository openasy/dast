import { timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, join, normalize } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { createGunzip } from "node:zlib";
import { AuthError, mergeOpenApi, sendProblem, type Auth, type Role } from "@openasy/auth";
import type { Agents } from "./agents.ts";
import { log } from "./log.ts";
import { countRequest, renderMetrics } from "./metrics.ts";
import type { ProductLink } from "./products.ts";
import type { Severity } from "./sarif.ts";
import { parseLimit, DastError, SEVERITIES, type FindingFilter, type ProblemCode, type Dast, type Status } from "./dast.ts";

export interface AppOptions {
  db: DatabaseSync;
  dast: Dast;
  /** dast-agent, its queue and the targets' schedules (ADR 0037). */
  agents: Agents;
  version: string;
  /** Sign-in, sessions, members and API tokens (ADR 0002, 0003). */
  auth: Auth;
  /** Token CI sends with SARIF. It can add scans and nothing else (ADR 0003). An API token with the editor role works too. */
  ingestToken?: string;
  /** For tests and local scripts: one shared token with the admin role. main.ts never sets it. */
  adminToken?: string;
  /** Built web UI; omit to run headless (ADR 0018). */
  webDir?: string;
  /** Built API reference (Swagger UI), served at /api/docs. */
  docsDir?: string;
  /** The OpenAPI description, served at /api/openapi.json with this release's version. */
  openapi?: Record<string, unknown>;
  /** false when /metrics is served on its own port instead (ADR 0026). */
  serveMetrics?: boolean;
  /** The install's OpenAsy products and their addresses, from OPENASY_PRODUCTS, for the product switcher. */
  products?: ProductLink[];
}

function metricsText(dast: Dast, version: string) {
  const s = dast.summary();
  return renderMetrics(version, {
    targets: s.targets,
    verified: s.verified,
    findings: dast.severityTotals(),
    suppressed: dast.suppressedCount(),
    failingChecks: s.failingChecks,
  });
}

/** Serves only /metrics, for a port that is not exposed with the rest (DAST_METRICS_PORT). */
export function createMetricsHandler(dast: Dast, version: string) {
  return (req: IncomingMessage, res: ServerResponse) => {
    if (new URL(req.url ?? "/", "http://localhost").pathname !== "/metrics") return problem(res, 404, "not-found");
    send(res, 200, metricsText(dast, version), "text/plain; version=0.0.4");
  };
}

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".json": "application/json",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "content-security-policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'",
};

/** Largest SARIF log accepted, after decompression. */
const SARIF_LIMIT = 64 * 1024 * 1024;

function send(res: ServerResponse, status: number, body: string | Buffer, type = "application/json", headers: Record<string, string> = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers, "content-type": type, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

const json = (res: ServerResponse, status: number, data: unknown, headers?: Record<string, string>) =>
  send(res, status, JSON.stringify(data), "application/json", headers);

const TITLES: Record<ProblemCode, string> = {
  "invalid-token": "Invalid token",
  "invalid-json": "Invalid JSON",
  "invalid-body": "Invalid request body",
  "invalid-sarif": "Invalid SARIF",
  "verification-failed": "Verification failed",
  "not-found": "Not found",
  conflict: "Conflict",
  forbidden: "Forbidden",
  "not-configured": "Not configured",
  "payload-too-large": "Payload too large",
  "internal-error": "Internal error",
};

/** RFC 9457 Problem Details (ADR 0024). `code` is the stable part clients match on. */
function problem(res: ServerResponse, status: number, code: ProblemCode, detail?: string) {
  const body = { type: `https://openasy.github.io/problems/${code}`, title: TITLES[code], status, code, ...(detail && { detail }) };
  send(res, status, JSON.stringify(body), "application/problem+json");
}

/** Serves a file from dir, or returns false when the path is outside it or missing. */
async function serveFile(res: ServerResponse, dir: string, relative: string): Promise<boolean> {
  const file = normalize(join(dir, relative));
  if (!file.startsWith(normalize(dir)) || !extname(file)) return false;
  try {
    send(res, 200, await readFile(file), TYPES[extname(file)] ?? "application/octet-stream");
    return true;
  } catch {
    return false;
  }
}

/** Reads the whole body, gunzipping it when sent with `Content-Encoding: gzip`, up to limit bytes. */
async function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  const encoding = req.headers["content-encoding"];
  if (encoding && encoding !== "gzip" && encoding !== "identity") throw new DastError(400, "invalid-body", "Content-Encoding must be gzip or absent.");
  const source = encoding === "gzip" ? req.pipe(createGunzip()) : req;
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of source as AsyncIterable<Buffer>) {
      size += chunk.length;
      if (size > limit) throw new DastError(413, "payload-too-large", `The body must be at most ${Math.round(limit / 1024 / 1024)} MiB.`);
      chunks.push(chunk);
    }
  } catch (err) {
    if (err instanceof DastError) throw err;
    throw new DastError(400, "invalid-body", "The gzip body could not be read.");
  }
  return Buffer.concat(chunks);
}

async function readJson(req: IncomingMessage, limit = 64 * 1024): Promise<Record<string, unknown>> {
  const raw = await readBody(req, limit).catch((err: unknown) => {
    if (err instanceof DastError && err.code === "payload-too-large")
      throw new DastError(400, "invalid-json", `The body must be JSON, at most ${Math.round(limit / 1024)} KiB.`);
    throw err;
  });
  try {
    const body = JSON.parse(raw.toString("utf8")) as unknown;
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("not an object");
    return body as Record<string, unknown>;
  } catch {
    throw new DastError(400, "invalid-json", "The body must be a JSON object.");
  }
}

function tokenMatches(header: string | undefined, expected: string | undefined): boolean {
  if (!expected || !header?.startsWith("Bearer ")) return false;
  const a = Buffer.from(header.slice(7));
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** The role a route needs (ADR 0003), "ingest" for scans sent from CI, or "agent" for an enrolled dast-agent. */
type Access = "none" | "ingest" | "agent" | Role;
interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  params: string[];
  body: () => Promise<Record<string, unknown>>;
  /** Who made the request, for the audit trail of a decision. */
  actor: () => string;
  /** On "agent" routes: the enrolled dast-agent that sent the request. */
  agent: string;
  /** Whether the caller has the admin role. */
  isAdmin: () => boolean;
}
interface Route {
  method: string;
  /** Path pattern; each `:name` matches one segment. */
  path: string;
  auth: Access;
  handle: (ctx: Ctx) => unknown;
}

function findingFilter(url: URL, targetId?: string): FindingFilter {
  const status = url.searchParams.get("status") ?? "open";
  if (status !== "open" && status !== "suppressed" && status !== "resolved")
    throw new DastError(422, "invalid-body", "status must be open, suppressed or resolved.");
  const severity = url.searchParams.get("severity")?.split(",").filter(Boolean) as Severity[] | undefined;
  if (severity?.some((s) => !SEVERITIES.includes(s)))
    throw new DastError(422, "invalid-body", `severity is a comma-separated list of ${SEVERITIES.join(", ")}.`);
  const q = url.searchParams.get("q")?.trim();
  if (q && q.length > 128) throw new DastError(422, "invalid-body", "q must be at most 128 characters.");
  return { status: status as Status, severity, q: q || undefined, targetId: targetId ?? url.searchParams.get("target") ?? undefined };
}

export function createApp({
  db,
  dast,
  agents,
  version,
  auth,
  adminToken,
  ingestToken,
  webDir,
  docsDir,
  openapi,
  serveMetrics = true,
  products = [],
}: AppOptions) {
  // The served description includes /api/v1/auth from @openasy/auth, so the API reference documents sign-in too.
  const spec = openapi && JSON.stringify({ ...mergeOpenApi(openapi), info: { ...(openapi.info as object), version } });
  const noContent = (res: ServerResponse) => {
    res.writeHead(204, SECURITY_HEADERS).end();
  };
  const cursor = (url: URL) => url.searchParams.get("cursor") ?? undefined;
  const limit = (url: URL) => parseLimit(url.searchParams.get("limit"));
  const page = <K extends string, T>(key: K, p: { items: T[]; nextCursor?: string }) =>
    ({ [key]: p.items, ...(p.nextCursor && { nextCursor: p.nextCursor }) }) as Record<K, T[]> & { nextCursor?: string };

  const routes: Route[] = [
    { method: "GET", path: "/api/v1/version", auth: "none", handle: () => ({ product: "dast", version }) },
    { method: "GET", path: "/api/v1/products", auth: "viewer", handle: () => ({ products }) },
    { method: "GET", path: "/api/v1/summary", auth: "viewer", handle: () => dast.summary() },

    // Reports in, from CI or from whoever runs the scanner. The answer says whether the check passes.
    {
      method: "POST",
      path: "/api/v1/scans",
      auth: "ingest",
      handle: async ({ req, res, url }) => {
        const scan = dast.ingest({ target: url.searchParams.get("target"), engine: url.searchParams.get("engine") }, await readBody(req, SARIF_LIMIT));
        json(res, 201, scan, { location: `/api/v1/scans/${scan.id}` });
      },
    },
    { method: "GET", path: "/api/v1/scans/:id", auth: "viewer", handle: ({ params }) => dast.scan(params[0]!) },

    // Targets.
    { method: "GET", path: "/api/v1/targets", auth: "viewer", handle: ({ url }) => page("targets", dast.listTargets(cursor(url), limit(url))) },
    { method: "POST", path: "/api/v1/targets", auth: "admin", handle: async ({ res, body }) => json(res, 201, dast.createTarget(await body())) },
    { method: "GET", path: "/api/v1/targets/:id", auth: "viewer", handle: ({ params }) => dast.target(params[0]!) },
    {
      method: "PATCH",
      path: "/api/v1/targets/:id",
      auth: "admin",
      handle: async ({ params, body }) => {
        const { schedule, scheduleProfile, ...rest } = await body();
        if (schedule !== undefined || scheduleProfile !== undefined) {
          dast.target(params[0]!);
          agents.setSchedule(params[0]!, { schedule, scheduleProfile });
          if (Object.keys(rest).length) dast.updateTarget(params[0]!, rest);
          return dast.target(params[0]!);
        }
        return dast.updateTarget(params[0]!, rest);
      },
    },
    { method: "DELETE", path: "/api/v1/targets/:id", auth: "admin", handle: ({ res, params }) => (dast.deleteTarget(params[0]!), noContent(res)) },
    {
      method: "POST",
      path: "/api/v1/targets/:id/verify",
      auth: "admin",
      handle: async ({ params, actor }) => {
        try {
          return await dast.verify(params[0]!);
        } catch (err) {
          // dast cannot reach a private address; an agent in that network reads the proof instead.
          if (err instanceof DastError && /private address/.test(err.message) && agents.queueVerify(params[0]!, actor()))
            throw new DastError(
              422,
              "verification-failed",
              `${err.message.replace(/^Could not read the proof: /, "").replace(/;.*$/, "")}: an agent reads the proof now, and the target is verified once it has. See Scans, queue.`,
            );
          throw err;
        }
      },
    },
    // Scans run by dast-agent: by hand here, or by the target's schedule.
    {
      method: "POST",
      path: "/api/v1/targets/:id/scan",
      auth: "editor",
      handle: async ({ res, params, body, actor, isAdmin }) => json(res, 201, agents.scanNow(params[0]!, await body(), actor(), isAdmin())),
    },
    {
      method: "GET",
      path: "/api/v1/jobs",
      auth: "viewer",
      handle: ({ url }) => ({ jobs: agents.listJobs({ targetId: url.searchParams.get("target") ?? undefined }) }),
    },
    { method: "GET", path: "/api/v1/agents", auth: "admin", handle: () => ({ agents: agents.listAgents() }) },
    { method: "POST", path: "/api/v1/agents", auth: "admin", handle: async ({ res, body }) => json(res, 201, agents.createAgent(await body())) },
    { method: "DELETE", path: "/api/v1/agents/:id", auth: "admin", handle: ({ res, params }) => (agents.deleteAgent(params[0]!), noContent(res)) },
    // dast-agent: enrol once with the token, then ask for work and send back what each engine found.
    { method: "POST", path: "/api/v1/agent/enroll", auth: "none", handle: async ({ body }) => agents.enroll(await body()) },
    { method: "POST", path: "/api/v1/agent/work", auth: "agent", handle: async ({ agent, body }) => agents.work(agent, (await body()).version) },
    {
      method: "POST",
      path: "/api/v1/agent/jobs/:id/sarif",
      auth: "agent",
      handle: async ({ req, res, url, agent, params }) =>
        json(res, 201, agents.report(agent, params[0]!, url.searchParams.get("engine"), await readBody(req, SARIF_LIMIT))),
    },
    {
      method: "POST",
      path: "/api/v1/agent/jobs/:id/done",
      auth: "agent",
      handle: ({ res, agent, params }) => (agents.finish(agent, params[0]!), noContent(res)),
    },
    {
      method: "POST",
      path: "/api/v1/agent/jobs/:id/failed",
      auth: "agent",
      handle: async ({ res, agent, params, body }) => (agents.fail(agent, params[0]!, await body()), noContent(res)),
    },
    {
      method: "POST",
      path: "/api/v1/agent/jobs/:id/proof",
      auth: "agent",
      handle: async ({ res, agent, params, body }) => (agents.proof(agent, params[0]!, await body()), noContent(res)),
    },
    {
      method: "GET",
      path: "/api/v1/targets/:id/scans",
      auth: "viewer",
      handle: ({ url, params }) => page("scans", dast.scans(params[0]!, cursor(url), limit(url))),
    },
    {
      method: "GET",
      path: "/api/v1/targets/:id/findings",
      auth: "viewer",
      handle: ({ url, params }) => page("findings", dast.findings(findingFilter(url, params[0]!), cursor(url), limit(url))),
    },

    // Findings of every target.
    {
      method: "GET",
      path: "/api/v1/findings",
      auth: "viewer",
      handle: ({ url }) => page("findings", dast.findings(findingFilter(url), cursor(url), limit(url))),
    },
    {
      // Triage stays with the finding across scans (ADR 0037).
      method: "PUT",
      path: "/api/v1/targets/:id/findings/:fingerprint",
      auth: "editor",
      handle: async ({ params, body, actor }) => dast.triage(params[0]!, params[1]!, await body(), actor()),
    },
  ];

  const compiled = routes.map((r) => ({ ...r, re: new RegExp(`^${r.path.replace(/:[a-z]+/g, "([^/]+)")}$`) }));

  /** Returns who is calling, or null for the ingest token. */
  function authorize(req: IncomingMessage, access: Access): string | null {
    if (access === "none") return null;
    if (access === "agent") {
      const agent = agents.agentBySecret(req.headers.authorization);
      if (!agent) throw new DastError(401, "invalid-token", "Send the agent's own secret, from enrolment, as a bearer token.");
      return agent;
    }
    if (access === "ingest" && tokenMatches(req.headers.authorization, ingestToken)) return null;
    if (tokenMatches(req.headers.authorization, adminToken)) return "admin token";
    if (access === "ingest") {
      // An API token or a session with the editor role can send scans too, for CI set up from Settings.
      if (!ingestToken && !req.headers.authorization?.startsWith("Bearer oa_"))
        throw new DastError(503, "not-configured", "Set DAST_INGEST_TOKEN on dast, or send an API token with the editor role.");
      if (!req.headers.authorization?.startsWith("Bearer oa_"))
        throw new DastError(401, "invalid-token", "Send DAST_INGEST_TOKEN or an API token as a bearer token.");
    }
    const p = auth.authorize(req, access === "ingest" ? "editor" : access);
    return p.kind === "session" ? p.user.name : `API token ${p.name}`;
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<string> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    if (path === "/healthz") return (json(res, 200, { status: "ok" }), "/healthz");

    if (path === "/readyz") {
      // Ready to take scans as long as the database answers.
      try {
        db.prepare("SELECT 1").get();
        json(res, 200, { status: "ready" });
      } catch {
        json(res, 503, { status: "database unavailable" });
      }
      return "/readyz";
    }

    if (path === "/metrics") {
      // Not even the web UI's fallback answers here when metrics have their own port.
      if (serveMetrics) send(res, 200, metricsText(dast, version), "text/plain; version=0.0.4");
      else problem(res, 404, "not-found");
      return "/metrics";
    }

    if (path === "/api/openapi.json" && spec) return (send(res, 200, spec), "/api/openapi.json");

    if (docsDir && (path === "/api/docs" || path.startsWith("/api/docs/"))) {
      if (path === "/api/docs") {
        res.writeHead(301, { ...SECURITY_HEADERS, location: "/api/docs/" }).end();
        return "/api/docs";
      }
      const relative = path.slice("/api/docs/".length) || "index.html";
      if (!(await serveFile(res, docsDir, relative))) problem(res, 404, "not-found");
      return "/api/docs";
    }

    if (await auth.handle(req, res)) return auth.routeName(req) ?? "/api/v1/auth/*";

    for (const r of compiled) {
      const m = path.match(r.re);
      if (!m || r.method !== req.method) continue;
      try {
        const who = authorize(req, r.auth);
        const params = m.slice(1).map(decodeURIComponent);
        const isAdmin = () => {
          if (who === "admin token") return true;
          try {
            auth.authorize(req, "admin");
            return true;
          } catch {
            return false;
          }
        };
        const result = await r.handle({ req, res, url, params, body: () => readJson(req), actor: () => who ?? "unknown", agent: who ?? "", isAdmin });
        if (!res.headersSent && result !== undefined) json(res, 200, result);
      } catch (err) {
        if (err instanceof AuthError) {
          sendProblem(res, err);
          if (!req.complete) req.resume();
          return r.path;
        }
        if (!(err instanceof DastError)) throw err;
        problem(res, err.status, err.code, err.message);
        // Unread request bodies would otherwise hold the connection.
        if (!req.complete) req.resume();
      }
      return r.path;
    }

    if (path.startsWith("/api/")) return (problem(res, 404, "not-found"), "/api/*");

    if (webDir && (req.method === "GET" || req.method === "HEAD")) {
      // Unknown paths fall back to the single-page app.
      if (!(await serveFile(res, webDir, path === "/" ? "index.html" : path))) send(res, 200, await readFile(join(webDir, "index.html")), TYPES[".html"]);
      return "/web";
    }

    problem(res, 404, "not-found");
    return "unmatched";
  }

  return async (req: IncomingMessage, res: ServerResponse) => {
    const started = performance.now();
    let routeName = "error";
    try {
      routeName = await route(req, res);
    } catch (err) {
      log("error", "request failed", { error: String(err), path: req.url });
      if (!res.headersSent) problem(res, 500, "internal-error");
    }
    countRequest(req.method ?? "GET", routeName, res.statusCode);
    if (routeName !== "/healthz" && routeName !== "/metrics") {
      log("info", "request", { method: req.method, path: url(req), status: res.statusCode, ms: Math.round(performance.now() - started) });
    }
  };
}

/** The path without the query string, which may name hosts and images. */
const url = (req: IncomingMessage) => (req.url ?? "/").split("?")[0];
