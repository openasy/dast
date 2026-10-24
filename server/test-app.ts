// Starts the app on a random port for tests.
import { createServer, type RequestListener, type Server } from "node:http";
import { createAuth } from "@openasy/auth";
import type { AddressInfo } from "node:net";
import { createApp, type AppOptions } from "./app.ts";
import { openDb } from "./db.ts";
import { createAgents } from "./agents.ts";
import { createKeyring } from "./kek.ts";
import { createDast } from "./dast.ts";
import type { Verifier } from "./verify.ts";

export const INGEST_TOKEN = "test-ingest-token";
export const ADMIN_TOKEN = "test-admin-token";

export interface TestResult {
  rule: string;
  /** SARIF level. */
  level?: "error" | "warning" | "note";
  score?: number;
  url: string;
  param?: string;
  evidence?: string;
  message?: string;
}

/** A SARIF 2.1.0 log such as ZAP or Nuclei write. */
export function sarif(tool: string, ...results: TestResult[]) {
  return JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: tool, rules: [] } },
        results: results.map((r) => ({
          ruleId: r.rule,
          level: r.level ?? "warning",
          message: { text: r.message ?? `${r.rule} found` },
          properties: {
            ...(r.score !== undefined && { "security-severity": String(r.score) }),
            ...(r.param && { param: r.param }),
            ...(r.evidence && { evidence: r.evidence }),
          },
          locations: [{ physicalLocation: { artifactLocation: { uri: r.url } } }],
        })),
      },
    ],
  });
}

/** Answers the proof request of an origin with what the test says the site serves there. */
export function fakeSite() {
  const served = new Map<string, string>();
  const verifier: Verifier = async (origin) => {
    const content = served.get(origin);
    if (content === undefined) throw new Error(`${origin} is not reachable.`);
    return content;
  };
  return { served, verifier };
}

export async function startApp(opts: Partial<AppOptions> & { version: string; site?: ReturnType<typeof fakeSite> }) {
  const db = openDb(":memory:");
  const site = opts.site ?? fakeSite();
  const dast = createDast(db, { verifier: site.verifier });
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "dast", productName: "OpenAsy DAST", origin: base });
  const { site: _site, ...rest } = opts;
  const agents = createAgents(db, dast, { keyring: createKeyring(Buffer.alloc(32, 9)) });
  handler = createApp({ db, dast, agents, auth, ingestToken: INGEST_TOKEN, adminToken: ADMIN_TOKEN, ...rest });
  const as =
    (token: string) =>
    (path: string, init: RequestInit = {}) =>
      fetch(base + path, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers } });
  const admin = as(ADMIN_TOKEN);
  const ingest = as(INGEST_TOKEN);
  /** Sends a report the way CI does. */
  const scan = (query: Record<string, string>, body: string | Buffer) => ingest(`/api/v1/scans?${new URLSearchParams(query)}`, { method: "POST", body });
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { db, dast, agents, auth, base, admin, ingest, scan, site, close };
}
