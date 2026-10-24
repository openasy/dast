import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createAuth, oidcFromEnv, readSecretsKey } from "@openasy/auth";
import { createApp, createMetricsHandler } from "./app.ts";
import { openDb } from "./db.ts";
import { log } from "./log.ts";
import { parseProducts } from "./products.ts";
import { createAgents } from "./agents.ts";
import { createDast } from "./dast.ts";
import { createKeyring } from "./kek.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const port = Number(process.env.PORT ?? 8080);
const dbPath = process.env.DAST_DB ?? "/data/dast.db";
const retentionDays = Number(process.env.DAST_RETENTION_DAYS ?? 365);
const webDir = new URL("../dist/web", import.meta.url).pathname;
const docsDir = new URL("../dist/docs", import.meta.url).pathname;
const openapi = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Record<string, unknown>;
const headless = process.env.DAST_HEADLESS === "true";
// Set it to keep /metrics off the port that is published or behind an ingress (ADR 0026).
const metricsPort = process.env.DAST_METRICS_PORT ? Number(process.env.DAST_METRICS_PORT) : undefined;

if (!Number.isFinite(retentionDays) || retentionDays < 1) throw new Error("DAST_RETENTION_DAYS must be a number of days, 1 or more");

const db = openDb(dbPath);
// The address people open dast at, behind the TLS proxy (ADR 0026). Cookies, passkeys and OIDC redirects use it.
const publicUrl = (process.env.DAST_PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/$/, "");
const secretsKeyFile = process.env.DAST_SECRETS_KEY_FILE ?? "/run/secrets/openasy-kek";
const secretsKey = readSecretsKey(secretsKeyFile);
const auth = createAuth({
  db,
  product: "dast",
  productName: "OpenAsy DAST",
  origin: publicUrl,
  // Locally the same dast is often opened as 127.0.0.1 too.
  trustedOrigins: publicUrl.startsWith("http://localhost:") ? [publicUrl.replace("localhost", "127.0.0.1")] : [],
  passwords: process.env.DAST_PASSWORD_SIGN_IN !== "false",
  oidc: oidcFromEnv(process.env, "DAST_"),
  secretsKey,
  // Audit log (ADR 0013): every sign-in, failure and change to members and tokens.
  onEvent: (event) => log(event.type === "sign-in-failed" ? "warn" : "info", "auth", { event }),
});
const dast = createDast(db, { retentionDays });
const agents = createAgents(db, dast, { keyring: secretsKey ? createKeyring(secretsKey) : undefined, log });
const products = parseProducts(process.env.OPENASY_PRODUCTS);
if (products.invalid.length) log("warn", "OPENASY_PRODUCTS: left out entries that are not id=https://address", { entries: products.invalid });
const server = createServer(
  createApp({
    db,
    dast,
    agents,
    version,
    auth,
    ingestToken: process.env.DAST_INGEST_TOKEN,
    webDir: !headless && existsSync(webDir) ? webDir : undefined,
    docsDir: existsSync(docsDir) ? docsDir : undefined,
    openapi,
    serveMetrics: metricsPort === undefined,
    products: products.products,
  }),
);
const metricsServer = metricsPort !== undefined ? createServer(createMetricsHandler(dast, version)) : undefined;
metricsServer?.listen(metricsPort, () => log("info", "metrics on their own port", { port: metricsPort }));

server.listen(port, () => log("info", "dast started", { version, port, db: dbPath, headless, retentionDays }));
if (!process.env.DAST_INGEST_TOKEN)
  log("warn", "DAST_INGEST_TOKEN is not set; CI needs an API token with the editor role (Settings, API tokens) to send scans");
if (!publicUrl.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(publicUrl)) {
  log("warn", "DAST_PUBLIC_URL is not https: browsers will not keep secure cookies or allow passkeys. Put dast behind TLS (ADR 0026)", { url: publicUrl });
}
if (auth.secretsInClear)
  log("warn", "no secrets key: TOTP secrets are stored unencrypted. Mount a 32-byte key (openssl rand -hex 32)", { file: secretsKeyFile });
const setup = auth.setupLink();
// No default password (ADR 0013): the first person to open this link becomes the owner.
if (setup) log("info", "no owner yet: open this link once to create the owner account", { url: setup });

dast.purge();
// Scheduled scans are queued within a minute of their time (ADR 0037).
const timers: NodeJS.Timeout[] = [
  setInterval(() => auth.purge(), 5 * 60_000),
  setInterval(() => dast.purge(), 24 * 3_600_000),
  setInterval(() => agents.tick(), 60_000),
];

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  for (const t of timers) clearInterval(t);
  metricsServer?.close();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
