import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ADMIN_TOKEN, INGEST_TOKEN, sarif, startApp } from "./test-app.ts";

// Contract tests (ADR 0024): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "dast-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
const covered = new Set<string>();

beforeAll(async () => {
  app = await startApp({ version, openapi: spec, docsDir });
  base = app.base;
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared
    ? `openapi#/components/responses/${shared}`
    : `openapi#/paths/${path.replaceAll("/", "~1")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body };
}

const auth = (token: string, body?: string, type = "application/json") => ({
  headers: { authorization: `Bearer ${token}`, "content-type": type },
  ...(body !== undefined && { body }),
});
const admin = (body?: unknown) => auth(ADMIN_TOKEN, body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body));
const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

describe("openapi.json", () => {
  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    // dast's own operations, then sign-in from @openasy/auth (tested against its description in that package).
    expect(Object.keys(served.paths).filter((p) => !p.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  let target = "";
  let proof = "";
  let fingerprint = "";
  const shop = "https://shop.example.com";
  const report = (...urls: string[]) => sarif("ZAP", ...urls.map((u) => ({ rule: `rule-${u}`, level: "error" as const, url: `${shop}/${u}` })));
  const send = (body = report("a")) => auth(INGEST_TOKEN, body);
  const path = (query: string) => `/api/v1/scans?${query}`;

  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/products", {});
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
  });

  it("targets: read and verify", async () => {
    // Targets come from the endpoints file only (ADR 0052), with the login's secret in the environment.
    const created = await app.setTarget(
      "shop-staging",
      shop,
      { schedule: "weekly", login: { kind: "header", header: "Authorization", secret: "DAST_SHOP_TOKEN" } },
      { DAST_SHOP_TOKEN: "Bearer s3cret" },
    );
    target = created.id;
    proof = created.verification.content;
    await call("GET", "/api/v1/targets", admin());
    await call("GET", "/api/v1/targets", admin(), "/api/v1/targets?limit=1");
    await call("GET", "/api/v1/targets", admin(), "/api/v1/targets?limit=0");
    await call("GET", "/api/v1/targets", {});
    await call("GET", "/api/v1/targets/{id}", admin(), `/api/v1/targets/${target}`);
    await call("GET", "/api/v1/targets/{id}", admin(), "/api/v1/targets/missing");
    await call("POST", "/api/v1/targets/{id}/verify", admin(), `/api/v1/targets/${target}/verify`);
    app.site.served.set(shop, proof);
    expect(((await call("POST", "/api/v1/targets/{id}/verify", admin(), `/api/v1/targets/${target}/verify`)).body as { verified: boolean }).verified).toBe(
      true,
    );
    await call("POST", "/api/v1/targets/{id}/verify", admin(), "/api/v1/targets/missing/verify");
    await call("POST", "/api/v1/targets/{id}/verify", { method: "POST" }, `/api/v1/targets/${target}/verify`);
  });

  it("agents, the queue and schedules", async () => {
    await call("POST", "/api/v1/targets/{id}/scan", admin({ profile: "standard" }), `/api/v1/targets/${target}/scan`);
    await call("POST", "/api/v1/targets/{id}/scan", admin({ profile: "max" }), `/api/v1/targets/${target}/scan`);
    await call("POST", "/api/v1/targets/{id}/scan", admin({}), "/api/v1/targets/missing/scan");
    await call("POST", "/api/v1/targets/{id}/scan", { method: "POST" }, `/api/v1/targets/${target}/scan`);
    await call("GET", "/api/v1/targets/{id}/auth-profiles", admin(), `/api/v1/targets/${target}/auth-profiles`);
    await call("GET", "/api/v1/targets/{id}/auth-profiles", admin(), "/api/v1/targets/missing/auth-profiles");
    await call("GET", "/api/v1/targets/{id}/auth-profiles", {}, `/api/v1/targets/${target}/auth-profiles`);
    const login = (
      (await call("GET", "/api/v1/targets/{id}/auth-profiles", admin(), `/api/v1/targets/${target}/auth-profiles`)).body as {
        authProfiles: Array<{ id: string }>;
      }
    ).authProfiles[0]!;
    await call("POST", "/api/v1/targets/{id}/scan", admin({ profile: "standard", authProfile: login.id }), `/api/v1/targets/${target}/scan`);
    await call("GET", "/api/v1/jobs", admin());
    await call("GET", "/api/v1/jobs", admin(), `/api/v1/jobs?target=${target}`);
    await call("GET", "/api/v1/jobs", {});
    const made = (await call("POST", "/api/v1/agents", admin({ name: "dc1" }))).body as { enrollToken: string; agent: { id: string } };
    await call("POST", "/api/v1/agents", admin({ name: "dc1" }));
    await call("POST", "/api/v1/agents", admin({ name: "Not A Name" }));
    await call("POST", "/api/v1/agents", {});
    await call("GET", "/api/v1/agents", admin());
    await call("GET", "/api/v1/agents", {});
    await call("POST", "/api/v1/agent/enroll", { method: "POST", body: JSON.stringify({ token: "ode_nope" }) });
    const { secret } = (await call("POST", "/api/v1/agent/enroll", { method: "POST", body: JSON.stringify({ token: made.enrollToken, version }) })).body as {
      secret: string;
    };
    const agent = (body: unknown, token = secret) => ({
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
    await call("POST", "/api/v1/agent/work", agent({}, "oda_nope"));
    const job = ((await call("POST", "/api/v1/agent/work", agent({ version }))).body as { jobs: Array<{ id: string }> }).jobs[0]!;
    const at = (what: string) => `/api/v1/agent/jobs/${job.id}/${what}`;
    await call("POST", "/api/v1/agent/jobs/{id}/sarif", agent(report("b")), `${at("sarif")}?engine=zap`);
    await call("POST", "/api/v1/agent/jobs/{id}/sarif", agent(report("b")), `${at("sarif")}?engine=burp`);
    await call("POST", "/api/v1/agent/jobs/{id}/proof", agent({ content: "x" }), at("proof"));
    await call("POST", "/api/v1/agent/jobs/{id}/done", agent({}), at("done"));
    await call("POST", "/api/v1/agent/jobs/{id}/done", agent({}), at("done"));
    await call("POST", "/api/v1/agent/jobs/{id}/failed", agent({ error: "late" }), at("failed"));
    await call("POST", "/api/v1/agent/jobs/{id}/sarif", agent(report("b")), `${at("sarif")}?engine=zap`);
    await call("DELETE", "/api/v1/targets/{id}/auth-profiles/{profile}", admin(), `/api/v1/targets/${target}/auth-profiles/${login.id}`);
    // A login of a target added here before the file can still be removed here.
    const at2 = new Date().toISOString();
    app.db
      .prepare(
        "INSERT INTO targets (id, name, url, production, fail_on, verify_token, created_at) VALUES ('ui-t', 'legacy', 'https://legacy.example.com', 0, 'high', 'x', ?)",
      )
      .run(at2);
    app.db
      .prepare(
        "INSERT INTO auth_profiles (id, target_id, name, kind, header_name, secret, created_at) VALUES ('ui-login', 'ui-t', 'api', 'header', 'X', 'sealed', ?)",
      )
      .run(at2);
    await call("DELETE", "/api/v1/targets/{id}/auth-profiles/{profile}", admin(), "/api/v1/targets/ui-t/auth-profiles/ui-login");
    await call("DELETE", "/api/v1/targets/{id}/auth-profiles/{profile}", admin(), "/api/v1/targets/ui-t/auth-profiles/ui-login");
    await call("DELETE", "/api/v1/agents/{id}", admin(), `/api/v1/agents/${made.agent.id}`);
    await call("DELETE", "/api/v1/agents/{id}", admin(), "/api/v1/agents/missing");
  });

  it("reports and every refusal", async () => {
    await call("POST", "/api/v1/scans", send(), path("target=shop-staging"));
    const second = (await call("POST", "/api/v1/scans", send(report("a", "b")), path("target=shop-staging&engine=zap"))).body as {
      id: string;
      findings: Array<{ fingerprint: string }>;
    };
    fingerprint = second.findings[0]!.fingerprint;
    await call("POST", "/api/v1/scans", send(), path("target=missing"));
    await call("POST", "/api/v1/scans", send("{nope"), path("target=shop-staging"));
    await call("POST", "/api/v1/scans", send(JSON.stringify({ hello: 1 })), path("target=shop-staging"));
    await call("POST", "/api/v1/scans", send(), path("engine=zap"));
    await call("POST", "/api/v1/scans", auth("wrong", report("a")), path("target=shop-staging"));
    await call("POST", "/api/v1/scans", { method: "POST" }, path("target=shop-staging"));
    await call("GET", "/api/v1/scans/{id}", admin(), `/api/v1/scans/${second.id}`);
    await call("GET", "/api/v1/scans/{id}", admin(), "/api/v1/scans/missing");
    await call("GET", "/api/v1/scans/{id}", {}, `/api/v1/scans/${second.id}`);
    await call("GET", "/api/v1/targets/{id}/scans", admin(), `/api/v1/targets/${target}/scans`);
    await call("GET", "/api/v1/targets/{id}/scans", admin(), "/api/v1/targets/missing/scans");
    await call("GET", "/api/v1/targets/{id}/scans", admin(), `/api/v1/targets/${target}/scans?cursor=junk`);
    await call("GET", "/api/v1/targets/{id}/scans", {}, `/api/v1/targets/${target}/scans`);
  });

  it("findings and triage", async () => {
    const { body } = await call("GET", "/api/v1/findings", admin());
    expect((body as { findings: unknown[] }).findings).toHaveLength(2);
    await call("GET", "/api/v1/findings", admin(), "/api/v1/findings?status=resolved&severity=high,critical&q=rule&limit=1");
    await call("GET", "/api/v1/findings", admin(), `/api/v1/findings?target=${target}`);
    await call("GET", "/api/v1/findings", admin(), "/api/v1/findings?severity=urgent");
    await call("GET", "/api/v1/findings", {});
    await call("GET", "/api/v1/targets/{id}/findings", admin(), `/api/v1/targets/${target}/findings`);
    await call("GET", "/api/v1/targets/{id}/findings", admin(), `/api/v1/targets/${target}/findings?status=suppressed`);
    await call("GET", "/api/v1/targets/{id}/findings", admin(), "/api/v1/targets/missing/findings");
    await call("GET", "/api/v1/targets/{id}/findings", {}, `/api/v1/targets/${target}/findings`);

    const put = (fp: string, state: unknown) =>
      call("PUT", "/api/v1/targets/{id}/findings/{fingerprint}", admin(state), `/api/v1/targets/${target}/findings/${fp}`);
    await put(fingerprint, { state: "false-positive", reason: "A test page" });
    await put(fingerprint, { state: "accepted", reason: "Behind the VPN", expiresAt: inDays(30) });
    await put(fingerprint, { state: "accepted", reason: "No end" });
    await put(fingerprint, "nope");
    await put("missing", { state: "open" });
    await call("GET", "/api/v1/targets/{id}/findings", admin(), `/api/v1/targets/${target}/findings?status=suppressed`);
    await put(fingerprint, { state: "open" });
    await call("PUT", "/api/v1/targets/{id}/findings/{fingerprint}", { method: "PUT" }, `/api/v1/targets/${target}/findings/${fingerprint}`);
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/summary", {});
    await call("GET", "/api/v1/overview", admin());
    await call("GET", "/api/v1/overview", {});
    await call("GET", "/api/v1/findings", admin(), "/api/v1/findings?rule=10038");
  });

  it("deletes a target", async () => {
    await call("DELETE", "/api/v1/targets/{id}", admin(), `/api/v1/targets/${target}`);
    await call("DELETE", "/api/v1/targets/{id}", admin(), "/api/v1/targets/ui-t");
    await call("DELETE", "/api/v1/targets/{id}", admin(), "/api/v1/targets/ui-t");
    await call("DELETE", "/api/v1/targets/{id}", { method: "DELETE" }, "/api/v1/targets/x");
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
