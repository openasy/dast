import { gzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { sarif, startApp, type TestResult } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;
beforeAll(async () => {
  app = await startApp({ version: "0.1.0" });
});
afterAll(() => app.close());

const shop = "https://shop.example.com";
const sqli: TestResult = { rule: "40018", level: "error", url: `${shop}/search?q=1`, param: "q", evidence: "' OR 1=1 --", message: "SQL injection" };
const xss: TestResult = { rule: "40012", score: 8, url: `${shop}/profile`, param: "name", message: "Reflected XSS" };
const headers: TestResult = { rule: "10038", level: "note", url: shop, message: "Content Security Policy header not set" };
const exposed: TestResult = { rule: "git-config", score: 5, url: `${shop}/.git/config`, message: "Exposed git configuration" };

const json = async (res: Response) => (await res.json()) as any;
const zap = (...r: TestResult[]) => app.scan({ target: "shop-staging" }, sarif("ZAP", ...r));
const nuclei = (...r: TestResult[]) => app.scan({ target: "shop-staging" }, sarif("Nuclei", ...r));
const post = (path: string, body: unknown) => app.admin(path, { method: "POST", body: JSON.stringify(body) });

describe("targets", () => {
  it("creates a target, with the proof the owner must serve", async () => {
    const res = await post("/api/v1/targets", { name: "shop-staging", url: `${shop}/` });
    expect(res.status).toBe(201);
    expect(await json(res)).toMatchObject({
      name: "shop-staging",
      url: shop,
      production: false,
      failOn: "high",
      verified: false,
      verification: { method: "file", url: `${shop}/.well-known/openasy-dast`, content: expect.stringMatching(/^openasy-dast-[0-9a-f]{32}$/) },
    });
  });

  it("refuses duplicates and things that are not addresses", async () => {
    expect((await post("/api/v1/targets", { name: "shop-staging", url: "https://other.example.com" })).status).toBe(409);
    expect((await post("/api/v1/targets", { name: "other", url: shop })).status).toBe(409);
    expect((await post("/api/v1/targets", { name: "x", url: "ftp://shop.example.com" })).status).toBe(422);
    expect((await post("/api/v1/targets", { name: "x", url: "not a url" })).status).toBe(422);
    expect((await post("/api/v1/targets", { name: "bad name", url: "https://a.example.com" })).status).toBe(422);
    expect((await post("/api/v1/targets", { name: "x", url: "https://a.example.com", production: "yes" })).status).toBe(422);
    expect((await post("/api/v1/targets", { name: "x", url: "https://a.example.com", extra: 1 })).status).toBe(422);
    expect((await post("/api/v1/targets", { name: "x", url: "https://a.example.com", failOn: "urgent" })).status).toBe(422);
  });

  it("is verified only when the site serves the content", async () => {
    const [target] = (await json(await app.admin("/api/v1/targets"))).targets;
    const verify = () => app.admin(`/api/v1/targets/${target.id}/verify`, { method: "POST" });
    expect(await json(await verify())).toMatchObject({ code: "verification-failed", detail: expect.stringContaining("not reachable") });
    app.site.served.set(shop, "something else");
    expect(await json(await verify())).toMatchObject({ code: "verification-failed", detail: expect.stringContaining("does not hold") });
    app.site.served.set(shop, `${target.verification.content}\n`);
    const done = await json(await verify());
    expect(done).toMatchObject({ verified: true, verification: null, verifiedAt: expect.any(String) });
    // Asking again changes nothing, even when the site stops serving the file.
    app.site.served.delete(shop);
    expect(await json(await verify())).toMatchObject({ verified: true, verifiedAt: done.verifiedAt });
    expect((await app.admin("/api/v1/targets/missing/verify", { method: "POST" })).status).toBe(404);
  });
});

describe("reports", () => {
  it("adopts the first report of an engine, even when it holds high findings", async () => {
    const scan = await json(await zap(sqli, xss, headers));
    expect(scan).toMatchObject({ engine: "zap", tool: "ZAP", total: 3, new: 3, blocking: 0, passed: true, resolved: 0, ignored: 0, target: { name: "shop-staging" } });
    expect((await json(await app.admin("/api/v1/targets")).then((r: any) => r.targets[0])).open).toEqual({ critical: 0, high: 2, medium: 0, low: 1 });
  });

  it("fails a later report for new findings at or above failOn", async () => {
    // The same findings on other query strings are not new; one high and one medium are.
    const scan = await json(await zap({ ...sqli, url: `${shop}/search?q=2` }, xss, headers, { rule: "90020", level: "error", url: `${shop}/api/export`, message: "Remote OS command injection" }, { rule: "10020", score: 5, url: `${shop}/` }));
    expect(scan).toMatchObject({ total: 5, new: 2, blocking: 1, passed: false, failOn: "high" });
    expect(scan.findings.map((f: { rule: string }) => f.rule)).toEqual(["90020", "10020"]);
  });

  it("marks what the engine stops reporting as fixed, and leaves other engines alone", async () => {
    await nuclei(exposed);
    const scan = await json(await zap(xss, headers));
    expect(scan).toMatchObject({ total: 2, new: 0, resolved: 3, passed: true });
    const id = (await json(await app.admin("/api/v1/targets"))).targets[0].id;
    const resolved = (await json(await app.admin(`/api/v1/targets/${id}/findings?status=resolved`))).findings.map((f: { rule: string }) => f.rule).sort();
    expect(resolved).toEqual(["10020", "40018", "90020"]);
    expect((await json(await app.admin(`/api/v1/targets/${id}/findings`))).findings.map((f: { rule: string }) => f.rule).sort()).toEqual(["10038", "40012", "git-config"]);
  });

  it("leaves out findings outside the target's address", async () => {
    const scan = await json(await nuclei(exposed, { rule: "x", url: "https://other.example.com/a" }, { rule: "y", url: "https://shop.example.com.evil.net/a" }, { rule: "z", url: "src/file.js" }));
    expect(scan).toMatchObject({ total: 1, ignored: 3, new: 0 });
  });

  it("takes a gzipped body and an engine name", async () => {
    const res = await app.ingest(`/api/v1/scans?${new URLSearchParams({ target: "shop-staging", engine: "custom" })}`, { method: "POST", body: gzipSync(sarif("My scanner", headers)), headers: { "content-encoding": "gzip" } });
    expect(await json(res)).toMatchObject({ engine: "custom", tool: "My scanner", total: 1 });
  });

  it("refuses what it cannot place", async () => {
    const problem = async (res: Response, status: number, code: string) => (expect(res.status).toBe(status), expect(await json(res)).toMatchObject({ code }));
    await problem(await app.scan({ target: "nope" }, sarif("ZAP")), 404, "not-found");
    await problem(await app.scan({}, sarif("ZAP")), 422, "invalid-body");
    await problem(await app.scan({ target: "../x" }, sarif("ZAP")), 422, "invalid-body");
    await problem(await app.scan({ target: "shop-staging", engine: "Bad Engine" }, sarif("ZAP")), 422, "invalid-body");
    await problem(await app.scan({ target: "shop-staging" }, "{nope"), 422, "invalid-sarif");
    await problem(await app.scan({ target: "shop-staging" }, JSON.stringify({ hello: 1 })), 422, "invalid-sarif");
    await problem(await app.ingest("/api/v1/scans?target=shop-staging", { method: "POST", body: "x", headers: { "content-encoding": "br" } }), 400, "invalid-body");
  });
});

describe("triage and policy", () => {
  const target = async () => (await json(await app.admin("/api/v1/targets"))).targets[0];
  const findingOf = async (rule: string) => {
    const t = await target();
    const f = (await json(await app.admin(`/api/v1/targets/${t.id}/findings?q=${rule}&status=open`))).findings[0];
    return { t, f, put: (body: unknown) => app.admin(`/api/v1/targets/${t.id}/findings/${f.fingerprint}`, { method: "PUT", body: JSON.stringify(body) }) };
  };
  const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

  it("needs a reason, and an end for accepted risk", async () => {
    const { put } = await findingOf("40012");
    expect((await put({ state: "accepted", reason: "Behind the VPN" })).status).toBe(422);
    expect((await put({ state: "accepted", reason: "Behind the VPN", expiresAt: inDays(-1) })).status).toBe(422);
    expect((await put({ state: "accepted", reason: "Behind the VPN", expiresAt: inDays(400) })).status).toBe(422);
    expect((await put({ state: "false-positive", reason: "" })).status).toBe(422);
    expect((await put({ state: "ignored", reason: "x" })).status).toBe(422);
    const t = await target();
    expect((await app.admin(`/api/v1/targets/${t.id}/findings/nope`, { method: "PUT", body: JSON.stringify({ state: "open" }) })).status).toBe(404);
  });

  it("keeps a decision with the finding across reports", async () => {
    const { put, t } = await findingOf("40012");
    const done = await json(await put({ state: "false-positive", reason: "Output is encoded by the framework" }));
    expect(done).toMatchObject({ rule: "40012", triage: { state: "false-positive", by: "admin token", active: true } });
    expect((await target()).open.high).toBe(0);
    // It goes missing and comes back: still triaged, so it is not new.
    await zap(headers);
    expect(await json(await zap(xss, headers))).toMatchObject({ new: 0, suppressed: 1, passed: true });
    expect((await json(await app.admin(`/api/v1/targets/${t.id}/findings?status=suppressed`))).findings.map((f: { rule: string }) => f.rule)).toEqual(["40012"]);
    expect(await json(await put({ state: "open" }))).toMatchObject({ triage: null });
  });

  it("changes what fails a check, and whether the target is production", async () => {
    const t = await target();
    const patch = (body: unknown) => app.admin(`/api/v1/targets/${t.id}`, { method: "PATCH", body: JSON.stringify(body) });
    expect(await json(await patch({ failOn: "none", production: true }))).toMatchObject({ failOn: "none", production: true });
    expect(await json(await zap(xss, headers, { rule: "new", level: "error", url: `${shop}/new` }))).toMatchObject({ new: 1, blocking: 0, passed: true, failOn: "none" });
    await patch({ failOn: "critical" });
    expect(await json(await zap(xss, headers, { rule: "new", level: "error", url: `${shop}/new` }, { rule: "crit", score: 9.9, url: `${shop}/crit` }))).toMatchObject({ new: 1, blocking: 1, passed: false });
    expect((await patch({})).status).toBe(422);
    expect((await patch({ failOn: "urgent" })).status).toBe(422);
    expect((await patch({ url: "https://x.example.com" })).status).toBe(422);
    expect((await patch({ production: "yes" })).status).toBe(422);
  });

  it("filters and pages findings", async () => {
    const all = await json(await app.admin("/api/v1/findings?limit=2"));
    expect(all.findings).toHaveLength(2);
    expect(all.nextCursor).toBeDefined();
    expect((await json(await app.admin(`/api/v1/findings?limit=2&cursor=${all.nextCursor}`))).findings.length).toBeGreaterThan(0);
    expect((await json(await app.admin("/api/v1/findings?severity=low"))).findings.map((f: { rule: string }) => f.rule)).toEqual(["10038"]);
    expect((await json(await app.admin("/api/v1/findings?q=git"))).findings.map((f: { rule: string }) => f.rule)).toEqual(["git-config"]);
    expect((await app.admin("/api/v1/findings?severity=urgent")).status).toBe(422);
    expect((await app.admin("/api/v1/findings?status=gone")).status).toBe(422);
    expect((await app.admin("/api/v1/findings?limit=0")).status).toBe(422);
  });

  it("deletes a target with its reports and findings", async () => {
    const t = await target();
    const scans = (await json(await app.admin(`/api/v1/targets/${t.id}/scans`))).scans;
    expect(scans.length).toBeGreaterThan(3);
    expect((await app.admin(`/api/v1/scans/${scans[0].id}`)).status).toBe(200);
    expect((await app.admin(`/api/v1/targets/${t.id}`, { method: "DELETE" })).status).toBe(204);
    expect((await app.admin(`/api/v1/targets/${t.id}`)).status).toBe(404);
    expect((await app.admin(`/api/v1/scans/${scans[0].id}`)).status).toBe(404);
    expect((await json(await app.admin("/api/v1/findings"))).findings).toEqual([]);
  });
});

describe("access", () => {
  it("asks for the ingest token or an editor, and keeps targets to admins", async () => {
    const anon = (path: string, init: RequestInit = {}) => fetch(app.base + path, init);
    expect((await anon("/api/v1/scans?target=a", { method: "POST", body: "{}" })).status).toBe(401);
    expect((await anon("/api/v1/scans?target=a", { method: "POST", body: "{}", headers: { authorization: "Bearer nope" } })).status).toBe(401);
    expect((await anon("/api/v1/targets")).status).toBe(401);
    expect((await anon("/api/v1/targets", { method: "POST", body: "{}" })).status).toBe(401);
    // The ingest token sends reports and nothing else.
    expect((await app.ingest("/api/v1/targets")).status).toBe(401);
    expect((await app.ingest("/api/v1/targets", { method: "POST", body: "{}" })).status).toBe(401);
    expect((await app.ingest("/api/v1/findings")).status).toBe(401);
    const closed = await startApp({ version: "0.1.0", ingestToken: undefined, adminToken: undefined });
    expect((await fetch(`${closed.base}/api/v1/scans?target=a`, { method: "POST", body: "{}" })).status).toBe(503);
    await closed.close();
  });

  it("answers version, health and metrics", async () => {
    expect(await json(await fetch(`${app.base}/api/v1/version`))).toEqual({ product: "dast", version: "0.1.0" });
    expect((await fetch(`${app.base}/healthz`)).status).toBe(200);
    expect((await fetch(`${app.base}/readyz`)).status).toBe(200);
    const metrics = await (await fetch(`${app.base}/metrics`)).text();
    expect(metrics).toContain('openasy_build_info{product="dast",version="0.1.0"} 1');
    expect(metrics).toMatch(/openasy_dast_targets \d+/);
    expect(metrics).toMatch(/openasy_dast_verified_targets \d+/);
    expect(metrics).toContain('openasy_dast_open_findings{severity="high"}');
  });
});
