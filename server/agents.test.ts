import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fakeSite, sarif, startApp } from "./test-app.ts";

const json = async (res: Response) => (await res.json()) as any;
const shop = "https://shop.example.com";
const intranet = "http://10.0.0.20";

let app: Awaited<ReturnType<typeof startApp>>;
const site = fakeSite();
// An address dast cannot reach answers as fetchProof does for it.
const verifier = site.verifier;
site.verifier = async (origin) => {
  if (origin === intranet) throw new Error("10.0.0.20 is on a private address; an agent in that network verifies it.");
  return verifier(origin);
};

beforeAll(async () => {
  app = await startApp({ version: "0.0.0", site });
});
afterAll(() => app.close());

const post = (path: string, body: unknown = {}) => app.admin(path, { method: "POST", body: JSON.stringify(body) });
let secret = "";
const agent = (path: string, body: unknown = {}) =>
  fetch(app.base + path, {
    method: "POST",
    headers: { authorization: `Bearer ${secret}`, "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
const work = async () => (await json(await agent("/api/v1/agent/work", { version: "0.5.0" }))).jobs as Array<Record<string, any>>;

describe("scans run by dast-agent (ADR 0037)", () => {
  let shopId = "";
  let intranetId = "";

  it("enrols an agent once", async () => {
    const made = await json(await post("/api/v1/agents", { name: "dc1" }));
    const enrolled = await json(await fetch(app.base + "/api/v1/agent/enroll", { method: "POST", body: JSON.stringify({ token: made.enrollToken }) }));
    secret = enrolled.secret;
    expect(secret).toMatch(/^oda_/);
    expect((await fetch(app.base + "/api/v1/agent/enroll", { method: "POST", body: JSON.stringify({ token: made.enrollToken }) })).status).toBe(401);
  });

  it("gives a target nobody has proven only a passive scan", async () => {
    const t = await json(await post("/api/v1/targets", { name: "shop", url: shop }));
    shopId = t.id;
    expect((await post(`/api/v1/targets/${shopId}/scan`, { profile: "standard" })).status).toBe(409);
    expect(await json(await post(`/api/v1/targets/${shopId}/scan`, { profile: "passive" }))).toMatchObject({
      kind: "scan",
      profile: "passive",
      status: "queued",
    });
    const [job] = await work();
    expect(job).toEqual({ id: expect.any(String), kind: "scan", target: { name: "shop", url: shop, production: false }, profile: "passive" });
    const res = await agent(`/api/v1/agent/jobs/${job!.id}/sarif?engine=zap`, sarif("ZAP", { rule: "10038", url: `${shop}/` }));
    expect(await json(res)).toMatchObject({ engine: "zap-passive", total: 1 });
    expect((await agent(`/api/v1/agent/jobs/${job!.id}/done`)).status).toBe(204);
  });

  it("keeps each kind of scan apart, so a passive scan does not fix what an active one found", async () => {
    site.served.set(shop, (await json(await app.admin(`/api/v1/targets/${shopId}`))).verification.content);
    expect((await json(await post(`/api/v1/targets/${shopId}/verify`))).verified).toBe(true);
    await post(`/api/v1/targets/${shopId}/scan`, { profile: "standard" });
    const [job] = await work();
    expect(job!.profile).toBe("standard");
    await agent(`/api/v1/agent/jobs/${job!.id}/sarif?engine=zap`, sarif("ZAP", { rule: "40018", url: `${shop}/login`, level: "error" }));
    await agent(`/api/v1/agent/jobs/${job!.id}/sarif?engine=nuclei`, sarif("Nuclei", { rule: "exposed-env", url: `${shop}/.env`, level: "error" }));
    await agent(`/api/v1/agent/jobs/${job!.id}/done`);
    await post(`/api/v1/targets/${shopId}/scan`, { profile: "passive" });
    const [again] = await work();
    await agent(`/api/v1/agent/jobs/${again!.id}/sarif?engine=zap`, sarif("ZAP"));
    await agent(`/api/v1/agent/jobs/${again!.id}/done`);
    const open = (await json(await app.admin(`/api/v1/targets/${shopId}/findings`))).findings.map((f: any) => f.rule).sort();
    expect(open).toEqual(["40018", "exposed-env"]);
  });

  it("gives a full scan of a production target only to an admin", async () => {
    await app.admin(`/api/v1/targets/${shopId}`, { method: "PATCH", body: JSON.stringify({ production: true }) });
    expect(() => app.agents.scanNow(shopId, { profile: "full" }, "editor@example.com", false)).toThrow(/needs an admin/);
    expect(app.agents.scanNow(shopId, { profile: "full" }, "admin@example.com", true)).toMatchObject({ profile: "full" });
    // One waiting scan per target: asking again changes it rather than adding another.
    expect(app.agents.scanNow(shopId, { profile: "standard" }, "editor@example.com", false)).toMatchObject({ profile: "standard" });
    expect(app.agents.listJobs({ targetId: shopId }).filter((j) => j.status === "queued")).toHaveLength(1);
    const [job] = await work();
    await agent(`/api/v1/agent/jobs/${job!.id}/failed`, { error: "ZAP could not reach the target" });
    expect(app.agents.listJobs({ targetId: shopId })[0]).toMatchObject({ status: "failed", error: "ZAP could not reach the target" });
  });

  it("sends a login's secret only to the agent running a scan that uses it, and never back to people", async () => {
    const add = (body: unknown) => post(`/api/v1/targets/${shopId}/auth-profiles`, body);
    expect(
      (
        await add({
          name: "web",
          kind: "form",
          loginUrl: "https://evil.example.com/login",
          usernameField: "u",
          passwordField: "p",
          username: "a",
          password: "b",
          loggedInRegex: "Sign out",
        })
      ).status,
    ).toBe(422);
    const form = await json(
      await add({
        name: "web",
        kind: "form",
        loginUrl: `${shop}/login`,
        usernameField: "email",
        passwordField: "password",
        username: "scan@example.com",
        password: "hunter22",
        loggedInRegex: "Sign out",
      }),
    );
    expect(form).toMatchObject({ kind: "form", username: "scan@example.com", loginUrl: `${shop}/login` });
    expect(JSON.stringify(form)).not.toContain("hunter22");
    expect(JSON.stringify(app.db.prepare("SELECT * FROM auth_profiles").all())).not.toContain("hunter22");
    const header = await json(await add({ name: "api", kind: "header", headerName: "Authorization", value: "Bearer t0ken" }));
    expect(JSON.stringify(await json(await app.admin(`/api/v1/targets/${shopId}/auth-profiles`)))).not.toContain("t0ken");

    app.agents.scanNow(shopId, { profile: "standard", authProfile: form.id }, "admin@example.com", true);
    const [job] = await work();
    expect(job!.auth).toEqual({
      kind: "form",
      loginUrl: `${shop}/login`,
      usernameField: "email",
      passwordField: "password",
      username: "scan@example.com",
      password: "hunter22",
      loggedInRegex: "Sign out",
    });
    expect(app.agents.listJobs({ targetId: shopId })[0]).toMatchObject({ authProfile: "web" });
    await agent(`/api/v1/agent/jobs/${job!.id}/done`);
    app.agents.scanNow(shopId, { profile: "standard", authProfile: header.id }, "admin@example.com", true);
    expect((await work())[0]!.auth).toEqual({ kind: "header", headerName: "Authorization", value: "Bearer t0ken" });
    // A login of another target is refused.
    expect(() => app.agents.scanNow(intranetId || shopId, { authProfile: "nope" }, "admin@example.com", true)).toThrow(/logins/);
  });

  it("has an agent read the proof of a target on a private address", async () => {
    const t = await json(await post("/api/v1/targets", { name: "intranet", url: intranet }));
    intranetId = t.id;
    const res = await post(`/api/v1/targets/${intranetId}/verify`);
    expect(res.status).toBe(422);
    expect((await json(res)).detail).toMatch(/an agent reads the proof now/);
    const [job] = await work();
    expect(job).toMatchObject({ kind: "verify", proofUrl: `${intranet}/.well-known/openasy-dast` });
    expect((await agent(`/api/v1/agent/jobs/${job!.id}/proof`, { content: t.verification.content })).status).toBe(204);
    expect((await json(await app.admin(`/api/v1/targets/${intranetId}`))).verified).toBe(true);
  });

  it("queues scheduled scans when their time comes, as far as the target allows", async () => {
    const t = await json(await post("/api/v1/targets", { name: "blog", url: "https://blog.example.com" }));
    const patched = await json(
      await app.admin(`/api/v1/targets/${t.id}`, { method: "PATCH", body: JSON.stringify({ schedule: "daily", scheduleProfile: "full" }) }),
    );
    expect(patched).toMatchObject({ schedule: "daily", scheduleProfile: "full", nextScanAt: expect.any(String) });
    app.db.prepare("UPDATE targets SET next_scan_at = '2000-01-01T00:00:00.000Z' WHERE id = ?").run(t.id);
    app.agents.tick();
    // Not verified: the schedule asks for full, the target allows passive.
    expect(app.agents.listJobs({ targetId: t.id })).toEqual([expect.objectContaining({ profile: "passive", requestedBy: "schedule", status: "queued" })]);
    expect(Date.parse((await json(await app.admin(`/api/v1/targets/${t.id}`))).nextScanAt)).toBeGreaterThan(Date.now());
    app.agents.tick();
    expect(app.agents.listJobs({ targetId: t.id })).toHaveLength(1);
  });

  it("puts a job an agent did not finish back in the queue, three times at most", async () => {
    for (let i = 0; i < 3; i++) {
      const [job] = await work();
      expect(job!.target.name).toBe("blog");
      app.db.prepare("UPDATE scan_jobs SET lease_until = '2000-01-01T00:00:00.000Z' WHERE id = ?").run(job!.id);
    }
    expect(await work()).toEqual([]);
    expect(app.agents.listJobs().find((j) => j.target.name === "blog")).toMatchObject({ status: "failed", attempts: 3 });
  });
});
