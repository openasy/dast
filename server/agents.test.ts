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
    const t = await app.setTarget("shop", shop);
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
    await app.setTarget("shop", shop, { production: true });
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
    const form = {
      kind: "form",
      url: `${shop}/login`,
      usernameField: "email",
      passwordField: "password",
      username: "scan@example.com",
      loggedIn: "Sign out (you)",
      secret: "DAST_SHOP_PASSWORD",
    };
    // The file names the variable; the secret is only in the environment.
    await app.setTarget("shop", shop, { production: true, login: form });
    expect(app.fileWarnings()).toEqual(["shop: DAST_SHOP_PASSWORD is not set, so it is scanned without its login."]);
    expect((await json(await app.admin(`/api/v1/targets/${shopId}/auth-profiles`))).authProfiles).toEqual([]);
    await app.setTarget("shop", shop, { production: true, login: form }, { DAST_SHOP_PASSWORD: "hunter22" });
    expect(app.fileWarnings()).toEqual([]);
    const [login] = (await json(await app.admin(`/api/v1/targets/${shopId}/auth-profiles`))).authProfiles;
    expect(login).toMatchObject({ name: "file", kind: "form", username: "scan@example.com", loginUrl: `${shop}/login` });
    expect(JSON.stringify(login)).not.toContain("hunter22");
    expect(JSON.stringify(app.db.prepare("SELECT * FROM auth_profiles").all())).not.toContain("hunter22");
    // It is changed in the file, not here.
    expect((await app.admin(`/api/v1/targets/${shopId}/auth-profiles/${login.id}`, { method: "DELETE" })).status).toBe(409);

    app.agents.scanNow(shopId, { profile: "standard", authProfile: login.id }, "admin@example.com", true);
    const [job] = await work();
    expect(job!.auth).toEqual({
      kind: "form",
      loginUrl: `${shop}/login`,
      usernameField: "email",
      passwordField: "password",
      username: "scan@example.com",
      password: "hunter22",
      // The text the file names, matched as it is written.
      loggedInRegex: "Sign out \\(you\\)",
    });
    expect(app.agents.listJobs({ targetId: shopId })[0]).toMatchObject({ authProfile: "file" });
    await agent(`/api/v1/agent/jobs/${job!.id}/done`);
    // Another kind of login in the file replaces it, under the same id.
    await app.setTarget(
      "shop",
      shop,
      { production: true, login: { kind: "header", header: "Authorization", secret: "DAST_SHOP_TOKEN" } },
      { DAST_SHOP_TOKEN: "Bearer t0ken" },
    );
    const [header] = (await json(await app.admin(`/api/v1/targets/${shopId}/auth-profiles`))).authProfiles;
    expect(header).toMatchObject({ id: login.id, kind: "header", headerName: "Authorization" });
    expect(JSON.stringify(header)).not.toContain("t0ken");
    app.agents.scanNow(shopId, { profile: "standard", authProfile: header.id }, "admin@example.com", true);
    expect((await work())[0]!.auth).toEqual({ kind: "header", headerName: "Authorization", value: "Bearer t0ken" });
    // A login of another target is refused.
    expect(() => app.agents.scanNow(intranetId || shopId, { authProfile: "nope" }, "admin@example.com", true)).toThrow(/logins/);
  });

  it("has an agent read the proof of a target on a private address", async () => {
    const t = await app.setTarget("intranet", intranet);
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
    const t = await app.setTarget(
      "blog",
      "https://blog.example.com",
      {
        schedule: "daily",
        profile: "full",
        login: { kind: "header", header: "Authorization", secret: "DAST_BLOG_TOKEN" },
      },
      { DAST_BLOG_TOKEN: "Bearer blog" },
    );
    expect(t).toMatchObject({ schedule: "daily", scheduleProfile: "full", nextScanAt: expect.any(String) });
    app.db.prepare("UPDATE targets SET next_scan_at = '2000-01-01T00:00:00.000Z' WHERE id = ?").run(t.id);
    app.agents.tick();
    // Not verified: the schedule asks for full, the target allows passive.
    // A scheduled scan uses the login the file names.
    expect(app.agents.listJobs({ targetId: t.id })).toEqual([
      expect.objectContaining({ profile: "passive", requestedBy: "schedule", status: "queued", authProfile: "file" }),
    ]);
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
