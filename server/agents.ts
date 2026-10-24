// dast-agent and its queue (ADR 0037). Agents enrol with a one-time token and ask for jobs; dast never connects to
// them. A scan is started by hand or by a target's schedule, and what it may do depends on the target: a target
// nobody has proven is theirs gets a passive scan and nothing else, and a production target gets a full scan only from
// an admin. The agent sends one SARIF report per engine, kept apart per kind of scan, so a passive scan never marks
// what an active one found as fixed.
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { DastError, type Dast } from "./dast.ts";
import type { Keyring } from "./kek.ts";
import { VERIFY_PATH } from "./verify.ts";

export type Profile = "passive" | "standard" | "full";
export type Schedule = "none" | "daily" | "weekly";
const PROFILES: Profile[] = ["passive", "standard", "full"];
const SCHEDULES: Schedule[] = ["none", "daily", "weekly"];
const ENGINES = ["zap", "nuclei"] as const;

const AGENT_NAME = /^[a-z0-9][a-z0-9.-]{0,62}$/;
const ENROLL_TTL_MS = 7 * 86_400_000;
/** An agent that has not asked for work in this long is offline. */
const ONLINE_MS = 2 * 60_000;
/** A job an agent took and did not finish in this long goes back to the queue; full scans can take an hour. */
const LEASE_MS = 3 * 3_600_000;
const MAX_ATTEMPTS = 3;
const DAY = 86_400_000;

const now = () => new Date().toISOString();
const hash = (s: string) => createHash("sha256").update(s).digest("hex");
const bad = (detail: string) => new DastError(422, "invalid-body", detail);
const notFound = (what: string) => new DastError(404, "not-found", `${what} does not exist.`);

export interface Agent {
  id: string;
  name: string;
  status: "waiting-to-enrol" | "online" | "offline";
  version: string | null;
  lastSeen: string | null;
  createdAt: string;
}

export interface Job {
  id: string;
  target: { id: string; name: string };
  kind: "scan" | "verify";
  profile: Profile | null;
  status: "queued" | "running" | "done" | "failed";
  attempts: number;
  error: string | null;
  /** The login the scan used, by name; null without one. */
  authProfile: string | null;
  requestedBy: string;
  createdAt: string;
  finishedAt: string | null;
}

/** How a scan gets past a target's login. The secret is never part of it. */
export interface AuthProfile {
  id: string;
  name: string;
  kind: "header" | "form";
  headerName: string | null;
  loginUrl: string | null;
  usernameField: string | null;
  passwordField: string | null;
  username: string | null;
  loggedInRegex: string | null;
  createdAt: string;
}

/** The login as the agent running the scan gets it: with its secret, and to nobody else. */
export type WorkAuth =
  | { kind: "header"; headerName: string; value: string }
  | { kind: "form"; loginUrl: string; usernameField: string; passwordField: string; username: string; password: string; loggedInRegex: string };

/** What an agent gets: the address, how hard it may test it, and nothing else about the install. */
export interface Work {
  id: string;
  kind: "scan" | "verify";
  target: { name: string; url: string; production: boolean };
  profile: Profile | null;
  /** For verify: where the proof is. */
  proofUrl?: string;
  auth?: WorkAuth;
}

const HEADER = /^[A-Za-z0-9-]{1,64}$/;
const FIELD = /^[A-Za-z0-9_.[\]-]{1,64}$/;

export function createAgents(
  db: DatabaseSync,
  dast: Dast,
  opts: { keyring?: Keyring; log?: (level: "info" | "warn", msg: string, f?: Record<string, unknown>) => void } = {},
) {
  const toAgent = (a: Record<string, string | null>): Agent => ({
    id: a.id!,
    name: a.name!,
    status: !a.secret_hash ? "waiting-to-enrol" : a.last_seen && Date.now() - Date.parse(a.last_seen) < ONLINE_MS ? "online" : "offline",
    version: a.version ?? null,
    lastSeen: a.last_seen ?? null,
    createdAt: a.created_at!,
  });

  const toJob = (j: Record<string, string | number | null>): Job => ({
    id: j.id as string,
    target: { id: j.target_id as string, name: j.target_name as string },
    kind: j.kind as Job["kind"],
    profile: (j.profile as Profile | null) ?? null,
    status: j.status as Job["status"],
    attempts: j.attempts as number,
    error: (j.error as string | null) ?? null,
    authProfile: (j.auth_name as string | null) ?? null,
    requestedBy: j.requested_by as string,
    createdAt: j.created_at as string,
    finishedAt: (j.finished_at as string | null) ?? null,
  });

  const target = (id: string) => {
    const t = db.prepare("SELECT * FROM targets WHERE id = ?").get(id) as Record<string, string | number | null> | undefined;
    if (!t) throw notFound("The target");
    return t;
  };

  function listJobs(filter: { targetId?: string } = {}): Job[] {
    return (
      db
        .prepare(
          `SELECT j.*, t.name AS target_name, a.name AS auth_name FROM scan_jobs j JOIN targets t ON t.id = j.target_id
           LEFT JOIN auth_profiles a ON a.id = j.auth_profile_id
           ${filter.targetId ? "WHERE j.target_id = ?" : ""} ORDER BY j.created_at DESC, j.rowid DESC LIMIT 200`,
        )
        .all(...(filter.targetId ? [filter.targetId] : [])) as Array<Record<string, string | number | null>>
    ).map(toJob);
  }

  /** The most a target allows: passive until it is proven, and full on production only when an admin asks. */
  function allowed(t: Record<string, string | number | null>, want: Profile, admin: boolean): Profile {
    if (t.verified_at === null) return "passive";
    if (want === "full" && t.production === 1 && !admin) return "standard";
    return want;
  }

  function queue(targetId: string, kind: "scan" | "verify", profile: Profile | null, by: string, authProfileId: string | null = null): Job {
    // One waiting job per target and kind: asking again does not pile up scans.
    const waiting = db.prepare("SELECT id FROM scan_jobs WHERE target_id = ? AND kind = ? AND status = 'queued'").get(targetId, kind) as
      { id: string } | undefined;
    if (waiting) {
      db.prepare("UPDATE scan_jobs SET profile = ?, requested_by = ?, auth_profile_id = ? WHERE id = ?").run(profile, by, authProfileId, waiting.id);
      return listJobs({ targetId }).find((j) => j.id === waiting.id)!;
    }
    const id = randomUUID();
    db.prepare(
      "INSERT INTO scan_jobs (id, target_id, kind, profile, status, requested_by, created_at, auth_profile_id) VALUES (?, ?, ?, ?, 'queued', ?, ?, ?)",
    ).run(id, targetId, kind, profile, by, now(), authProfileId);
    return listJobs({ targetId }).find((j) => j.id === id)!;
  }

  const toProfile = (a: Record<string, string | null>): AuthProfile => ({
    id: a.id!,
    name: a.name!,
    kind: a.kind as AuthProfile["kind"],
    headerName: a.header_name ?? null,
    loginUrl: a.login_url ?? null,
    usernameField: a.username_field ?? null,
    passwordField: a.password_field ?? null,
    username: a.username ?? null,
    loggedInRegex: a.logged_in_regex ?? null,
    createdAt: a.created_at!,
  });

  function listAuthProfiles(targetId: string): AuthProfile[] {
    target(targetId);
    return (db.prepare("SELECT * FROM auth_profiles WHERE target_id = ? ORDER BY name").all(targetId) as Array<Record<string, string | null>>).map(toProfile);
  }

  /**
   * Adds a login: a header sent with every request, or a form ZAP fills in. The login page must be on the target's
   * origin, so a scan never sends its password anywhere else.
   */
  function createAuthProfile(targetId: string, body: Record<string, unknown>): AuthProfile {
    const t = target(targetId);
    if (!opts.keyring) throw new DastError(503, "not-configured", "Mount openasy-kek: a login's secret is kept only sealed (ADR 0021).");
    const str = (k: string, max = 256) => (typeof body[k] === "string" && (body[k] as string).length <= max ? (body[k] as string) : "");
    const name = str("name", 64).trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/.test(name)) throw bad("name is up to 64 letters, digits, spaces, . _ and -.");
    if (db.prepare("SELECT 1 FROM auth_profiles WHERE target_id = ? AND name = ?").get(targetId, name))
      throw new DastError(409, "conflict", `This target has a login named ${name}.`);
    const id = randomUUID();
    if (body.kind === "header") {
      const headerName = str("headerName", 64);
      const value = str("value", 4096);
      if (!HEADER.test(headerName)) throw bad("headerName is a header name, such as Authorization.");
      if (!value || /[\r\n]/.test(value)) throw bad("value is the header's value, on one line.");
      db.prepare("INSERT INTO auth_profiles (id, target_id, name, kind, header_name, secret, created_at) VALUES (?, ?, ?, 'header', ?, ?, ?)").run(
        id,
        targetId,
        name,
        headerName,
        opts.keyring.seal(value),
        now(),
      );
    } else if (body.kind === "form") {
      const loginUrl = str("loginUrl", 2048);
      let login: URL;
      try {
        login = new URL(loginUrl);
      } catch {
        throw bad("loginUrl is the address the login form is sent to.");
      }
      if (login.origin !== new URL(t.url as string).origin) throw bad("loginUrl must be on the target's own origin.");
      const usernameField = str("usernameField", 64);
      const passwordField = str("passwordField", 64);
      if (!FIELD.test(usernameField) || !FIELD.test(passwordField)) throw bad("usernameField and passwordField are the form's field names.");
      const username = str("username");
      const password = str("password", 1024);
      if (!username || !password) throw bad("username and password are required.");
      const loggedInRegex = str("loggedInRegex", 256);
      try {
        if (!loggedInRegex) throw new Error();
        new RegExp(loggedInRegex);
      } catch {
        throw bad("loggedInRegex is a pattern only a signed-in page contains, such as Sign out.");
      }
      db.prepare(
        `INSERT INTO auth_profiles (id, target_id, name, kind, login_url, username_field, password_field, username, logged_in_regex, secret, created_at)
         VALUES (?, ?, ?, 'form', ?, ?, ?, ?, ?, ?, ?)`,
      ).run(id, targetId, name, login.href, usernameField, passwordField, username, loggedInRegex, opts.keyring.seal(password), now());
    } else throw bad("kind is header or form.");
    return toProfile(db.prepare("SELECT * FROM auth_profiles WHERE id = ?").get(id) as Record<string, string | null>);
  }

  function deleteAuthProfile(targetId: string, id: string) {
    if (db.prepare("DELETE FROM auth_profiles WHERE id = ? AND target_id = ?").run(id, targetId).changes === 0) throw notFound("The login");
  }

  /** The login a job uses, with its secret, for the agent that runs it. */
  function workAuth(authProfileId: string | null): WorkAuth | undefined {
    if (!authProfileId || !opts.keyring) return undefined;
    const a = db.prepare("SELECT * FROM auth_profiles WHERE id = ?").get(authProfileId) as Record<string, string> | undefined;
    if (!a) return undefined;
    const secret = opts.keyring.open(a.secret!).toString("utf8");
    return a.kind === "header"
      ? { kind: "header", headerName: a.header_name!, value: secret }
      : {
          kind: "form",
          loginUrl: a.login_url!,
          usernameField: a.username_field!,
          passwordField: a.password_field!,
          username: a.username!,
          password: secret,
          loggedInRegex: a.logged_in_regex!,
        };
  }

  /** Starts a scan by hand. Asking for more than the target allows is refused, so nobody is surprised. */
  function scanNow(targetId: string, body: { profile?: unknown; authProfile?: unknown }, by: string, admin: boolean): Job {
    const t = target(targetId);
    const profile = (body.profile ?? "standard") as Profile;
    if (!PROFILES.includes(profile)) throw bad(`profile is one of ${PROFILES.join(", ")}.`);
    if (profile !== "passive" && t.verified_at === null)
      throw new DastError(409, "conflict", "Verify the target first: until then only a passive scan runs, which sends no attacks.");
    if (profile === "full" && t.production === 1 && !admin)
      throw new DastError(403, "forbidden", "A full scan of a production target needs an admin: it sends every attack ZAP and Nuclei have.");
    let authProfileId: string | null = null;
    if (body.authProfile !== undefined && body.authProfile !== null) {
      const a = db.prepare("SELECT id FROM auth_profiles WHERE id = ? AND target_id = ?").get(String(body.authProfile), targetId) as { id: string } | undefined;
      if (!a) throw bad("authProfile is the id of one of this target's logins.");
      authProfileId = a.id;
    }
    return queue(targetId, "scan", profile, by, authProfileId);
  }

  /** A target's schedule; the scan it queues is limited by what the target allows when it runs. */
  function setSchedule(targetId: string, body: { schedule?: unknown; scheduleProfile?: unknown }) {
    const t = target(targetId);
    const schedule = (body.schedule ?? t.schedule) as Schedule;
    const profile = (body.scheduleProfile ?? t.schedule_profile) as Profile;
    if (!SCHEDULES.includes(schedule)) throw bad(`schedule is one of ${SCHEDULES.join(", ")}.`);
    if (!PROFILES.includes(profile)) throw bad(`scheduleProfile is one of ${PROFILES.join(", ")}.`);
    const next = schedule === "none" ? null : new Date(Date.now() + (schedule === "daily" ? DAY : 7 * DAY)).toISOString();
    db.prepare("UPDATE targets SET schedule = ?, schedule_profile = ?, next_scan_at = ? WHERE id = ?").run(
      schedule,
      profile,
      schedule === t.schedule && t.next_scan_at ? (t.next_scan_at as string) : next,
      targetId,
    );
  }

  /** Queues the scans whose time has come. */
  function tick() {
    const due = db.prepare("SELECT * FROM targets WHERE schedule <> 'none' AND next_scan_at <= ?").all(now()) as Array<Record<string, string | number | null>>;
    for (const t of due) {
      const profile = allowed(t, t.schedule_profile as Profile, true);
      queue(t.id as string, "scan", profile, "schedule");
      db.prepare("UPDATE targets SET next_scan_at = ? WHERE id = ?").run(
        new Date(Date.now() + (t.schedule === "daily" ? DAY : 7 * DAY)).toISOString(),
        t.id as string,
      );
      opts.log?.("info", "scheduled scan queued", { target: t.name, profile });
    }
  }

  /** A target on a private address is verified by an agent that can reach it, if there is one. */
  function queueVerify(targetId: string, by: string): Job | null {
    if (!db.prepare("SELECT 1 FROM agents WHERE secret_hash IS NOT NULL").get()) return null;
    return queue(targetId, "verify", null, by);
  }

  function listAgents(): Agent[] {
    return (db.prepare("SELECT * FROM agents ORDER BY name").all() as Array<Record<string, string | null>>).map(toAgent);
  }

  function createAgent(body: { name?: unknown }) {
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!AGENT_NAME.test(name)) throw bad("name is lowercase letters, digits, dots and dashes, such as dc1.");
    if (db.prepare("SELECT 1 FROM agents WHERE name = ?").get(name)) throw new DastError(409, "conflict", `An agent named ${name} exists.`);
    const id = randomUUID();
    const token = `ode_${randomBytes(24).toString("base64url")}`;
    db.prepare("INSERT INTO agents (id, name, enroll_token_hash, enroll_expires_at, created_at) VALUES (?, ?, ?, ?, ?)").run(
      id,
      name,
      hash(token),
      new Date(Date.now() + ENROLL_TTL_MS).toISOString(),
      now(),
    );
    return { agent: toAgent(db.prepare("SELECT * FROM agents WHERE id = ?").get(id) as Record<string, string | null>), enrollToken: token };
  }

  function deleteAgent(id: string) {
    if (db.prepare("DELETE FROM agents WHERE id = ?").run(id).changes === 0) throw notFound("The agent");
  }

  /** Trades a one-time token for the agent's own secret, which only its hash is kept of. */
  function enroll(body: { token?: unknown; version?: unknown }) {
    const token = typeof body.token === "string" ? body.token : "";
    const a = db.prepare("SELECT * FROM agents WHERE enroll_token_hash = ?").get(hash(token)) as Record<string, string> | undefined;
    if (!a || Date.parse(a.enroll_expires_at!) < Date.now())
      throw new DastError(401, "invalid-token", "The enrolment token is unknown, used or expired. Make a new one under Agents.");
    const secret = `oda_${randomBytes(32).toString("base64url")}`;
    db.prepare("UPDATE agents SET enroll_token_hash = NULL, enroll_expires_at = NULL, secret_hash = ?, version = ?, last_seen = ? WHERE id = ?").run(
      hash(secret),
      typeof body.version === "string" ? body.version.slice(0, 32) : null,
      now(),
      a.id!,
    );
    return { id: a.id!, name: a.name!, secret };
  }

  function agentBySecret(authorization: string | undefined): string | undefined {
    const secret = authorization?.startsWith("Bearer oda_") ? authorization.slice(7) : undefined;
    if (!secret) return undefined;
    const want = Buffer.from(hash(secret));
    const row = db.prepare("SELECT id, secret_hash FROM agents WHERE secret_hash = ?").get(hash(secret)) as { id: string; secret_hash: string } | undefined;
    return row && timingSafeEqual(Buffer.from(row.secret_hash), want) ? row.id : undefined;
  }

  /** The next job for an agent, leased to it; a lease that ran out goes back to the queue, three times at most. */
  function work(agentId: string, version?: unknown): { jobs: Work[] } {
    db.prepare("UPDATE agents SET last_seen = ?, version = COALESCE(?, version) WHERE id = ?").run(
      now(),
      typeof version === "string" ? version.slice(0, 32) : null,
      agentId,
    );
    db.prepare(
      `UPDATE scan_jobs SET status = CASE WHEN attempts >= ${MAX_ATTEMPTS} THEN 'failed' ELSE 'queued' END,
         error = CASE WHEN attempts >= ${MAX_ATTEMPTS} THEN 'The agent did not finish it, ${MAX_ATTEMPTS} times.' ELSE error END,
         agent_id = NULL, lease_until = NULL
       WHERE status = 'running' AND lease_until < ?`,
    ).run(now());
    const job = db
      .prepare(
        "SELECT j.*, t.name, t.url, t.production, t.verified_at FROM scan_jobs j JOIN targets t ON t.id = j.target_id WHERE j.status = 'queued' ORDER BY j.created_at LIMIT 1",
      )
      .get() as Record<string, string | number | null> | undefined;
    if (!job) return { jobs: [] };
    // What the target allows is checked again when the scan starts: it may have changed since it was queued.
    const profile = job.kind === "scan" ? allowed(job, job.profile as Profile, true) : null;
    db.prepare("UPDATE scan_jobs SET status = 'running', agent_id = ?, lease_until = ?, attempts = attempts + 1, profile = ? WHERE id = ?").run(
      agentId,
      new Date(Date.now() + LEASE_MS).toISOString(),
      profile,
      job.id as string,
    );
    return {
      jobs: [
        {
          id: job.id as string,
          kind: job.kind as Work["kind"],
          target: { name: job.name as string, url: job.url as string, production: job.production === 1 },
          profile,
          ...(job.kind === "verify" && { proofUrl: new URL(VERIFY_PATH, job.url as string).href }),
          ...(job.kind === "scan" && job.auth_profile_id && { auth: workAuth(job.auth_profile_id as string) }),
        },
      ],
    };
  }

  const ownJob = (agentId: string, jobId: string) => {
    const j = db
      .prepare("SELECT j.*, t.name FROM scan_jobs j JOIN targets t ON t.id = j.target_id WHERE j.id = ? AND j.agent_id = ? AND j.status = 'running'")
      .get(jobId, agentId) as Record<string, string | number | null> | undefined;
    if (!j) throw notFound("A running job of this agent");
    return j;
  };

  /** One engine's report of a scan, kept apart per kind of scan. */
  function report(agentId: string, jobId: string, engine: string | null, sarif: Buffer) {
    const j = ownJob(agentId, jobId);
    if (j.kind !== "scan" || !ENGINES.includes(engine as (typeof ENGINES)[number])) throw bad(`engine is one of ${ENGINES.join(", ")}.`);
    return dast.ingest({ target: j.name as string, engine: `${engine}-${j.profile}` }, sarif);
  }

  function finish(agentId: string, jobId: string) {
    ownJob(agentId, jobId);
    db.prepare("UPDATE scan_jobs SET status = 'done', finished_at = ?, lease_until = NULL WHERE id = ?").run(now(), jobId);
  }

  function fail(agentId: string, jobId: string, body: { error?: unknown }) {
    ownJob(agentId, jobId);
    const error = typeof body.error === "string" ? body.error.slice(0, 1000) : "The agent could not scan it.";
    db.prepare("UPDATE scan_jobs SET status = 'failed', error = ?, finished_at = ?, lease_until = NULL WHERE id = ?").run(error, now(), jobId);
    opts.log?.("warn", "scan job failed", { job: jobId, error });
  }

  /** What an agent read at the target's proof address; the target is verified when it is the target's secret. */
  function proof(agentId: string, jobId: string, body: { content?: unknown }) {
    const j = ownJob(agentId, jobId);
    if (j.kind !== "verify") throw bad("This job is not a verification.");
    const content = typeof body.content === "string" ? body.content.slice(0, 256).trim() : "";
    const t = target(j.target_id as string);
    if (content === t.verify_token) {
      db.prepare("UPDATE targets SET verified_at = COALESCE(verified_at, ?) WHERE id = ?").run(now(), t.id as string);
      finish(agentId, jobId);
    } else {
      fail(agentId, jobId, { error: `${new URL(VERIFY_PATH, t.url as string).href} does not hold the verification content.` });
    }
  }

  return {
    listJobs,
    listAuthProfiles,
    createAuthProfile,
    deleteAuthProfile,
    scanNow,
    setSchedule,
    tick,
    queueVerify,
    listAgents,
    createAgent,
    deleteAgent,
    enroll,
    agentBySecret,
    work,
    report,
    finish,
    fail,
    proof,
  };
}

export type Agents = ReturnType<typeof createAgents>;
