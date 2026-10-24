import { randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import { pageOf, parseSarif, SarifError, SEVERITIES, type Finding, type Severity } from "./sarif.ts";
import { fetchProof, VERIFY_PATH, type Verifier } from "./verify.ts";

export type ProblemCode =
  | "invalid-token"
  | "invalid-json"
  | "invalid-body"
  | "invalid-sarif"
  | "verification-failed"
  | "not-found"
  | "conflict"
  | "forbidden"
  | "not-configured"
  | "payload-too-large"
  | "internal-error";

export class DastError extends Error {
  readonly status: number;
  readonly code: ProblemCode;
  constructor(status: number, code: ProblemCode, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

export type FailOn = Severity | "none";
export type Triage = "open" | "false-positive" | "accepted";
export type Status = "open" | "suppressed" | "resolved";

const FAIL_ON: FailOn[] = [...SEVERITIES, "none"];
const TRIAGE: Triage[] = ["open", "false-positive", "accepted"];
const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const RANK_SQL = `CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END`;

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const ENGINE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const MAX_ACCEPT_DAYS = 366;
/** Findings in the answer to a scan, for CI logs. The rest are on the target's page. */
const SCAN_FINDINGS_IN_ANSWER = 100;

const now = () => new Date().toISOString();
const bad = (detail: string) => new DastError(422, "invalid-body", detail);
const notFound = (what: string) => new DastError(404, "not-found", `${what} does not exist.`);

export interface Page<T> {
  items: T[];
  /** Opaque; pass it back as `cursor` for the next page. Absent on the last page (ADR 0024). */
  nextCursor?: string;
}

const encodeCursor = (offset: number) => Buffer.from(JSON.stringify({ o: offset })).toString("base64url");
function decodeCursor(cursor: string | undefined): number {
  if (!cursor) return 0;
  try {
    const o = (JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as { o?: unknown }).o;
    if (typeof o === "number" && Number.isSafeInteger(o) && o >= 0) return o;
  } catch {
    // fall through
  }
  throw bad("cursor is not one this API returned.");
}

export function parseLimit(value: string | null, max = 500, fallback = 100): number {
  if (value === null) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > max) throw bad(`limit must be between 1 and ${max}.`);
  return n;
}

export type Counts = Record<Severity, number>;
const zero = (): Counts => ({ critical: 0, high: 0, medium: 0, low: 0 });

/** The address a target stands for: origin and path, without credentials, query string or fragment. */
export function targetUrl(value: unknown): string {
  const url = typeof value === "string" ? pageOf(value.trim()) : null;
  if (!url) throw bad("url must be a web address starting with http:// or https://.");
  return url.origin + url.pathname.replace(/\/+$/, "");
}

const inScope = (target: string, page: string) => page === target || page.startsWith(`${target}/`);

export interface FindingFilter {
  status: Status;
  severity?: Severity[];
  q?: string;
  targetId?: string;
}

interface FindingRow {
  target_id: string;
  target_name: string;
  fingerprint: string;
  engine: string;
  rule_id: string;
  severity: Severity;
  url: string;
  param: string | null;
  message: string;
  evidence: string | null;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  triage: Triage;
  reason: string | null;
  triaged_by: string | null;
  triaged_at: string | null;
  expires_at: string | null;
}

export interface DastOptions {
  /** Scans, and fixed findings nobody triaged, older than this are deleted (ADR 0015). */
  retentionDays?: number;
  /** Fetches the proof of ownership. Tests replace it. */
  verifier?: Verifier;
}

export function createDast(db: DatabaseSync, { retentionDays = 365, verifier = fetchProof }: DastOptions = {}) {
  // Triage that has not expired. A finding whose acceptance ran out is open again.
  const SUPPRESSED = `(triage <> 'open' AND (expires_at IS NULL OR expires_at > ?))`;

  const targetRow = (id: string) => {
    const r = db.prepare("SELECT * FROM targets WHERE id = ?").get(id) as Record<string, any> | undefined;
    if (!r) throw notFound("The target");
    return r;
  };

  function openCounts(targetId?: string): Counts {
    const c = zero();
    const rows = db
      .prepare(
        `SELECT severity, COUNT(*) AS n FROM findings WHERE resolved_at IS NULL AND NOT ${SUPPRESSED} ${targetId ? "AND target_id = ?" : ""} GROUP BY severity`,
      )
      .all(...([now(), ...(targetId ? [targetId] : [])] as SQLInputValue[])) as Array<{ severity: Severity; n: number }>;
    for (const r of rows) c[r.severity] = r.n;
    return c;
  }

  function presentTarget(t: Record<string, any>) {
    const last = db
      .prepare("SELECT created_at, engine, new_count, blocking FROM scans WHERE target_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1")
      .get(t.id) as Record<string, any> | undefined;
    const suppressed = (
      db.prepare(`SELECT COUNT(*) AS n FROM findings WHERE target_id = ? AND resolved_at IS NULL AND ${SUPPRESSED}`).get(t.id, now()) as { n: number }
    ).n;
    const verified = t.verified_at !== null;
    return {
      id: t.id as string,
      name: t.name as string,
      url: t.url as string,
      production: t.production === 1,
      failOn: t.fail_on as FailOn,
      verified,
      verifiedAt: (t.verified_at as string | null) ?? null,
      // Shown until the target is verified. Knowing it proves nothing; serving it from the target does.
      verification: verified
        ? null
        : { method: "file" as const, url: `${t.url.replace(/^(https?:\/\/[^/]+).*$/, "$1")}${VERIFY_PATH}`, content: t.verify_token as string },
      open: openCounts(t.id),
      suppressed,
      lastScan: last ? { at: last.created_at as string, engine: last.engine as string, new: last.new_count as number, passed: last.blocking === 0 } : null,
      schedule: t.schedule as "none" | "daily" | "weekly",
      scheduleProfile: t.schedule_profile as "passive" | "standard" | "full",
      nextScanAt: (t.next_scan_at as string | null) ?? null,
      createdAt: t.created_at as string,
    };
  }

  function presentFinding(f: FindingRow) {
    const active = f.triage !== "open" && (!f.expires_at || f.expires_at > now());
    return {
      target: { id: f.target_id, name: f.target_name },
      fingerprint: f.fingerprint,
      engine: f.engine,
      rule: f.rule_id,
      severity: f.severity,
      url: f.url,
      param: f.param,
      message: f.message,
      evidence: f.evidence,
      firstSeen: f.first_seen,
      lastSeen: f.last_seen,
      resolvedAt: f.resolved_at,
      triage:
        f.triage === "open"
          ? null
          : { state: f.triage as Exclude<Triage, "open">, reason: f.reason!, by: f.triaged_by, at: f.triaged_at, expiresAt: f.expires_at, active },
    };
  }

  function findingsQuery(filter: FindingFilter, cursor: string | undefined, limit: number) {
    const where: string[] = [];
    const args: SQLInputValue[] = [];
    const at = `'${now()}'`;
    if (filter.status === "resolved") where.push("f.resolved_at IS NOT NULL");
    else {
      where.push("f.resolved_at IS NULL");
      where.push(filter.status === "suppressed" ? SUPPRESSED.replace("?", at) : `NOT ${SUPPRESSED.replace("?", at)}`);
    }
    if (filter.targetId) (where.push("f.target_id = ?"), args.push(filter.targetId));
    if (filter.severity?.length) (where.push(`f.severity IN (${filter.severity.map(() => "?").join(",")})`), args.push(...filter.severity));
    if (filter.q) {
      const like = `%${filter.q.replace(/[\\%_]/g, "\\$&")}%`;
      where.push("(f.rule_id LIKE ? ESCAPE '\\' OR f.url LIKE ? ESCAPE '\\' OR f.message LIKE ? ESCAPE '\\')");
      args.push(like, like, like);
    }
    const offset = decodeCursor(cursor);
    const rows = db
      .prepare(
        `SELECT f.*, t.name AS target_name FROM findings f JOIN targets t ON t.id = f.target_id WHERE ${where.join(" AND ")}
         ORDER BY ${RANK_SQL.replaceAll("severity", "f.severity")} DESC, f.first_seen DESC, f.fingerprint LIMIT ? OFFSET ?`,
      )
      .all(...args, limit + 1, offset) as unknown as FindingRow[];
    return {
      items: rows.slice(0, limit).map(presentFinding),
      ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }),
    } satisfies Page<unknown>;
  }

  function presentScan(s: Record<string, any>, targetName: string) {
    return {
      id: s.id as string,
      target: { id: s.target_id as string, name: targetName },
      engine: s.engine as string,
      tool: s.tool as string,
      total: s.total as number,
      new: s.new_count as number,
      resolved: s.resolved as number,
      suppressed: s.suppressed as number,
      ignored: s.ignored as number,
      blocking: s.blocking as number,
      failOn: s.fail_on as FailOn,
      passed: s.blocking === 0,
      createdAt: s.created_at as string,
    };
  }

  const failOnOf = (value: unknown): FailOn => {
    if (typeof value !== "string" || !FAIL_ON.includes(value as FailOn)) throw bad(`failOn must be one of ${FAIL_ON.join(", ")}.`);
    return value as FailOn;
  };

  return {
    createTarget(body: Record<string, unknown>) {
      const { name, url, production = false, failOn = "high", ...rest } = body;
      if (Object.keys(rest).length || typeof name !== "string" || !NAME.test(name))
        throw bad("Expected { name, url, production?, failOn? }; name is up to 64 letters, digits, . _ and -.");
      if (typeof production !== "boolean") throw bad("production must be true or false.");
      const address = targetUrl(url);
      if (db.prepare("SELECT 1 FROM targets WHERE name = ? OR url = ?").get(name, address))
        throw new DastError(409, "conflict", "A target with this name or address exists.");
      const id = randomUUID();
      db.prepare("INSERT INTO targets (id, name, url, production, fail_on, verify_token, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(
        id,
        name,
        address,
        production ? 1 : 0,
        failOnOf(failOn),
        `openasy-dast-${randomBytes(16).toString("hex")}`,
        now(),
      );
      return presentTarget(targetRow(id));
    },

    listTargets(cursor: string | undefined, limit: number): Page<ReturnType<typeof presentTarget>> {
      const offset = decodeCursor(cursor);
      const rows = db.prepare("SELECT * FROM targets ORDER BY name LIMIT ? OFFSET ?").all(limit + 1, offset) as Array<Record<string, any>>;
      return { items: rows.slice(0, limit).map(presentTarget), ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) };
    },

    target: (id: string) => presentTarget(targetRow(id)),

    updateTarget(id: string, body: Record<string, unknown>) {
      targetRow(id);
      const { production, failOn, ...rest } = body;
      if (Object.keys(rest).length || (production === undefined && failOn === undefined)) throw bad("Expected { production?, failOn? }.");
      if (production !== undefined) {
        if (typeof production !== "boolean") throw bad("production must be true or false.");
        db.prepare("UPDATE targets SET production = ? WHERE id = ?").run(production ? 1 : 0, id);
      }
      if (failOn !== undefined) db.prepare("UPDATE targets SET fail_on = ? WHERE id = ?").run(failOnOf(failOn), id);
      return presentTarget(targetRow(id));
    },

    deleteTarget(id: string) {
      if (db.prepare("DELETE FROM targets WHERE id = ?").run(id).changes === 0) throw notFound("The target");
    },

    /** Asks the target for the proof. A target that answers with its secret belongs to whoever can change its files. */
    async verify(id: string) {
      const t = targetRow(id);
      if (t.verified_at === null) {
        let answer: string;
        try {
          answer = await verifier(new URL(t.url).origin);
        } catch (err) {
          throw new DastError(422, "verification-failed", `Could not read the proof: ${(err as Error).message}`);
        }
        if (answer.trim() !== t.verify_token)
          throw new DastError(422, "verification-failed", `${new URL(VERIFY_PATH, t.url).href} does not hold the verification content.`);
        db.prepare("UPDATE targets SET verified_at = ? WHERE id = ?").run(now(), id);
      }
      return presentTarget(targetRow(id));
    },

    /**
     * Takes a SARIF report from ZAP, Nuclei or another scanner. Findings outside the target's address are left out.
     * What the same engine reported before and does not report now is fixed. The first report of an engine for a
     * target adopts what is there; later ones fail a check for new findings at or above the target's failOn.
     */
    ingest(params: { target: string | null; engine: string | null }, raw: Buffer) {
      const name = params.target;
      if (!name || !NAME.test(name)) throw bad("target is required: the name of a target.");
      const target = db.prepare("SELECT * FROM targets WHERE name = ?").get(name) as Record<string, any> | undefined;
      if (!target) throw notFound("The target");
      if (params.engine && !ENGINE.test(params.engine)) throw bad("engine is lowercase letters, digits and -, up to 32.");

      let body: unknown;
      try {
        body = JSON.parse(raw.toString("utf8"));
      } catch {
        throw new DastError(422, "invalid-sarif", "The body is not JSON.");
      }
      let parsed: ReturnType<typeof parseSarif>;
      try {
        parsed = parseSarif(body);
      } catch (err) {
        if (err instanceof SarifError) throw new DastError(422, "invalid-sarif", err.message);
        throw err;
      }
      const engine = params.engine || (parsed.tool.toLowerCase().match(/[a-z0-9]+/)?.[0] ?? "other").slice(0, 32);
      const kept = parsed.findings.filter((f) => inScope(target.url, f.url));
      const ignored = parsed.findings.length - kept.length + parsed.skipped;

      const at = now();
      const id = randomUUID();
      const failOn = target.fail_on as FailOn;
      db.exec("BEGIN IMMEDIATE");
      try {
        const known = new Map<string, { resolved_at: string | null; triage: Triage; expires_at: string | null }>();
        for (const r of db
          .prepare("SELECT fingerprint, resolved_at, triage, expires_at FROM findings WHERE target_id = ? AND engine = ?")
          .all(target.id, engine) as Array<{ fingerprint: string; resolved_at: string | null; triage: Triage; expires_at: string | null }>)
          known.set(r.fingerprint, r);
        const first = !db.prepare("SELECT 1 FROM scans WHERE target_id = ? AND engine = ?").get(target.id, engine);
        const triaged = (f: Finding) => {
          const k = known.get(f.fingerprint);
          return !!k && k.triage !== "open" && (!k.expires_at || k.expires_at > at);
        };
        const fresh = kept.filter((f) => !known.has(f.fingerprint) || known.get(f.fingerprint)!.resolved_at !== null);
        const added = fresh.filter((f) => !triaged(f));
        const blocking = failOn === "none" || first ? 0 : added.filter((f) => RANK[f.severity] >= RANK[failOn]).length;

        const upsert = db.prepare(
          `INSERT INTO findings (target_id, fingerprint, engine, rule_id, severity, url, param, message, evidence, first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (target_id, fingerprint) DO UPDATE SET severity = excluded.severity, message = excluded.message, evidence = excluded.evidence, last_seen = excluded.last_seen,
             first_seen = CASE WHEN findings.resolved_at IS NULL THEN findings.first_seen ELSE excluded.first_seen END, resolved_at = NULL`,
        );
        for (const f of kept) upsert.run(target.id, f.fingerprint, engine, f.ruleId, f.severity, f.url, f.param, f.message, f.evidence, at, at);
        const resolved = db
          .prepare("UPDATE findings SET resolved_at = ? WHERE target_id = ? AND engine = ? AND resolved_at IS NULL AND last_seen < ?")
          .run(at, target.id, engine, at).changes as number;

        db.prepare(
          "INSERT INTO scans (id, target_id, engine, tool, total, new_count, resolved, suppressed, ignored, blocking, fail_on, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).run(id, target.id, engine, parsed.tool, kept.length, added.length, resolved, fresh.length - added.length, ignored, blocking, failOn, at);
        db.exec("COMMIT");
        return {
          ...presentScan(db.prepare("SELECT * FROM scans WHERE id = ?").get(id) as Record<string, any>, name),
          findings: added
            .sort((a, b) => RANK[b.severity] - RANK[a.severity])
            .slice(0, SCAN_FINDINGS_IN_ANSWER)
            .map((f) => ({ fingerprint: f.fingerprint, rule: f.ruleId, severity: f.severity, url: f.url, param: f.param, message: f.message })),
        };
      } catch (err) {
        db.exec("ROLLBACK");
        throw err;
      }
    },

    summary() {
      const targets = (db.prepare("SELECT COUNT(*) AS n FROM targets").get() as { n: number }).n;
      const verified = (db.prepare("SELECT COUNT(*) AS n FROM targets WHERE verified_at IS NOT NULL").get() as { n: number }).n;
      const suppressed = (db.prepare(`SELECT COUNT(*) AS n FROM findings WHERE resolved_at IS NULL AND ${SUPPRESSED}`).get(now()) as { n: number }).n;
      const week = new Date(Date.now() - 7 * 86_400_000).toISOString();
      const failing = (db.prepare("SELECT COUNT(*) AS n FROM scans WHERE blocking > 0 AND created_at > ?").get(week) as { n: number }).n;
      const lastScanAt = (db.prepare("SELECT MAX(created_at) AS t FROM scans").get() as { t: string | null }).t;
      return { targets, verified, open: openCounts(), suppressed, failingChecks: failing, lastScanAt };
    },

    severityTotals: () => openCounts(),
    targetCount: () => (db.prepare("SELECT COUNT(*) AS n FROM targets").get() as { n: number }).n,
    suppressedCount: () => (db.prepare(`SELECT COUNT(*) AS n FROM findings WHERE resolved_at IS NULL AND ${SUPPRESSED}`).get(now()) as { n: number }).n,

    findings(filter: FindingFilter, cursor: string | undefined, limit: number) {
      if (filter.targetId) targetRow(filter.targetId);
      return findingsQuery(filter, cursor, limit);
    },

    scans(targetId: string, cursor: string | undefined, limit: number) {
      const t = targetRow(targetId);
      const offset = decodeCursor(cursor);
      const rows = db
        .prepare("SELECT * FROM scans WHERE target_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?")
        .all(targetId, limit + 1, offset) as Array<Record<string, any>>;
      return {
        items: rows.slice(0, limit).map((s) => presentScan(s, t.name)),
        ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }),
      } satisfies Page<unknown>;
    },

    scan(id: string) {
      const s = db.prepare("SELECT s.*, t.name AS target_name FROM scans s JOIN targets t ON t.id = s.target_id WHERE s.id = ?").get(id) as
        Record<string, any> | undefined;
      if (!s) throw notFound("The scan");
      return presentScan(s, s.target_name);
    },

    /** Sets or clears the triage of one finding. It stays with the finding across scans. */
    triage(targetId: string, fingerprint: string, body: Record<string, unknown>, by: string) {
      targetRow(targetId);
      const { state, reason, expiresAt, ...rest } = body;
      if (Object.keys(rest).length || typeof state !== "string" || !TRIAGE.includes(state as Triage))
        throw bad(`Expected { state, reason?, expiresAt? }; state is one of ${TRIAGE.join(", ")}.`);
      if (!db.prepare("SELECT 1 FROM findings WHERE target_id = ? AND fingerprint = ?").get(targetId, fingerprint)) throw notFound("The finding");
      if (state === "open") {
        db.prepare(
          "UPDATE findings SET triage = 'open', reason = NULL, triaged_by = NULL, triaged_at = NULL, expires_at = NULL WHERE target_id = ? AND fingerprint = ?",
        ).run(targetId, fingerprint);
      } else {
        // A decision without a reason is lost the day its author leaves (ADR 0037).
        if (typeof reason !== "string" || reason.trim().length < 3 || reason.length > 500) throw bad("reason is required: 3 to 500 characters.");
        let expires: string | null = null;
        if (expiresAt !== undefined && expiresAt !== null) {
          const t = typeof expiresAt === "string" ? Date.parse(expiresAt) : NaN;
          if (Number.isNaN(t) || t <= Date.now()) throw bad("expiresAt must be a date in the future.");
          if (t > Date.now() + MAX_ACCEPT_DAYS * 86_400_000) throw bad(`expiresAt must be within ${MAX_ACCEPT_DAYS} days.`);
          expires = new Date(t).toISOString();
        }
        // Accepted risk always ends; a false positive does not need to.
        if (state === "accepted" && !expires) throw bad("expiresAt is required for accepted risk.");
        db.prepare("UPDATE findings SET triage = ?, reason = ?, triaged_by = ?, triaged_at = ?, expires_at = ? WHERE target_id = ? AND fingerprint = ?").run(
          state,
          reason.trim(),
          by,
          now(),
          expires,
          targetId,
          fingerprint,
        );
      }
      const row = db
        .prepare("SELECT f.*, t.name AS target_name FROM findings f JOIN targets t ON t.id = f.target_id WHERE f.target_id = ? AND f.fingerprint = ?")
        .get(targetId, fingerprint) as unknown as FindingRow;
      return presentFinding(row);
    },

    purge() {
      const before = new Date(Date.now() - retentionDays * 86_400_000).toISOString();
      db.prepare("DELETE FROM scans WHERE created_at < ?").run(before);
      db.prepare("DELETE FROM findings WHERE resolved_at IS NOT NULL AND resolved_at < ? AND triage = 'open'").run(before);
    },
  };
}

export type Dast = ReturnType<typeof createDast>;
export { SEVERITIES };
