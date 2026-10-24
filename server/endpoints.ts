// The install's endpoints from a file, the same file for every product that watches endpoints (ADR 0052). Each product
// reads what it needs: Uptime checks every entry, Certificates reads the certificate of https:// and tls:// ones, and
// DAST scans the ones with a dast block. This file is the same in each of those products; keep the copies in step
// (test/endpoints.yaml is shared too).
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { parse } from "yaml";

export type EndpointKind = "http" | "tcp" | "dns" | "tls";

export interface Endpoint {
  /** Unique in the file, and how the entry is found again when the file changes. */
  name: string;
  /** As written, without a trailing slash on a bare origin. */
  url: string;
  kind: EndpointKind;
  host: string;
  /** The port the scheme implies when none is written: 80, 443 for https:// and tls://; null for dns://. */
  port: number | null;
  group: string | null;
  /** The server it runs on: a name from the hosts file (OPENASY_HOSTS), not checked here. */
  server: string | null;
  public: boolean;
  everySeconds: number | null;
  /** Left to each product to check: Uptime knows which keys a kind takes. */
  expect: Record<string, unknown>;
  tags: string[];
  /** How many failed checks in a row make it down, 1 to 10; Uptime's. */
  failures: number | null;
  /** What DAST scans it with, when it is a DAST target; left to DAST to check. */
  dast: Record<string, unknown> | null;
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;
const SERVER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
const KEYS = ["name", "url", "group", "server", "public", "every", "expect", "tags", "failures", "dast"];
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** "90s", "5m", "1h" or a number of seconds. */
function seconds(v: unknown, at: string): number {
  const m = typeof v === "number" ? [String(v), String(v), "s"] : typeof v === "string" ? /^(\d+)\s*(s|m|h)?$/.exec(v.trim()) : null;
  const n = m ? Number(m[1]) * (m[2] === "h" ? 3600 : m[2] === "m" ? 60 : 1) : NaN;
  if (!Number.isInteger(n) || n < 30 || n > 86_400) throw new Error(`${at}.every is 30s to 24h, such as 1m or 5m.`);
  return n;
}

function address(raw: string, at: string): Pick<Endpoint, "url" | "kind" | "host" | "port"> {
  const url = URL.parse(raw);
  const scheme = url?.protocol.slice(0, -1);
  if (!url || !url.hostname || !["http", "https", "tcp", "dns", "tls"].includes(scheme!)) {
    throw new Error(`${at}.url must start with https://, http://, tcp://, dns:// or tls://, such as https://www.example.com.`);
  }
  if (url.username || url.password) throw new Error(`${at}.url must not hold a user name or password: they would be shown to runners and in logs.`);
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const port = url.port ? Number(url.port) : scheme === "http" ? 80 : scheme === "https" || scheme === "tls" ? 443 : null;
  if (scheme === "tcp" && !url.port) throw new Error(`${at}.url: a tcp:// address needs a port, such as tcp://db.example.com:5432.`);
  if (scheme === "dns" && (url.port || (url.pathname && url.pathname !== "/")))
    throw new Error(`${at}.url: a dns:// address is a name only, such as dns://www.example.com.`);
  if ((scheme === "tcp" || scheme === "tls") && url.pathname && url.pathname !== "/") throw new Error(`${at}.url: a ${scheme}:// address is host:port only.`);
  const kind: EndpointKind = scheme === "https" ? "http" : (scheme as EndpointKind);
  return { url: kind === "http" ? url.href : `${scheme}://${url.host}`, kind, host, port };
}

/** Reads the file's text. Throws with the entry and field at fault, so one message says what to fix. */
export function parseEndpoints(text: string): Endpoint[] {
  let doc: unknown;
  try {
    doc = parse(text);
  } catch (err) {
    throw new Error(`Not valid YAML: ${(err as Error).message.split("\n")[0]}`);
  }
  if (doc === null || doc === undefined) return [];
  if (!isObj(doc) || Object.keys(doc).some((k) => k !== "endpoints")) throw new Error("The file holds one list, endpoints:, and nothing else.");
  const list = doc.endpoints ?? [];
  if (!Array.isArray(list)) throw new Error("endpoints must be a list.");
  if (list.length > 2000) throw new Error("endpoints holds at most 2000 entries.");
  const seen = new Set<string>();
  return list.map((e, i) => {
    const at = `endpoints[${i}]`;
    if (!isObj(e)) throw new Error(`${at} must be a map with at least name and url.`);
    const extra = Object.keys(e).filter((k) => !KEYS.includes(k));
    if (extra.length) throw new Error(`${at}: unknown ${extra.join(", ")}; an entry takes ${KEYS.join(", ")}.`);
    if (typeof e.name !== "string" || !NAME.test(e.name.trim())) throw new Error(`${at}.name is required: up to 64 letters, digits, spaces and . _ -.`);
    const name = e.name.trim();
    if (seen.has(name.toLowerCase())) throw new Error(`${at}.name: ${name} is in the file twice.`);
    seen.add(name.toLowerCase());
    const where = `${at} (${name})`;
    if (typeof e.url !== "string" || e.url.length > 512) throw new Error(`${where}.url is required.`);
    if (e.group !== undefined && e.group !== null && (typeof e.group !== "string" || e.group.length > 64 || /[\x00-\x1f<>]/.test(e.group)))
      throw new Error(`${where}.group is a name of up to 64 characters.`);
    if (e.server !== undefined && e.server !== null && (typeof e.server !== "string" || !SERVER.test(e.server)))
      throw new Error(`${where}.server is a name from the hosts file: letters, digits, dots, dashes and underscores, up to 63.`);
    if (e.public !== undefined && typeof e.public !== "boolean") throw new Error(`${where}.public is true or false.`);
    if (e.expect !== undefined && !isObj(e.expect)) throw new Error(`${where}.expect is a map, such as { status: 200 }.`);
    if (e.failures !== undefined && (!Number.isInteger(e.failures) || (e.failures as number) < 1 || (e.failures as number) > 10))
      throw new Error(`${where}.failures is a whole number from 1 to 10.`);
    if (e.dast !== undefined && !isObj(e.dast)) throw new Error(`${where}.dast is a map, such as { schedule: weekly }.`);
    if (
      e.tags !== undefined &&
      (!Array.isArray(e.tags) || e.tags.length > 8 || e.tags.some((t) => typeof t !== "string" || !/^[A-Za-z0-9._:-]{1,32}$/.test(t)))
    ) {
      throw new Error(`${where}.tags is up to 8 short words of letters, digits and . _ : -.`);
    }
    return {
      name,
      ...address(e.url.trim(), where),
      group: typeof e.group === "string" && e.group.trim() ? e.group.trim() : null,
      server: typeof e.server === "string" ? e.server : null,
      public: e.public === true,
      everySeconds: e.every === undefined ? null : seconds(e.every, where),
      expect: (e.expect as Record<string, unknown> | undefined) ?? {},
      tags: [...new Set((e.tags as string[] | undefined) ?? [])],
      failures: (e.failures as number | undefined) ?? null,
      dast: (e.dast as Record<string, unknown> | undefined) ?? null,
    };
  });
}

/** A file entry's id: the same for the same name, and safe in a URL. */
export const fileId = (name: string) => `file-${createHash("sha256").update(name.toLowerCase()).digest("hex").slice(0, 16)}`;

export interface EndpointsFileState {
  path: string;
  /** When the file was last read and applied, or null if it never was. */
  appliedAt: string | null;
  entries: number;
  /** Why the file on disk is not what is applied; the last good list stays until it is fixed. */
  error: string | null;
  /** Things to fix that did not stop the file from being applied. */
  warnings: string[];
}

/**
 * Reads the file now and whenever it changes (checked every `everyMs`, by size, time and content), and hands each new
 * list to `apply`, which returns warnings or throws to refuse it. A file that cannot be read or applied leaves the last
 * good list in place. `stop()` ends the polling.
 */
export function watchEndpoints(
  path: string,
  apply: (endpoints: Endpoint[]) => string[],
  { everyMs = 60_000, onChange }: { everyMs?: number; onChange?: (state: EndpointsFileState) => void } = {},
) {
  const state: EndpointsFileState = { path, appliedAt: null, entries: 0, error: null, warnings: [] };
  let seen = "";
  const read = () => {
    let text: string;
    let stamp: string;
    try {
      const st = statSync(path);
      text = readFileSync(path, "utf8");
      stamp = `${st.size}:${st.mtimeMs}:${createHash("sha256").update(text).digest("hex")}`;
    } catch (err) {
      const error = `Cannot read ${path}: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}`;
      if (state.error !== error) ((state.error = error), onChange?.(state));
      return;
    }
    if (stamp === seen) return;
    seen = stamp;
    try {
      const endpoints = parseEndpoints(text);
      state.warnings = apply(endpoints);
      Object.assign(state, { appliedAt: new Date().toISOString(), entries: endpoints.length, error: null });
    } catch (err) {
      state.error = (err as Error).message;
    }
    onChange?.(state);
  };
  read();
  const timer = setInterval(read, everyMs);
  timer.unref();
  return { state, read, stop: () => clearInterval(timer) };
}
