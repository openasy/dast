import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones.
const MIGRATIONS = [
  `CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
   -- An address that may be tested. Nothing is attacked until the owner of the address has proven it is theirs
   -- (verified_at), and a production target is never given a full scan without an admin's say (ADR 0037).
   CREATE TABLE targets (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL UNIQUE,
     url TEXT NOT NULL UNIQUE,
     production INTEGER NOT NULL DEFAULT 0,
     fail_on TEXT NOT NULL CHECK (fail_on IN ('critical', 'high', 'medium', 'low', 'none')),
     verify_token TEXT NOT NULL,
     verified_at TEXT,
     created_at TEXT NOT NULL
   );
   -- One row per report. A report is what one engine found over the target; it replaces that engine's view of it.
   CREATE TABLE scans (
     id TEXT PRIMARY KEY,
     target_id TEXT NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
     engine TEXT NOT NULL,
     tool TEXT NOT NULL,
     total INTEGER NOT NULL,
     new_count INTEGER NOT NULL,
     resolved INTEGER NOT NULL,
     suppressed INTEGER NOT NULL,
     ignored INTEGER NOT NULL,
     blocking INTEGER NOT NULL,
     fail_on TEXT NOT NULL,
     created_at TEXT NOT NULL
   );
   CREATE INDEX scans_target ON scans (target_id, created_at DESC);
   -- One row per finding of a target, found again by its fingerprint. A row an engine stops reporting gets
   -- resolved_at and opens again if the same finding comes back. Triage stays on the row.
   CREATE TABLE findings (
     target_id TEXT NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
     fingerprint TEXT NOT NULL,
     engine TEXT NOT NULL,
     rule_id TEXT NOT NULL,
     severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
     url TEXT NOT NULL,
     param TEXT,
     message TEXT NOT NULL,
     evidence TEXT,
     first_seen TEXT NOT NULL,
     last_seen TEXT NOT NULL,
     resolved_at TEXT,
     triage TEXT NOT NULL DEFAULT 'open' CHECK (triage IN ('open', 'false-positive', 'accepted')),
     reason TEXT,
     triaged_by TEXT,
     triaged_at TEXT,
     expires_at TEXT,
     PRIMARY KEY (target_id, fingerprint)
   );
   CREATE INDEX findings_open ON findings (target_id, severity) WHERE resolved_at IS NULL`,
  // dast-agent runs ZAP and Nuclei where the targets are (ADR 0037): agents enrol with a one-time token, and scans
  // started by hand or by a target's schedule wait in a queue for them. A verify job reads the proof of a target on a
  // private address, which dast itself cannot reach.
  `CREATE TABLE agents (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL UNIQUE,
     enroll_token_hash TEXT,
     enroll_expires_at TEXT,
     secret_hash TEXT,
     version TEXT,
     last_seen TEXT,
     created_at TEXT NOT NULL
   );
   CREATE TABLE scan_jobs (
     id TEXT PRIMARY KEY,
     target_id TEXT NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
     kind TEXT NOT NULL CHECK (kind IN ('scan', 'verify')),
     profile TEXT CHECK (profile IN ('passive', 'standard', 'full')),
     status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'done', 'failed')),
     agent_id TEXT REFERENCES agents (id) ON DELETE SET NULL,
     lease_until TEXT,
     attempts INTEGER NOT NULL DEFAULT 0,
     error TEXT,
     requested_by TEXT NOT NULL,
     created_at TEXT NOT NULL,
     finished_at TEXT
   );
   CREATE INDEX scan_jobs_queue ON scan_jobs (status, created_at);
   CREATE INDEX scan_jobs_target ON scan_jobs (target_id, created_at DESC);
   ALTER TABLE targets ADD COLUMN schedule TEXT NOT NULL DEFAULT 'none' CHECK (schedule IN ('none', 'daily', 'weekly'));
   ALTER TABLE targets ADD COLUMN schedule_profile TEXT NOT NULL DEFAULT 'standard' CHECK (schedule_profile IN ('passive', 'standard', 'full'));
   ALTER TABLE targets ADD COLUMN next_scan_at TEXT;`,
  // Auth profiles: how a scan gets past a target's login (ADR 0037). The secret, a header value or a password, is
  // sealed with openasy-kek and sent only to the agent running a scan that uses it.
  `CREATE TABLE auth_profiles (
     id TEXT PRIMARY KEY,
     target_id TEXT NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
     name TEXT NOT NULL,
     kind TEXT NOT NULL CHECK (kind IN ('header', 'form')),
     header_name TEXT,
     login_url TEXT,
     username_field TEXT,
     password_field TEXT,
     username TEXT,
     logged_in_regex TEXT,
     secret TEXT NOT NULL,
     created_at TEXT NOT NULL,
     UNIQUE (target_id, name)
   );
   ALTER TABLE scan_jobs ADD COLUMN auth_profile_id TEXT REFERENCES auth_profiles (id) ON DELETE SET NULL;`,
  // Targets come from the endpoints file (ADR 0052); ones added in the UI before stay until the file takes them over.
  `ALTER TABLE targets ADD COLUMN source TEXT NOT NULL DEFAULT 'ui' CHECK (source IN ('ui', 'file'));`,
];

/** Opens the product's single SQLite file in WAL mode (ADR 0011) and migrates it forward. */
export function openDb(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  for (let v = row.v; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
