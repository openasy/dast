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
