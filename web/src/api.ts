// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json.

export type Severity = "critical" | "high" | "medium" | "low";
export type FailOn = Severity | "none";
export type Counts = Record<Severity, number>;

/** Another OpenAsy product of this install, from OPENASY_PRODUCTS. */
export interface ProductLink {
  id: string;
  url: string;
}

export interface Summary {
  targets: number;
  verified: number;
  open: Counts;
  suppressed: number;
  failingChecks: number;
  lastScanAt: string | null;
}

export interface Target {
  id: string;
  name: string;
  url: string;
  production: boolean;
  failOn: FailOn;
  verified: boolean;
  verifiedAt: string | null;
  verification: { method: "file"; url: string; content: string } | null;
  open: Counts;
  suppressed: number;
  lastScan: { at: string; engine: string; new: number; passed: boolean } | null;
  createdAt: string;
  schedule: Schedule;
  scheduleProfile: Profile;
  nextScanAt: string | null;
}

/** How a scan gets past the target's login; the secret never comes back. */
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

/** passive sends no attacks; standard and full need a verified target (ADR 0037). */
export type Profile = "passive" | "standard" | "full";
export type Schedule = "none" | "daily" | "weekly";

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
  authProfile: string | null;
  requestedBy: string;
  createdAt: string;
  finishedAt: string | null;
}

export interface TriageState {
  state: "false-positive" | "accepted";
  reason: string;
  by: string | null;
  at: string | null;
  expiresAt: string | null;
  active: boolean;
}

export interface Finding {
  target: { id: string; name: string };
  fingerprint: string;
  engine: string;
  rule: string;
  severity: Severity;
  url: string;
  param: string | null;
  message: string;
  evidence: string | null;
  firstSeen: string;
  lastSeen: string;
  resolvedAt: string | null;
  triage: TriageState | null;
}

export interface Scan {
  id: string;
  target: { id: string; name: string };
  engine: string;
  tool: string;
  total: number;
  new: number;
  resolved: number;
  suppressed: number;
  ignored: number;
  blocking: number;
  failOn: FailOn;
  passed: boolean;
  createdAt: string;
}

export class Unauthorized extends Error {}
/** The signed-in owner or admin has no second factor yet; the sign-in gate asks for one. */
export class MfaSetupRequired extends Error {}
export class ApiError extends Error {}

// The session is an HttpOnly cookie set by sign-in (@openasy/auth); the browser sends it, nothing is stored here.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers },
  });
  if (!res.ok) {
    const problem = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    if (res.status === 401) throw new Unauthorized(problem.detail);
    if (problem.code === "mfa-setup-required") throw new MfaSetupRequired(problem.detail);
    throw new ApiError(problem.detail ?? `${path}: ${res.status}`);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}
