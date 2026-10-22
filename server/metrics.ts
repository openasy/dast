// Prometheus text exposition, written by hand: a few lines, no client library needed.
const requests = new Map<string, number>();

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

export interface Gauges {
  targets: number;
  verified: number;
  /** Open findings by severity, without triaged ones. */
  findings: Record<string, number>;
  suppressed: number;
  /** Reports of the last 7 days that failed their check. */
  failingChecks: number;
}

export function renderMetrics(version: string, g: Gauges): string {
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="dast",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    "# HELP openasy_dast_targets Targets that may be tested.",
    "# TYPE openasy_dast_targets gauge",
    `openasy_dast_targets ${g.targets}`,
    "# HELP openasy_dast_verified_targets Targets whose owner has proven the address is theirs.",
    "# TYPE openasy_dast_verified_targets gauge",
    `openasy_dast_verified_targets ${g.verified}`,
    "# HELP openasy_dast_open_findings Open findings by severity, without triaged ones.",
    "# TYPE openasy_dast_open_findings gauge",
    ...Object.entries(g.findings).map(([s, n]) => `openasy_dast_open_findings{severity="${s}"} ${n}`),
    "# HELP openasy_dast_suppressed_findings Open findings that someone marked as a false positive or accepted risk.",
    "# TYPE openasy_dast_suppressed_findings gauge",
    `openasy_dast_suppressed_findings ${g.suppressed}`,
    "# HELP openasy_dast_failing_checks Reports of the last 7 days that failed their check.",
    "# TYPE openasy_dast_failing_checks gauge",
    `openasy_dast_failing_checks ${g.failingChecks}`,
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
