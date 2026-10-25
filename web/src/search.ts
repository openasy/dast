// What the search window (Cmd+K) finds in DAST: targets by name, and open findings by rule, address or message, from the API.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { Bug, Globe } from "lucide-react";
import type { Finding, Target } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const [list, found] = await Promise.all([
      call<{ targets: Target[] }>("/api/v1/targets?limit=500", { signal }),
      call<{ findings: Finding[] }>(`/api/v1/findings?${new URLSearchParams({ q, limit: "8" })}`, { signal }),
    ]);
    const named: SearchResult[] = list.targets
      .filter((e) => e.name.toLowerCase().includes(q))
      .slice(0, 6)
      .map((e) => ({
        id: `target:${e.id}`,
        label: e.name,
        detail: e.url,
        kind: t("search.target"),
        icon: Globe,
        mono: false,
        href: `/targets/${encodeURIComponent(e.id)}`,
      }));
    const findings: SearchResult[] = found.findings.map((f) => ({
      id: `finding:${f.target.id}:${f.fingerprint}`,
      label: f.message,
      detail: `${f.url} · ${f.target.name}`,
      kind: t("search.finding"),
      icon: Bug,
      severity: f.severity,
      mono: false,
      href: `/targets/${encodeURIComponent(f.target.id)}`,
    }));
    return [...named, ...findings];
  };
}
