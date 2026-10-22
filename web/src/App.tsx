import {
  AppShell,
  Badge,
  BrandProvider,
  Button,
  DataTable,
  Dialog,
  EmptyState,
  FacetFilter,
  FilterBar,
  IconButton,
  KpiCard,
  KpiGrid,
  navigate,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  SearchInput,
  SelectField,
  SeverityBadge,
  StatusBadge,
  Tabs,
  TextField,
  usePath,
  type Column,
  type ProductId,
  useThemePreference,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAuth } from "@openasy/auth/react";
import { Bug, CircleSlash, Crosshair, KeyRound, LogIn, LogOut, Plus, Settings2, ShieldCheck, Trash2, UserRound, Users, X } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { api, MfaSetupRequired, Unauthorized, type FailOn, type Finding, type ProductLink, type Scan, type Severity, type Summary, type Target } from "./api.ts";

function ago(iso: string | null | undefined): string {
  if (!iso) return "never";
  const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86_400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86_400)} d ago`;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

const PAGES = ["targets", "setup", "account", "members", "signin", "tokens"] as const;
type Route = { page: "findings" | (typeof PAGES)[number] } | { page: "target"; id: string };
/** The first path segments that are pages of this UI, for followLinks. */
export const PATHS = ["findings", ...PAGES];
function parseRoute(path: string): Route {
  const [page, id] = path.replace(/^\//, "").split("/");
  if (page === "targets" && id) return { page: "target", id: decodeURIComponent(id) };
  if ((PAGES as readonly string[]).includes(page ?? "")) return { page: page as (typeof PAGES)[number] };
  return { page: "findings" };
}

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi() {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await api<T>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}
type Call = ReturnType<typeof useApi>;

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const FAIL_ON: Array<{ value: FailOn; label: string }> = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High or worse" },
  { value: "medium", label: "Medium or worse" },
  { value: "low", label: "Any finding" },
  { value: "none", label: "Never fail" },
];

/** Compact severity counts; each badge carries the full name for screen readers. */
function SevCounts({ counts }: { counts: Record<Severity, number> }) {
  const shown = SEVERITIES.filter((s) => counts[s] > 0);
  if (!shown.length) return <span className="text-xs text-fg-muted">None</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {shown.map((s) => (
        <Badge key={s} tone={s === "low" ? "neutral" : s === "medium" ? "warning" : "danger"}>
          <span className="sr-only">{s} </span>
          {counts[s]}
        </Badge>
      ))}
    </span>
  );
}

function Code({ children }: { children: ReactNode }) {
  return <pre className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs text-fg">{children}</pre>;
}

function FindingPanel({ finding, call, onClose, onChanged }: { finding: Finding; call: Call; onClose: () => void; onChanged: () => void }) {
  const { can } = useAuth();
  const [deciding, setDeciding] = useState(false);
  const [state, setState] = useState<"false-positive" | "accepted">("false-positive");
  const [days, setDays] = useState("90");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string>();
  const close = () => (setDeciding(false), setReason(""), setError(undefined));
  const url = `/api/v1/targets/${finding.target.id}/findings/${finding.fingerprint}`;

  const decide = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await call(url, { method: "PUT", body: JSON.stringify({ state, reason, ...(state === "accepted" && { expiresAt: new Date(Date.now() + Number(days) * 86_400_000).toISOString() }) }) });
      close();
      onChanged();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  const reopen = () => call(url, { method: "PUT", body: JSON.stringify({ state: "open" }) }).then(onChanged, () => {});
  const t = finding.triage;

  return (
    <Panel
      aria-label={`${finding.rule} details`}
      title={<span className="dast-wrap font-mono text-sm">{finding.rule}</span>}
      description={`${finding.target.name} · ${finding.engine}`}
      actions={
        <IconButton label="Close details" size="sm" onClick={onClose}>
          <X />
        </IconButton>
      }
    >
      <div className="flex flex-col gap-3 text-sm">
        <div className="flex flex-wrap items-center gap-1.5">
          <SeverityBadge severity={finding.severity} />
          {finding.param && <Badge mono>param {finding.param}</Badge>}
        </div>
        <span className="dast-wrap font-mono text-xs">{finding.url}</span>
        <p className="m-0 text-fg-muted">{finding.message}</p>
        {finding.evidence && <Code>{finding.evidence}</Code>}
        {t && (
          <div className="flex flex-col gap-1 rounded-md border border-line p-2.5 text-xs">
            <span>
              <StatusBadge tone={t.active ? "success" : "neutral"}>{t.state === "false-positive" ? "False positive" : t.active ? "Accepted risk" : "Acceptance expired"}</StatusBadge>
            </span>
            <span>{t.reason}</span>
            <span className="text-fg-muted">
              {t.by ? `${t.by}, ` : ""}
              {ago(t.at)}
              {t.expiresAt ? `, until ${new Date(t.expiresAt).toLocaleDateString()}` : ""}
            </span>
          </div>
        )}
        {can("editor") && (
          <div className="flex gap-2 border-t border-line pt-3">
            <Button size="sm" icon={<CircleSlash />} onClick={() => setDeciding(true)}>
              {t ? "Change decision" : "Triage"}
            </Button>
            {t && (
              <Button size="sm" onClick={() => void reopen()}>
                Open again
              </Button>
            )}
          </div>
        )}
        <Dialog
          open={deciding}
          onOpenChange={(open) => !open && close()}
          title={`Triage ${finding.rule}`}
          description="The decision stays with this finding across scans, so it does not fail the next check. Say why, for the next review."
          onSubmit={decide}
          footer={
            <>
              <Button type="button" onClick={close}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={reason.trim().length < 3}>
                Save decision
              </Button>
            </>
          }
        >
          <SelectField
            label="Decision"
            value={state}
            onChange={(e) => setState(e.target.value as typeof state)}
            options={[
              { value: "false-positive", label: "False positive" },
              { value: "accepted", label: "Accepted risk" },
            ]}
          />
          <TextField label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} hint="Why, for the next review." error={error} />
          {state === "accepted" && (
            <SelectField
              label="For"
              value={days}
              onChange={(e) => setDays(e.target.value)}
              options={[
                { value: "30", label: "30 days" },
                { value: "90", label: "90 days" },
                { value: "180", label: "180 days" },
                { value: "365", label: "1 year" },
              ]}
            />
          )}
        </Dialog>
      </div>
    </Panel>
  );
}

type Tab = "open" | "suppressed" | "resolved";

/** Findings of every target, or of one when targetId is given. */
function FindingsTable({ call, targetId, summary, reload }: { call: Call; targetId?: string; summary?: { open: Record<Severity, number> }; reload: () => void }) {
  const [tab, setTab] = useState<Tab>("open");
  const [sev, setSev] = useState<string[]>([]);
  const [q, setQ] = useState("");
  const [rows, setRows] = useState<Finding[]>();
  const [more, setMore] = useState<string>();
  const [open, setOpen] = useState<Finding | null>(null);
  const base = targetId ? `/api/v1/targets/${targetId}/findings` : "/api/v1/findings";

  const query = useCallback(
    (cursor?: string) => {
      const p = new URLSearchParams({ status: tab, limit: "200" });
      if (sev.length) p.set("severity", sev.join(","));
      if (q.trim()) p.set("q", q.trim());
      if (cursor) p.set("cursor", cursor);
      return call<{ findings: Finding[]; nextCursor?: string }>(`${base}?${p}`);
    },
    [call, base, tab, sev, q],
  );
  const load = useCallback(() => {
    query().then((r) => (setRows(r.findings), setMore(r.nextCursor)), () => setRows([]));
  }, [query]);
  useEffect(load, [load]);
  const loadMore = () => more && query(more).then((r) => (setRows((x) => [...(x ?? []), ...r.findings]), setMore(r.nextCursor)));

  const columns: Column<Finding>[] = [
    { id: "sev", header: "Severity", width: "104px", cell: (f) => <SeverityBadge severity={f.severity} /> },
    {
      id: "rule",
      header: "Rule",
      width: "30%",
      cell: (f) => (
        <span className="flex min-w-0 flex-col">
          <button type="button" className="dast-wrap self-start text-left font-mono text-xs font-medium text-fg hover:underline">
            {f.rule}
          </button>
          <span className="dast-clamp text-xs text-fg-muted" title={f.message}>
            {f.message}
          </span>
        </span>
      ),
    },
    {
      id: "where",
      header: "Where",
      width: "32%",
      cell: (f) => (
        <span className="dast-wrap font-mono text-xs">
          {f.url.replace(/^https?:\/\//, "")}
          {f.param ? ` (${f.param})` : ""}
        </span>
      ),
    },
    { id: "engine", header: "Engine", cell: (f) => <Badge>{f.engine}</Badge> },
    ...(targetId ? [] : [{ id: "target", header: "Target", cell: (f: Finding) => <span className="text-xs">{f.target.name}</span> } satisfies Column<Finding>]),
    { id: "seen", header: "First seen", sortValue: (f) => f.firstSeen, cell: (f) => <span className="text-xs whitespace-nowrap">{ago(f.firstSeen)}</span> },
  ];

  return (
    <>
      <Tabs<Tab>
        label="Finding views"
        value={tab}
        onChange={setTab}
        items={[
          { value: "open", label: "Open" },
          { value: "suppressed", label: "Triaged" },
          { value: "resolved", label: "Fixed" },
        ]}
      />
      <FilterBar onClear={() => (setSev([]), setQ(""))}>
        <FacetFilter label="Severity" selected={sev} onChange={setSev} options={SEVERITIES.map((s) => ({ value: s, label: s.charAt(0).toUpperCase() + s.slice(1), count: tab === "open" ? summary?.open[s] : undefined }))} />
        <SearchInput label="Search rule, address or message" className="w-64" value={q} onChange={(e) => setQ(e.target.value)} />
      </FilterBar>
      <div className={open ? "grid gap-2.5 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]" : "grid gap-2.5"}>
        <Panel
          title={tab === "open" ? "Open" : tab === "suppressed" ? "False positives and accepted risk" : "Fixed"}
          description="What the scanners found on running applications, most severe first"
          flush
          footer={
            more ? (
              <Button size="sm" onClick={loadMore}>
                Load more
              </Button>
            ) : undefined
          }
        >
          <DataTable
            label="Findings"
            columns={columns}
            rows={rows ?? []}
            loading={!rows}
            getRowId={(f) => `${f.target.id}/${f.fingerprint}`}
            onRowClick={(f) => setOpen(f)}
            activeRowId={open ? `${open.target.id}/${open.fingerprint}` : undefined}
            minWidth={900}
            pageSize={50}
            empty={
              <EmptyState title={tab === "open" ? "No open findings" : tab === "suppressed" ? "Nothing triaged" : "Nothing fixed yet"}>
                {tab === "open" && summary && !Object.values(summary.open).some(Boolean) ? (
                  <>
                    Send a scan report to see findings. See <a href="/setup">Setup</a>.
                  </>
                ) : (
                  "Nothing matches these filters."
                )}
              </EmptyState>
            }
          />
        </Panel>
        {open && (
          <FindingPanel
            finding={open}
            call={call}
            onClose={() => setOpen(null)}
            onChanged={() => {
              setOpen(null);
              load();
              reload();
            }}
          />
        )}
      </div>
    </>
  );
}

function FindingsPage({ call, summary, reload }: { call: Call; summary?: Summary; reload: () => void }) {
  const s = summary;
  return (
    <>
      <PageHeader title="Findings" description={s ? `${plural(s.targets, "target")}, ${s.verified} verified · last report ${ago(s.lastScanAt)}` : undefined} />
      {s && (
        <KpiGrid minWidth={150}>
          <KpiCard label="Critical" value={s.open.critical} footer={<SeverityBadge severity="critical" />} />
          <KpiCard label="High" value={s.open.high} footer={<SeverityBadge severity="high" />} />
          <KpiCard label="Medium" value={s.open.medium} footer={<SeverityBadge severity="medium" />} />
          <KpiCard label="Low" value={s.open.low} footer={<SeverityBadge severity="low" />} />
          <KpiCard label="Failed checks, 7 days" value={s.failingChecks} tone={s.failingChecks ? "warning" : "success"} />
          <KpiCard label="Triaged" value={s.suppressed} tone="info" />
        </KpiGrid>
      )}
      <FindingsTable call={call} summary={s} reload={reload} />
    </>
  );
}

function CheckStatus({ passed }: { passed: boolean }) {
  return passed ? <StatusBadge tone="success">Passed</StatusBadge> : <StatusBadge tone="danger">Failed</StatusBadge>;
}

function VerifiedBadge({ t }: { t: Pick<Target, "verified"> }) {
  return t.verified ? <StatusBadge tone="success">Verified</StatusBadge> : <StatusBadge tone="warning">Not verified</StatusBadge>;
}

function TargetsPage({ call, reload }: { call: Call; reload: () => void }) {
  const { can } = useAuth();
  const [rows, setRows] = useState<Target[]>();
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [address, setAddress] = useState("");
  const [production, setProduction] = useState("no");
  const [error, setError] = useState<string>();
  const load = useCallback(() => void call<{ targets: Target[] }>("/api/v1/targets?limit=500").then((r) => setRows(r.targets), () => setRows([])), [call]);
  useEffect(load, [load]);
  const close = () => (setAdding(false), setName(""), setAddress(""), setProduction("no"), setError(undefined));

  const add = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const t = await call<Target>("/api/v1/targets", { method: "POST", body: JSON.stringify({ name, url: address, production: production === "yes" }) });
      close();
      reload();
      navigate(`/targets/${t.id}`);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const columns: Column<Target>[] = [
    {
      id: "name",
      header: "Target",
      width: "24%",
      sortValue: (t) => t.name,
      cell: (t) => (
        <a href={`/targets/${t.id}`} className="font-medium">
          {t.name}
        </a>
      ),
    },
    { id: "url", header: "Address", cell: (t) => <span className="dast-wrap font-mono text-xs">{t.url}</span> },
    { id: "verified", header: "Ownership", cell: (t) => <VerifiedBadge t={t} /> },
    { id: "env", header: "Environment", cell: (t) => (t.production ? <Badge tone="warning">Production</Badge> : <Badge>Not production</Badge>) },
    { id: "open", header: "Open", cell: (t) => <SevCounts counts={t.open} /> },
    { id: "check", header: "Check", cell: (t) => (t.lastScan ? <CheckStatus passed={t.lastScan.passed} /> : "–") },
  ];
  return (
    <>
      <PageHeader
        title="Targets"
        description="An address that may be tested. Nothing is attacked until its owner has proven it is theirs."
        actions={
          can("admin") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setAdding(true)}>
              Add target
            </Button>
          )
        }
      />
      <Panel flush>
        <DataTable
          label="Targets"
          columns={columns}
          rows={rows ?? []}
          loading={!rows}
          getRowId={(t) => t.id}
          minWidth={900}
          empty={
            <EmptyState title="No targets yet">
              {can("admin") ? "Add the address of an application you own." : "An admin adds the addresses that may be tested."}
            </EmptyState>
          }
        />
      </Panel>
      <Dialog
        open={adding}
        onOpenChange={(open) => !open && close()}
        title="Add a target"
        description="You prove the address is yours next, by serving a short text from it."
        onSubmit={add}
        footer={
          <>
            <Button type="button" onClick={close}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" disabled={!name.trim() || !address.trim()}>
              Add target
            </Button>
          </>
        }
      >
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} hint="Letters, digits, . _ and -. CI sends reports by this name." />
        <TextField label="Address" value={address} onChange={(e) => setAddress(e.target.value)} hint="https://shop.example.com, or with a path to test only a part of it." error={error} />
        <SelectField
          label="Is it production?"
          value={production}
          onChange={(e) => setProduction(e.target.value)}
          options={[
            { value: "no", label: "No, staging or test" },
            { value: "yes", label: "Yes: never given a full scan without an admin's say" },
          ]}
        />
      </Dialog>
    </>
  );
}

function TargetPage({ call, id, reload }: { call: Call; id: string; reload: () => void }) {
  const { can } = useAuth();
  const [target, setTarget] = useState<Target | null>();
  const [scans, setScans] = useState<Scan[]>();
  const [failOn, setFailOn] = useState<FailOn>("high");
  const [production, setProduction] = useState("no");
  const [error, setError] = useState<string>();
  const [removing, setRemoving] = useState(false);
  const [checking, setChecking] = useState(false);

  const load = useCallback(() => {
    call<Target>(`/api/v1/targets/${id}`).then((t) => (setTarget(t), setFailOn(t.failOn), setProduction(t.production ? "yes" : "no")), () => setTarget(null));
    call<{ scans: Scan[] }>(`/api/v1/targets/${id}/scans?limit=50`).then((r) => setScans(r.scans), () => setScans([]));
  }, [call, id]);
  useEffect(load, [load]);

  const save = async () => {
    try {
      await call(`/api/v1/targets/${id}`, { method: "PATCH", body: JSON.stringify({ failOn, production: production === "yes" }) });
      setError(undefined);
      load();
      reload();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  const verify = async () => {
    setChecking(true);
    try {
      await call(`/api/v1/targets/${id}/verify`, { method: "POST" });
      setError(undefined);
      load();
      reload();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setChecking(false);
    }
  };
  const remove = () =>
    call(`/api/v1/targets/${id}`, { method: "DELETE" }).then(
      () => {
        reload();
        navigate("/targets");
      },
      (err: Error) => setError(err.message),
    );

  if (target === null)
    return (
      <EmptyState title="Target not found">
        It may have been deleted. <a href="/targets">Back to targets</a>.
      </EmptyState>
    );

  const columns: Column<Scan>[] = [
    { id: "when", header: "Report", sortValue: (s) => s.createdAt, cell: (s) => <span className="text-xs whitespace-nowrap">{ago(s.createdAt)}</span> },
    { id: "engine", header: "Engine", cell: (s) => <Badge>{s.engine}</Badge> },
    { id: "total", header: "Reported", align: "right", cell: (s) => s.total },
    { id: "new", header: "New", align: "right", cell: (s) => s.new },
    { id: "fixed", header: "Fixed", align: "right", cell: (s) => s.resolved },
    { id: "ignored", header: "Left out", align: "right", description: "Results outside the target's address.", cell: (s) => s.ignored },
    { id: "check", header: "Check", cell: (s) => <CheckStatus passed={s.passed} /> },
  ];
  return (
    <>
      <PageHeader title={target?.name ?? "Target"} description={target ? `${target.url} · ${plural(Object.values(target.open).reduce((a, b) => a + b, 0), "open finding")}` : undefined} actions={target && <VerifiedBadge t={target} />} />
      {target && !target.verified && target.verification && (
        <Panel title="Prove the address is yours" description="Serve this text, on its own, at the address below, then ask for verification. Until then only reports are accepted; nothing is attacked.">
          <div className="flex flex-col gap-2">
            <span className="dast-wrap font-mono text-xs">{target.verification.url}</span>
            <Code>{target.verification.content}</Code>
            {can("admin") && (
              <div className="flex items-center gap-2">
                <Button variant="primary" icon={<ShieldCheck />} onClick={() => void verify()} disabled={checking}>
                  {checking ? "Checking…" : "Verify"}
                </Button>
                {error && <span className="text-xs text-danger">{error}</span>}
              </div>
            )}
          </div>
        </Panel>
      )}
      {can("admin") && target && (
        <Panel title="Policy" description="What a check treats as a failure. Only findings an engine did not report before, and nobody has triaged, can fail it.">
          <div className="grid gap-2 sm:grid-cols-2">
            <SelectField label="Fail the check for" value={failOn} onChange={(e) => setFailOn(e.target.value as FailOn)} options={FAIL_ON} />
            <SelectField
              label="Production"
              value={production}
              onChange={(e) => setProduction(e.target.value)}
              options={[
                { value: "no", label: "No, staging or test" },
                { value: "yes", label: "Yes: no full scans" },
              ]}
            />
          </div>
          <div className="mt-3 flex gap-2">
            <Button variant="primary" onClick={() => void save()} disabled={failOn === target.failOn && (production === "yes") === target.production}>
              Save policy
            </Button>
            <Button icon={<Trash2 />} onClick={() => setRemoving(true)}>
              Delete target
            </Button>
          </div>
          <Dialog
            open={removing}
            onOpenChange={setRemoving}
            title={`Delete ${target.name}?`}
            description="Its reports, findings and decisions are deleted. You would add and verify it again to test it."
            footer={
              <>
                <Button type="button" onClick={() => setRemoving(false)}>
                  Cancel
                </Button>
                <Button type="button" variant="primary" onClick={() => void remove()}>
                  Delete
                </Button>
              </>
            }
          >
            <></>
          </Dialog>
        </Panel>
      )}
      <FindingsTable call={call} targetId={id} summary={target ?? undefined} reload={() => (load(), reload())} />
      <Panel title="Reports" flush>
        <DataTable label="Reports" columns={columns} rows={scans ?? []} loading={!scans} getRowId={(s) => s.id} minWidth={720} empty={<EmptyState title="No reports">Nothing has been sent for this target.</EmptyState>} />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Setup

function SetupPage() {
  const origin = window.location.origin;
  return (
    <>
      <PageHeader title="Setup" description="Run ZAP or Nuclei against an application you own, and send the report here. The answer says whether the check passes." />
      <Panel title="Send a report" description="Add the target first and verify it. Use DAST_INGEST_TOKEN, set where dast runs, or an API token with the editor role from API tokens.">
        <Code>{`nuclei -u https://shop.example.com -se results.sarif
curl -sf -X POST -H "Authorization: Bearer $DAST_INGEST_TOKEN" -H 'content-type: application/json' \
  --data-binary @results.sarif \
  "${origin}/api/v1/scans?target=shop-staging" > scan.json
jq -e '.passed' scan.json   # fail the pipeline`}</Code>
      </Panel>
      <Panel title="How a report is compared" description="Each engine's reports replace its own earlier ones. What it stops reporting is fixed; what it reports for the first time is new.">
        <ul className="dast-list flex flex-col gap-1 text-sm text-fg-muted">
          <li>The first report of an engine for a target adopts what is there and never fails a check.</li>
          <li>A finding is found again by rule, page and parameter, not by query string.</li>
          <li>Results outside the target's address are left out, and counted.</li>
          <li>Passwords, cookies and tokens in what an engine saw are masked before they are stored.</li>
          <li>dast does not run scans yet. When it does, an unverified target is never attacked.</li>
        </ul>
      </Panel>
    </>
  );
}

/** The first screen, until the first target exists. The summary is polled, so it gives way by itself. */
function WelcomePage() {
  return (
    <>
      <PageHeader title="Get started" description="Add a target you own, prove it, and send a report." actions={<StatusBadge tone="info">Waiting for the first target</StatusBadge>} />
      <SetupPage />
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title="Admins only">Ask an admin of this dast for access.</EmptyState>;
  const titles = {
    account: ["Account", "Your profile, password, two-step verification and where you are signed in."],
    members: ["Members", "Who can sign in to this dast, and with which role. Viewers see everything; editors also triage findings; admins also add and verify targets, change policies, and manage members and tokens."],
    signin: ["Sign-in", "Identity providers people can sign in with, such as OpenAsy Identity, Keycloak or Microsoft Entra ID, and which of their groups give which role."],
    tokens: ["API tokens", "For scripts and CI. Each token has one role and an expiry; the secret is shown once."],
  } as const;
  return (
    <>
      <PageHeader
        title={titles[page][0]}
        description={titles[page][1]}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              Sign out
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const [theme, setTheme] = useThemePreference();
  const { me, can } = useAuth();
  const route = parseRoute(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) => setProducts(r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "dast" && (PRODUCT_IDS as readonly string[]).includes(p.id))),
      () => {},
    );
  }, [call]);

  const reload = useCallback(() => void call<Summary>("/api/v1/summary").then(setSummary, () => {}), [call]);
  useEffect(() => {
    reload();
    const t = setInterval(reload, 15_000);
    return () => clearInterval(t);
  }, [reload]);

  const nav = [
    { id: "findings", label: "Findings", icon: Bug },
    { id: "targets", label: "Targets", icon: Crosshair, count: summary?.targets },
  ];
  const footerNav = [
    { id: "setup", label: "Setup", icon: Settings2 },
    ...(can("admin")
      ? [
          { id: "members", label: "Members", icon: Users },
          { id: "signin", label: "Sign-in", icon: LogIn },
          { id: "tokens", label: "API tokens", icon: KeyRound },
        ]
      : []),
    { id: "account", label: "Account", icon: UserRound },
  ];
  const active = route.page === "target" ? "targets" : route.page;
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);

  return (
    <AppShell
      product="dast"
      nav={nav}
      activeNav={active}
      onNavigate={(id) => navigate(`/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={footerNav}
      user={{ name: me.user.name, role: roleName }}
      theme={theme}
      onThemeChange={setTheme}
    >
      {route.page === "findings" && summary && summary.targets === 0 ? (
        <WelcomePage />
      ) : route.page === "findings" ? (
        <FindingsPage call={call} summary={summary} reload={reload} />
      ) : route.page === "targets" ? (
        <TargetsPage call={call} reload={reload} />
      ) : route.page === "target" ? (
        <TargetPage key={route.id} call={call} id={route.id} reload={reload} />
      ) : route.page === "account" || route.page === "members" || route.page === "signin" || route.page === "tokens" ? (
        <SettingsPage page={route.page} />
      ) : (
        <SetupPage />
      )}
    </AppShell>
  );
}

export function App() {
  const [theme] = useThemePreference();
  return (
    // No organization until branding is configurable (ADR 0004); the library's default is a placeholder.
    <BrandProvider theme={theme} brand={{ name: "OpenAsy", organization: undefined }} className="min-h-screen">
      <AuthGate product="OpenAsy DAST">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
