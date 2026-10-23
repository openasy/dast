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
  useAgo,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAuth } from "@openasy/auth/react";
import { Bug, CircleSlash, Crosshair, KeyRound, LogIn, LogOut, Plus, Settings2, ShieldCheck, Trash2, UserRound, Users, X } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  MfaSetupRequired,
  Unauthorized,
  type FailOn,
  type Finding,
  type ProductLink,
  type Scan,
  type Severity,
  type Summary,
  type Target,
} from "./api.ts";
import { useT, type T } from "./i18n.ts";

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
const FAIL_ON = (t: T): Array<{ value: FailOn; label: string }> => [
  { value: "critical", label: t("failOn.critical") },
  { value: "high", label: t("failOn.highOrWorse") },
  { value: "medium", label: t("failOn.mediumOrWorse") },
  { value: "low", label: t("failOn.anyFinding") },
  { value: "none", label: t("failOn.neverFail") },
];

/** Compact severity counts; each badge carries the full name for screen readers. */
function SevCounts({ counts }: { counts: Record<Severity, number> }) {
  const t = useT();
  const shown = SEVERITIES.filter((s) => counts[s] > 0);
  if (!shown.length) return <span className="text-xs text-fg-muted">{t("sevCounts.none")}</span>;
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
  const ago = useAgo();
  const msg = useT();
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
      await call(url, {
        method: "PUT",
        body: JSON.stringify({ state, reason, ...(state === "accepted" && { expiresAt: new Date(Date.now() + Number(days) * 86_400_000).toISOString() }) }),
      });
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
      aria-label={msg("findingPanel.details", { rule: finding.rule })}
      title={<span className="dast-wrap font-mono text-sm">{finding.rule}</span>}
      description={`${finding.target.name} · ${finding.engine}`}
      actions={
        <IconButton label={msg("findingPanel.closeDetails")} size="sm" onClick={onClose}>
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
              <StatusBadge tone={t.active ? "success" : "neutral"}>
                {t.state === "false-positive"
                  ? msg("findingPanel.falsePositive")
                  : t.active
                    ? msg("findingPanel.acceptedRisk")
                    : msg("findingPanel.acceptanceExpired")}
              </StatusBadge>
            </span>
            <span>{t.reason}</span>
            <span className="text-fg-muted">
              {t.by ? `${t.by}, ` : ""}
              {ago(t.at)}
              {t.expiresAt ? msg("findingPanel.until", { value: new Date(t.expiresAt).toLocaleDateString() }) : ""}
            </span>
          </div>
        )}
        {can("editor") && (
          <div className="flex gap-2 border-t border-line pt-3">
            <Button size="sm" icon={<CircleSlash />} onClick={() => setDeciding(true)}>
              {t ? msg("findingPanel.changeDecision") : msg("findingPanel.triage")}
            </Button>
            {t && (
              <Button size="sm" onClick={() => void reopen()}>
                {msg("findingPanel.openAgain")}
              </Button>
            )}
          </div>
        )}
        <Dialog
          open={deciding}
          onOpenChange={(open) => !open && close()}
          title={msg("findingPanel.triage2", { rule: finding.rule })}
          description={msg("findingPanel.theDecisionStaysWithThis")}
          onSubmit={decide}
          footer={
            <>
              <Button type="button" onClick={close}>
                {msg("findingPanel.cancel")}
              </Button>
              <Button type="submit" variant="primary" disabled={reason.trim().length < 3}>
                {msg("findingPanel.saveDecision")}
              </Button>
            </>
          }
        >
          <SelectField
            label={msg("findingPanel.decision")}
            value={state}
            onChange={(e) => setState(e.target.value as typeof state)}
            options={[
              { value: "false-positive", label: msg("findingPanel.falsePositive") },
              { value: "accepted", label: msg("findingPanel.acceptedRisk") },
            ]}
          />
          <TextField
            label={msg("findingPanel.reason")}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            hint={msg("findingPanel.whyForTheNextReview")}
            error={error}
          />
          {state === "accepted" && (
            <SelectField
              label={msg("findingPanel.for")}
              value={days}
              onChange={(e) => setDays(e.target.value)}
              options={[
                { value: "30", label: msg("findingPanel.n30Days") },
                { value: "90", label: msg("findingPanel.n90Days") },
                { value: "180", label: msg("findingPanel.n180Days") },
                { value: "365", label: msg("findingPanel.n1Year") },
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
function FindingsTable({
  call,
  targetId,
  summary,
  reload,
}: {
  call: Call;
  targetId?: string;
  summary?: { open: Record<Severity, number> };
  reload: () => void;
}) {
  const ago = useAgo();
  const t = useT();
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
    query().then(
      (r) => (setRows(r.findings), setMore(r.nextCursor)),
      () => setRows([]),
    );
  }, [query]);
  useEffect(load, [load]);
  const loadMore = () => more && query(more).then((r) => (setRows((x) => [...(x ?? []), ...r.findings]), setMore(r.nextCursor)));

  const columns: Column<Finding>[] = [
    { id: "sev", header: t("findingsTable.severity"), width: "104px", cell: (f) => <SeverityBadge severity={f.severity} /> },
    {
      id: "rule",
      header: t("findingsTable.rule"),
      width: "30%",
      cell: (f) => (
        <span className="flex min-w-0 flex-col">
          <button type="button" onClick={() => setOpen(f)} className="dast-wrap self-start text-left font-mono text-xs font-medium text-fg hover:underline">
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
      header: t("findingsTable.where"),
      width: "32%",
      cell: (f) => (
        <span className="dast-wrap font-mono text-xs">
          {f.url.replace(/^https?:\/\//, "")}
          {f.param ? ` (${f.param})` : ""}
        </span>
      ),
    },
    { id: "engine", header: t("findingsTable.engine"), cell: (f) => <Badge>{f.engine}</Badge> },
    ...(targetId
      ? []
      : [
          { id: "target", header: t("findingsTable.target"), cell: (f: Finding) => <span className="text-xs">{f.target.name}</span> } satisfies Column<Finding>,
        ]),
    {
      id: "seen",
      header: t("findingsTable.firstSeen"),
      sortValue: (f) => f.firstSeen,
      cell: (f) => <span className="text-xs whitespace-nowrap">{ago(f.firstSeen)}</span>,
    },
  ];

  return (
    <>
      <Tabs<Tab>
        label={t("findingsTable.findingViews")}
        value={tab}
        onChange={setTab}
        items={[
          { value: "open", label: t("findingsTable.open") },
          { value: "suppressed", label: t("findingsTable.triaged") },
          { value: "resolved", label: t("findingsTable.fixed") },
        ]}
      />
      <FilterBar onClear={() => (setSev([]), setQ(""))}>
        <FacetFilter
          label={t("findingsTable.severity")}
          selected={sev}
          onChange={setSev}
          options={SEVERITIES.map((s) => ({ value: s, label: s.charAt(0).toUpperCase() + s.slice(1), count: tab === "open" ? summary?.open[s] : undefined }))}
        />
        <SearchInput label={t("findingsTable.searchRuleAddressOrMessage")} className="w-64" value={q} onChange={(e) => setQ(e.target.value)} />
      </FilterBar>
      <div className={open ? "grid gap-2.5 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]" : "grid gap-2.5"}>
        <Panel
          title={tab === "open" ? t("findingsTable.open") : tab === "suppressed" ? t("findingsTable.falsePositivesAndAcceptedRisk") : t("findingsTable.fixed")}
          description={t("findingsTable.whatTheScannersFoundOn")}
          flush
          footer={
            more ? (
              <Button size="sm" onClick={loadMore}>
                {t("findingsTable.loadMore")}
              </Button>
            ) : undefined
          }
        >
          <DataTable
            label={t("findingsTable.findings")}
            columns={columns}
            rows={rows ?? []}
            loading={!rows}
            getRowId={(f) => `${f.target.id}/${f.fingerprint}`}
            onRowClick={(f) => setOpen(f)}
            activeRowId={open ? `${open.target.id}/${open.fingerprint}` : undefined}
            minWidth={900}
            pageSize={50}
            empty={
              <EmptyState
                title={
                  tab === "open"
                    ? t("findingsTable.noOpenFindings")
                    : tab === "suppressed"
                      ? t("findingsTable.nothingTriaged")
                      : t("findingsTable.nothingFixedYet")
                }
              >
                {tab === "open" && summary && !Object.values(summary.open).some(Boolean) ? (
                  <>
                    {t("findingsTable.sendAScanReportTo")} <a href="/setup">{t("findingsTable.setup")}</a>.
                  </>
                ) : (
                  t("findingsTable.nothingMatchesTheseFilters")
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
  const ago = useAgo();
  const t = useT();
  const s = summary;
  return (
    <>
      <PageHeader
        title={t("findingsPage.findings")}
        description={
          s
            ? t("findingsPage.verifiedLastReport", { plural: t("plurals.target", { count: s.targets }), verified: s.verified, ago: ago(s.lastScanAt) })
            : undefined
        }
      />
      {s && (
        <KpiGrid minWidth={150}>
          <KpiCard label={t("findingsPage.critical")} value={s.open.critical} footer={<SeverityBadge severity="critical" />} />
          <KpiCard label={t("findingsPage.high")} value={s.open.high} footer={<SeverityBadge severity="high" />} />
          <KpiCard label={t("findingsPage.medium")} value={s.open.medium} footer={<SeverityBadge severity="medium" />} />
          <KpiCard label={t("findingsPage.low")} value={s.open.low} footer={<SeverityBadge severity="low" />} />
          <KpiCard label={t("findingsPage.failedChecks7Days")} value={s.failingChecks} tone={s.failingChecks ? "warning" : "success"} />
          <KpiCard label={t("findingsPage.triaged")} value={s.suppressed} tone="info" />
        </KpiGrid>
      )}
      <FindingsTable call={call} summary={s} reload={reload} />
    </>
  );
}

function CheckStatus({ passed }: { passed: boolean }) {
  const t = useT();
  return passed ? <StatusBadge tone="success">{t("checkStatus.passed")}</StatusBadge> : <StatusBadge tone="danger">{t("checkStatus.failed")}</StatusBadge>;
}

function VerifiedBadge({ t }: { t: Pick<Target, "verified"> }) {
  const msg = useT();
  return t.verified ? (
    <StatusBadge tone="success">{msg("verifiedBadge.verified")}</StatusBadge>
  ) : (
    <StatusBadge tone="warning">{msg("verifiedBadge.notVerified")}</StatusBadge>
  );
}

function TargetsPage({ call, reload }: { call: Call; reload: () => void }) {
  const msg = useT();
  const { can } = useAuth();
  const [rows, setRows] = useState<Target[]>();
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [address, setAddress] = useState("");
  const [production, setProduction] = useState("no");
  const [error, setError] = useState<string>();
  const load = useCallback(
    () =>
      void call<{ targets: Target[] }>("/api/v1/targets?limit=500").then(
        (r) => setRows(r.targets),
        () => setRows([]),
      ),
    [call],
  );
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
      header: msg("targetsPage.target"),
      width: "24%",
      sortValue: (t) => t.name,
      cell: (t) => (
        <a href={`/targets/${t.id}`} className="font-medium">
          {t.name}
        </a>
      ),
    },
    { id: "url", header: msg("targetsPage.address"), cell: (t) => <span className="dast-wrap font-mono text-xs">{t.url}</span> },
    { id: "verified", header: msg("targetsPage.ownership"), cell: (t) => <VerifiedBadge t={t} /> },
    {
      id: "env",
      header: msg("targetsPage.environment"),
      cell: (t) => (t.production ? <Badge tone="warning">{msg("targetsPage.production")}</Badge> : <Badge>{msg("targetsPage.notProduction")}</Badge>),
    },
    { id: "open", header: msg("targetsPage.open"), cell: (t) => <SevCounts counts={t.open} /> },
    { id: "check", header: msg("targetsPage.check"), cell: (t) => (t.lastScan ? <CheckStatus passed={t.lastScan.passed} /> : "–") },
  ];
  return (
    <>
      <PageHeader
        title={msg("targetsPage.targets")}
        description={msg("targetsPage.anAddressThatMayBe")}
        actions={
          can("admin") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setAdding(true)}>
              {msg("targetsPage.addTarget")}
            </Button>
          )
        }
      />
      <Panel flush>
        <DataTable
          label={msg("targetsPage.targets")}
          columns={columns}
          rows={rows ?? []}
          loading={!rows}
          getRowId={(t) => t.id}
          minWidth={900}
          empty={
            <EmptyState title={msg("targetsPage.noTargetsYet")}>
              {can("admin") ? msg("targetsPage.addTheAddressOfAn") : msg("targetsPage.anAdminAddsTheAddresses")}
            </EmptyState>
          }
        />
      </Panel>
      <Dialog
        open={adding}
        onOpenChange={(open) => !open && close()}
        title={msg("targetsPage.addATarget")}
        description={msg("targetsPage.youProveTheAddressIs")}
        onSubmit={add}
        footer={
          <>
            <Button type="button" onClick={close}>
              {msg("targetsPage.cancel")}
            </Button>
            <Button type="submit" variant="primary" disabled={!name.trim() || !address.trim()}>
              {msg("targetsPage.addTarget")}
            </Button>
          </>
        }
      >
        <TextField label={msg("targetsPage.name")} value={name} onChange={(e) => setName(e.target.value)} hint={msg("targetsPage.lettersDigitsAndCiSends")} />
        <TextField
          label={msg("targetsPage.address")}
          value={address}
          onChange={(e) => setAddress(e.target.value)}
          hint="https://shop.example.com, or with a path to test only a part of it."
          error={error}
        />
        <SelectField
          label={msg("targetsPage.isItProduction")}
          value={production}
          onChange={(e) => setProduction(e.target.value)}
          options={[
            { value: "no", label: msg("targetsPage.noStagingOrTest") },
            { value: "yes", label: msg("targetsPage.yesNeverGivenAFull") },
          ]}
        />
      </Dialog>
    </>
  );
}

function TargetPage({ call, id, reload }: { call: Call; id: string; reload: () => void }) {
  const ago = useAgo();
  const msg = useT();
  const { can } = useAuth();
  const [target, setTarget] = useState<Target | null>();
  const [scans, setScans] = useState<Scan[]>();
  const [failOn, setFailOn] = useState<FailOn>("high");
  const [production, setProduction] = useState("no");
  const [error, setError] = useState<string>();
  const [removing, setRemoving] = useState(false);
  const [checking, setChecking] = useState(false);

  const load = useCallback(() => {
    call<Target>(`/api/v1/targets/${id}`).then(
      (t) => (setTarget(t), setFailOn(t.failOn), setProduction(t.production ? "yes" : "no")),
      () => setTarget(null),
    );
    call<{ scans: Scan[] }>(`/api/v1/targets/${id}/scans?limit=50`).then(
      (r) => setScans(r.scans),
      () => setScans([]),
    );
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
      <EmptyState title={msg("targetPage.targetNotFound")}>
        {msg("targetPage.itMayHaveBeenDeleted")} <a href="/targets">{msg("targetPage.backToTargets")}</a>.
      </EmptyState>
    );

  const columns: Column<Scan>[] = [
    {
      id: "when",
      header: msg("targetPage.report"),
      sortValue: (s) => s.createdAt,
      cell: (s) => <span className="text-xs whitespace-nowrap">{ago(s.createdAt)}</span>,
    },
    { id: "engine", header: msg("targetPage.engine"), cell: (s) => <Badge>{s.engine}</Badge> },
    { id: "total", header: msg("targetPage.reported"), align: "right", cell: (s) => s.total },
    { id: "new", header: msg("targetPage.new"), align: "right", cell: (s) => s.new },
    { id: "fixed", header: msg("targetPage.fixed"), align: "right", cell: (s) => s.resolved },
    { id: "ignored", header: msg("targetPage.leftOut"), align: "right", description: msg("targetPage.resultsOutsideTheTargetS"), cell: (s) => s.ignored },
    { id: "check", header: msg("targetPage.check"), cell: (s) => <CheckStatus passed={s.passed} /> },
  ];
  return (
    <>
      <PageHeader
        title={target?.name ?? msg("targetPage.target")}
        description={target ? `${target.url} · ${msg("plurals.openFinding", { count: Object.values(target.open).reduce((a, b) => a + b, 0) })}` : undefined}
        actions={target && <VerifiedBadge t={target} />}
      />
      {target && !target.verified && target.verification && (
        <Panel title={msg("targetPage.proveTheAddressIsYours")} description={msg("targetPage.serveThisTextOnIts")}>
          <div className="flex flex-col gap-2">
            <span className="dast-wrap font-mono text-xs">{target.verification.url}</span>
            <Code>{target.verification.content}</Code>
            {can("admin") && (
              <div className="flex items-center gap-2">
                <Button variant="primary" icon={<ShieldCheck />} onClick={() => void verify()} disabled={checking}>
                  {checking ? "Checking…" : msg("targetPage.verify")}
                </Button>
                {error && <span className="text-xs text-danger">{error}</span>}
              </div>
            )}
          </div>
        </Panel>
      )}
      {can("admin") && target && (
        <Panel title={msg("targetPage.policy")} description={msg("targetPage.whatACheckTreatsAs")}>
          <div className="grid gap-2 sm:grid-cols-2">
            <SelectField
              label={msg("targetPage.failTheCheckFor")}
              value={failOn}
              onChange={(e) => setFailOn(e.target.value as FailOn)}
              options={FAIL_ON(msg)}
            />
            <SelectField
              label={msg("targetPage.production")}
              value={production}
              onChange={(e) => setProduction(e.target.value)}
              options={[
                { value: "no", label: msg("targetPage.noStagingOrTest") },
                { value: "yes", label: msg("targetPage.yesNoFullScans") },
              ]}
            />
          </div>
          <div className="mt-3 flex gap-2">
            <Button variant="primary" onClick={() => void save()} disabled={failOn === target.failOn && (production === "yes") === target.production}>
              {msg("targetPage.savePolicy")}
            </Button>
            <Button icon={<Trash2 />} onClick={() => setRemoving(true)}>
              {msg("targetPage.deleteTarget")}
            </Button>
          </div>
          <Dialog
            open={removing}
            onOpenChange={setRemoving}
            title={msg("targetPage.delete", { name: target.name })}
            description={msg("targetPage.itsReportsFindingsAndDecisions")}
            footer={
              <>
                <Button type="button" onClick={() => setRemoving(false)}>
                  {msg("targetPage.cancel")}
                </Button>
                <Button type="button" variant="primary" onClick={() => void remove()}>
                  {msg("targetPage.delete2")}
                </Button>
              </>
            }
          >
            <></>
          </Dialog>
        </Panel>
      )}
      <FindingsTable call={call} targetId={id} summary={target ?? undefined} reload={() => (load(), reload())} />
      <Panel title={msg("targetPage.reports")} flush>
        <DataTable
          label={msg("targetPage.reports")}
          columns={columns}
          rows={scans ?? []}
          loading={!scans}
          getRowId={(s) => s.id}
          minWidth={720}
          empty={<EmptyState title={msg("targetPage.noReports")}>{msg("targetPage.nothingHasBeenSentFor")}</EmptyState>}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Setup

function SetupPage() {
  const t = useT();
  const origin = window.location.origin;
  return (
    <>
      <PageHeader title={t("setupPage.setup")} description={t("setupPage.runZapOrNucleiAgainst")} />
      <Panel title={t("setupPage.sendAReport")} description={t("setupPage.addTheTargetFirstAnd")}>
        <Code>{`nuclei -u https://shop.example.com -se results.sarif
curl -sf -X POST -H "Authorization: Bearer $DAST_INGEST_TOKEN" -H 'content-type: application/json' \
  --data-binary @results.sarif \
  "${origin}/api/v1/scans?target=shop-staging" > scan.json
jq -e '.passed' scan.json   # fail the pipeline`}</Code>
      </Panel>
      <Panel title={t("setupPage.howAReportIsCompared")} description={t("setupPage.eachEngineSReportsReplace")}>
        <ul className="dast-list flex flex-col gap-1 text-sm text-fg-muted">
          <li>{t("setupPage.theFirstReportOfAn")}</li>
          <li>{t("setupPage.aFindingIsFoundAgain")}</li>
          <li>{t("setupPage.resultsOutsideTheTargetS")}</li>
          <li>{t("setupPage.passwordsCookiesAndTokensIn")}</li>
          <li>{t("setupPage.dastDoesNotRunScans")}</li>
        </ul>
      </Panel>
    </>
  );
}

/** The first screen, until the first target exists. The summary is polled, so it gives way by itself. */
function WelcomePage() {
  const t = useT();
  return (
    <>
      <PageHeader
        title={t("welcomePage.getStarted")}
        description={t("welcomePage.addATargetYouOwn")}
        actions={<StatusBadge tone="info">{t("welcomePage.waitingForTheFirstTarget")}</StatusBadge>}
      />
      <SetupPage />
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const t = useT();
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title={t("settingsPage.adminsOnly")}>{t("settingsPage.askAnAdminOfThis")}</EmptyState>;
  const titles = {
    account: ["Account", "Your profile, password, two-step verification and where you are signed in."],
    members: [
      "Members",
      "Who can sign in to this dast, and with which role. Viewers see everything; editors also triage findings; admins also add and verify targets, change policies, and manage members and tokens.",
    ],
    signin: [
      "Sign-in",
      "Identity providers people can sign in with, such as OpenAsy Identity, Keycloak or Microsoft Entra ID, and which of their groups give which role.",
    ],
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
              {t("settingsPage.signOut")}
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const msg = useT();
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
    { id: "findings", label: msg("product.findings"), icon: Bug },
    { id: "targets", label: msg("product.targets"), icon: Crosshair, count: summary?.targets },
  ];
  const footerNav = [
    { id: "setup", label: msg("product.setup"), icon: Settings2 },
    ...(can("admin")
      ? [
          { id: "members", label: msg("product.members"), icon: Users },
          { id: "signin", label: msg("product.signIn"), icon: LogIn },
          { id: "tokens", label: msg("product.apiTokens"), icon: KeyRound },
        ]
      : []),
    { id: "account", label: msg("product.account"), icon: UserRound },
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
