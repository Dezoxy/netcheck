import {
  Bookmark,
  Check,
  Download,
  FileText,
  Globe,
  History,
  LockKeyhole,
  Menu,
  Play,
  Settings2,
  Trash2,
  X,
} from "lucide-react";
import { FormEvent, ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import {
  deleteSavedReport,
  listSavedReports,
  loadSavedReport,
  runDNSCheck,
  runFullCheck,
  runIPCheck,
  runRouteCheck,
  saveReport,
} from "./api";
import type {
  AnyReport,
  CheckMode,
  DNSCompareReport,
  FullCheckReport,
  IPInfoReport,
  RecentCheck,
  RouteReport,
  SavedReportMeta,
} from "./types";

const HISTORY_KEY = "netcheck.recent-checks.v1";
const MAX_RECENTS = 8;

type RunState = "idle" | "loading" | "ready" | "error";
type SideTab = "recent" | "saved";

const MODE_LABEL: Record<CheckMode, string> = {
  full: "Full Check",
  dns: "DNS Compare",
  route: "Route",
  ip: "IP Info",
};

export default function App() {
  const [mode, setMode] = useState<CheckMode>("full");
  const [target, setTarget] = useState("google.com");
  const [report, setReport] = useState<AnyReport | null>(null);
  const [runState, setRunState] = useState<RunState>("idle");
  const [error, setError] = useState("");
  const [insecure, setInsecure] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [sideTab, setSideTab] = useState<SideTab>("recent");
  const [recents, setRecents] = useState<RecentCheck[]>(readRecents);
  const [saved, setSaved] = useState<SavedReportMeta[]>([]);
  const [savedError, setSavedError] = useState("");
  const [savingNow, setSavingNow] = useState(false);
  const [savedJustNow, setSavedJustNow] = useState(false);

  useEffect(() => {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(recents));
  }, [recents]);

  const refreshSaved = useCallback(async () => {
    setSavedError("");
    try {
      setSaved(await listSavedReports());
    } catch (cause) {
      setSavedError(cause instanceof Error ? cause.message : "could not load saved reports");
    }
  }, []);

  useEffect(() => {
    if (sideTab === "saved") {
      void refreshSaved();
    }
  }, [sideTab, refreshSaved]);

  const runCheck = useCallback(
    async (overrideMode?: CheckMode, overrideTarget?: string) => {
      const effectiveMode = overrideMode ?? mode;
      const effectiveTarget = (overrideTarget ?? target).trim();
      if (!effectiveTarget) {
        setError("Enter a URL, host, or IP address.");
        setRunState("error");
        return;
      }
      setRunState("loading");
      setError("");
      setSavedJustNow(false);
      try {
        let next: AnyReport;
        switch (effectiveMode) {
          case "dns":
            next = await runDNSCheck(effectiveTarget);
            break;
          case "route":
            next = await runRouteCheck(effectiveTarget);
            break;
          case "ip":
            next = await runIPCheck(effectiveTarget);
            break;
          default:
            next = await runFullCheck(effectiveTarget, insecure);
        }
        setReport(next);
        setRunState("ready");
        setHistoryOpen(false);
        setRecents((current) => upsertRecent(current, next, effectiveMode));
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : "The check could not start.");
        setRunState("error");
      }
    },
    [insecure, mode, target],
  );

  async function submitCheck(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    await runCheck();
  }

  async function saveCurrent() {
    if (!report) {
      return;
    }
    setSavingNow(true);
    setSavedJustNow(false);
    try {
      await saveReport(report);
      setSavedJustNow(true);
      if (sideTab === "saved") {
        void refreshSaved();
      }
    } catch (cause) {
      setSavedError(cause instanceof Error ? cause.message : "save failed");
    } finally {
      setSavingNow(false);
    }
  }

  function exportReport() {
    if (!report) {
      return;
    }
    const targetName = reportTarget(report) || "report";
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = `netcheck-${report.kind}-${targetName}.json`;
    anchor.click();
    URL.revokeObjectURL(href);
  }

  function rerunRecent(recent: RecentCheck) {
    setTarget(recent.target);
    setMode(recent.mode);
    setHistoryOpen(false);
    void runCheck(recent.mode, recent.target);
  }

  async function openSaved(meta: SavedReportMeta) {
    try {
      const { report: loaded } = await loadSavedReport(meta.id);
      setReport(loaded);
      setMode(loaded.kind);
      setTarget(reportTarget(loaded));
      setRunState("ready");
      setHistoryOpen(false);
    } catch (cause) {
      setSavedError(cause instanceof Error ? cause.message : "could not load");
    }
  }

  async function removeSaved(meta: SavedReportMeta) {
    try {
      await deleteSavedReport(meta.id);
      setSaved((current) => current.filter((item) => item.id !== meta.id));
    } catch (cause) {
      setSavedError(cause instanceof Error ? cause.message : "delete failed");
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="topbar-leading">
          <IconButton className="mobile-menu-button" expanded={historyOpen} label="Menu" onClick={() => setHistoryOpen((open) => !open)}>
            <Menu />
          </IconButton>
          <div className="brand">netcheck</div>
        </div>
        <div className="topbar-actions">
          <IconButton className="desktop-history-button" label="Recent checks" onClick={() => setHistoryOpen((open) => !open)}>
            <History />
          </IconButton>
          <IconButton disabled={!report || savingNow} label={savedJustNow ? "Saved" : "Save report"} onClick={saveCurrent}>
            {savedJustNow ? <Check /> : <Bookmark />}
          </IconButton>
          <IconButton disabled={!report} label="Export JSON" onClick={exportReport}>
            <Download />
          </IconButton>
          <IconButton label="Settings" onClick={() => setSettingsOpen((open) => !open)}>
            <Settings2 />
          </IconButton>
        </div>
      </header>

      <aside className={`sidenav ${historyOpen ? "sidenav-open" : ""}`}>
        <div className="sidenav-heading">
          <div>
            <span>Diagnostics</span>
            <strong>Network Workbench</strong>
          </div>
          <IconButton className="sidenav-close-button" label="Close menu" onClick={() => setHistoryOpen(false)}>
            <X />
          </IconButton>
        </div>
        <nav className="sidenav-nav" aria-label="Workbench">
          <button
            aria-selected={sideTab === "recent"}
            className={`nav-item ${sideTab === "recent" ? "nav-item-active" : ""}`}
            onClick={() => setSideTab("recent")}
            type="button"
          >
            <History />
            <span>Recent Checks</span>
          </button>
          <button
            aria-selected={sideTab === "saved"}
            className={`nav-item ${sideTab === "saved" ? "nav-item-active" : ""}`}
            onClick={() => setSideTab("saved")}
            type="button"
          >
            <FileText />
            <span>Saved Reports</span>
          </button>
        </nav>
        {sideTab === "recent" ? (
          <section className="recent-list" aria-label="Recent checks">
            {recents.length === 0 ? <p className="empty-list">No recent checks yet.</p> : null}
            {recents.map((recent) => (
              <button className="recent-item" key={`${recent.target}-${recent.ranAt}`} onClick={() => rerunRecent(recent)} type="button">
                <span className={`recent-dot ${recent.ok ? "recent-dot-ok" : "recent-dot-fail"}`} />
                <span>
                  <strong>{recent.target}</strong>
                  <time>{MODE_LABEL[recent.mode] || "Full"} · {formatRecentTime(recent.ranAt)}</time>
                </span>
              </button>
            ))}
          </section>
        ) : (
          <section className="recent-list" aria-label="Saved reports">
            {savedError ? <p className="detail-error">{savedError}</p> : null}
            {saved.length === 0 && !savedError ? <p className="empty-list">No saved reports yet.</p> : null}
            {saved.map((item) => (
              <div className="recent-item recent-item-saved" key={item.id}>
                <button className="recent-item-main" onClick={() => openSaved(item)} type="button">
                  <span className={`recent-dot ${item.ok === false ? "recent-dot-fail" : "recent-dot-ok"}`} />
                  <span>
                    <strong>{item.target}</strong>
                    <time>{MODE_LABEL[item.kind] || item.kind} · {formatRecentTime(item.saved_at)}</time>
                  </span>
                </button>
                <IconButton label="Delete saved report" onClick={() => removeSaved(item)}>
                  <Trash2 />
                </IconButton>
              </div>
            ))}
          </section>
        )}
        <div className="sidenav-footer">
          <a href="https://github.com/Dezoxy/netcheck#readme" rel="noreferrer" target="_blank">
            <Globe />
            <span>Documentation</span>
          </a>
          <a href="https://github.com/Dezoxy/netcheck/issues" rel="noreferrer" target="_blank">
            <FileText />
            <span>Support</span>
          </a>
        </div>
      </aside>
      <button
        aria-label="Close navigation"
        className={`sidenav-backdrop ${historyOpen ? "sidenav-backdrop-open" : ""}`}
        onClick={() => setHistoryOpen(false)}
        type="button"
      />

      <main className="workbench">
        <form className="input-section" onSubmit={submitCheck}>
          <div className="target-row">
            <label className="target-field">
              <Globe />
              <span className="sr-only">Target</span>
              <input
                autoCapitalize="none"
                autoCorrect="off"
                onChange={(event) => setTarget(event.target.value)}
                spellCheck="false"
                value={target}
              />
            </label>
            <button className="run-button" disabled={runState === "loading"} type="submit">
              <Play />
              <span>{runState === "loading" ? "Running" : "Run Check"}</span>
            </button>
          </div>
          <div className="mode-tabs" role="tablist" aria-label="Check mode">
            {(Object.entries(MODE_LABEL) as Array<[CheckMode, string]>).map(([key, label]) => (
              <button
                key={key}
                aria-selected={mode === key}
                className={`mode-tab ${mode === key ? "mode-tab-active" : ""}`}
                onClick={() => setMode(key)}
                role="tab"
                type="button"
              >
                {label}
              </button>
            ))}
          </div>
        </form>

        {settingsOpen ? (
          <section className="settings-panel" aria-label="Check settings">
            <div>
              <strong>Check Settings</strong>
              <p>TLS verification stays on unless this run needs inspection of an invalid certificate. Only applies to the Full Check.</p>
            </div>
            <label>
              <input checked={insecure} onChange={(event) => setInsecure(event.target.checked)} type="checkbox" />
              <span>Allow insecure TLS</span>
            </label>
            <IconButton label="Close settings" onClick={() => setSettingsOpen(false)}>
              <X />
            </IconButton>
          </section>
        ) : null}

        {runState === "idle" ? <EmptyWorkbench mode={mode} onRun={() => void submitCheck()} /> : null}
        {runState === "error" ? <ErrorBanner message={error} /> : null}
        {report ? <ReportView loading={runState === "loading"} report={report} /> : null}
      </main>
    </div>
  );
}

// ─── Report routing ───────────────────────────────────────────────────────

function ReportView({ loading, report }: { loading: boolean; report: AnyReport }) {
  switch (report.kind) {
    case "full":
      return <FullCheckWorkbench loading={loading} report={report} />;
    case "dns":
      return <DNSCompareWorkbench loading={loading} report={report} />;
    case "route":
      return <RouteWorkbench loading={loading} report={report} />;
    case "ip":
      return <IPInfoWorkbench loading={loading} report={report} />;
  }
}

// ─── Full check view (unchanged from v1.1.0) ─────────────────────────────

function FullCheckWorkbench({ loading, report }: { loading: boolean; report: FullCheckReport }) {
  const tcp = report.tcp_v4 ?? report.tcp_v6;
  const status = report.ok ? "Healthy" : "Needs attention";
  const statusClass = report.ok ? "health-pill-ok" : "health-pill-fail";
  const timing = useMemo(() => timingSegments(report), [report]);

  return (
    <section className={loading ? "result-area result-area-loading" : "result-area"}>
      <div className="result-header">
        <h1>
          Full Check: <span>{report.target.host}</span>
        </h1>
        <div className={`health-pill ${statusClass}`}>
          <span />
          {status}
        </div>
      </div>

      <div className="summary-strip">
        <SummaryCard error={report.dns.error} label="DNS Resolution" ms={report.dns.took_ms} value="Success" />
        <SummaryCard error={tcp?.error} label="TCP Connection" ms={tcp?.took_ms} value={tcp ? "Success" : "Unavailable"} />
        <SummaryCard error={report.tls?.error} label="TLS Handshake" ms={report.tls?.took_ms} value={report.tls ? "Success" : "Skipped"} />
        <SummaryCard
          error={report.http.error}
          label="HTTP Response"
          ms={report.http.timing.total_ms}
          value={report.http.status ? `${report.http.status} ${report.http.status < 400 ? "OK" : ""}`.trim() : "Failed"}
        />
      </div>

      <Panel className="timing-panel" title="Timing Waterfall">
        <div className="waterfall" aria-label="HTTP timing waterfall">
          {timing.map((segment) => (
            <span key={segment.label} style={{ background: segment.color, width: `${segment.width}%` }} />
          ))}
        </div>
        <div className="timing-legend">
          {timing.map((segment) => (
            <span key={segment.label}>
              <i style={{ background: segment.color }} />
              {segment.label}
            </span>
          ))}
        </div>
      </Panel>

      <div className="details-grid">
        <Panel className="dns-panel" icon={<FileText />} title="DNS Records">
          <div className="dns-table">
            <div className="dns-header">
              <span>Type</span>
              <span>Value</span>
            </div>
            {report.dns.a.map((ip) => (
              <div className="dns-row" key={`a-${ip}`}>
                <span>A</span>
                <code>{ip}</code>
              </div>
            ))}
            {report.dns.aaaa.map((ip) => (
              <div className="dns-row" key={`aaaa-${ip}`}>
                <span>AAAA</span>
                <code>{ip}</code>
              </div>
            ))}
            {report.dns.error ? <p className="detail-error">{report.dns.error}</p> : null}
          </div>
        </Panel>

        <Panel className="tls-panel" icon={<LockKeyhole />} title="TLS Certificate">
          {report.tls ? (
            <dl className="certificate-grid">
              <Detail label="Protocol" value={report.tls.version} />
              <Detail label="Cipher" value={report.tls.cipher_suite} />
              <Detail label="Issuer" value={report.tls.issuer} />
              <Detail label="Expiry" value={`${formatDate(report.tls.not_after)} (${report.tls.days_remaining}d)`} />
              {report.tls.error ? <Detail error label="Error" value={report.tls.error} /> : null}
            </dl>
          ) : (
            <p className="muted">TLS does not run for this target.</p>
          )}
        </Panel>

        <Panel className="http-panel" title="HTTP Response">
          <div className="http-grid">
            <Metric label="Status" ok={report.http.status > 0 && report.http.status < 400} value={httpStatusLabel(report.http.status)} />
            <Metric label="Redirects" value={report.http.hops.length} />
            <Metric label="Server" value={report.http.server || "-"} />
            <Metric label="Final URL" value={report.http.final_url || "-"} wide />
          </div>
          {report.http.error ? <p className="detail-error">{report.http.error}</p> : null}
        </Panel>
      </div>
    </section>
  );
}

// ─── DNS compare view ─────────────────────────────────────────────────────

function DNSCompareWorkbench({ loading, report }: { loading: boolean; report: DNSCompareReport }) {
  const allAgree = report.queries.every((q) => q.verdict.agree);
  return (
    <section className={loading ? "result-area result-area-loading" : "result-area"}>
      <div className="result-header">
        <h1>
          DNS Compare: <span>{report.host}</span>
        </h1>
        <div className={`health-pill ${allAgree ? "health-pill-ok" : "health-pill-fail"}`}>
          <span />
          {allAgree ? "All resolvers agree" : "Disagreement detected"}
        </div>
      </div>

      {report.queries.map((q) => (
        <Panel key={q.qtype} className="dns-panel" icon={<FileText />} title={`${q.qtype} records`}>
          <div className="dns-table">
            <div className="dns-header dns-row-4">
              <span>Resolver</span>
              <span>Address</span>
              <span>Time</span>
              <span>Answer</span>
            </div>
            {q.results.map((r) => (
              <div className="dns-row dns-row-4" key={`${q.qtype}-${r.name}-${r.address}`}>
                <span>{r.name}</span>
                <code>{r.address}</code>
                <code>{r.took_ms}ms</code>
                {r.error ? (
                  <span className="detail-error">{r.error}</span>
                ) : (
                  <code>{(r.records ?? []).join(", ") || "(none)"}</code>
                )}
              </div>
            ))}
          </div>
          <p className="muted">
            {q.verdict.agree ? "All successful resolvers returned the same answer set." : `${q.verdict.groups.length} distinct answer sets:`}
          </p>
          {!q.verdict.agree
            ? q.verdict.groups.map((group, i) => (
                <p className="muted" key={`group-${i}`}>
                  <strong>Set {i + 1}</strong> ({group.resolvers.join(", ")}): <code>{group.records.join(", ") || "(empty)"}</code>
                </p>
              ))
            : null}
        </Panel>
      ))}
    </section>
  );
}

// ─── Route view ───────────────────────────────────────────────────────────

function RouteWorkbench({ loading, report }: { loading: boolean; report: RouteReport }) {
  return (
    <section className={loading ? "result-area result-area-loading" : "result-area"}>
      <div className="result-header">
        <h1>
          Route: <span>{report.host}</span>
          {report.dest_ip ? <span className="muted"> ({report.dest_ip})</span> : null}
        </h1>
        <div className={`health-pill ${report.reached ? "health-pill-ok" : "health-pill-fail"}`}>
          <span />
          {report.reached ? `Reached in ${report.hops.length} hops` : `Stopped after ${report.hops.length} hops`}
        </div>
      </div>

      <Panel className="dns-panel" icon={<FileText />} title="Hops">
        <div className="dns-table">
          <div className="dns-header dns-row-4">
            <span>#</span>
            <span>Address</span>
            <span>RTT (ms)</span>
            <span>ASN</span>
          </div>
          {report.hops.map((hop) => (
            <div className="dns-row dns-row-4" key={`hop-${hop.n}`}>
              <span>{hop.n}</span>
              {hop.timeout ? (
                <span className="muted">* * *</span>
              ) : (
                <code>{hopAddress(hop)}</code>
              )}
              {hop.timeout ? (
                <span className="muted">*</span>
              ) : (
                <code>{hopRTT(hop)}</code>
              )}
              {hop.asn ? <span>AS{hop.asn.asn} {hop.asn.org ?? ""}</span> : <span className="muted">—</span>}
            </div>
          ))}
        </div>
        {report.timeouts > 0 ? (
          <p className="muted">
            {report.timeouts} hop(s) timed out — routers commonly drop or rate-limit probes; missing hops don't always mean a broken route.
          </p>
        ) : null}
      </Panel>
    </section>
  );
}

function hopAddress(hop: RouteReport["hops"][number]): string {
  if (!hop.probes || hop.probes.length === 0) {
    return hop.ips?.[0] ?? "(no addresses)";
  }
  const first = hop.probes[0];
  if (first.host && first.ip) {
    return `${first.host} (${first.ip})`;
  }
  return first.ip ?? first.host ?? "(no addresses)";
}

function hopRTT(hop: RouteReport["hops"][number]): string {
  if (!hop.probes || hop.probes.length === 0) {
    return "—";
  }
  return hop.probes.map((p) => p.rtt_ms.toFixed(2)).join(" / ");
}

// ─── IP info view ─────────────────────────────────────────────────────────

function IPInfoWorkbench({ loading, report }: { loading: boolean; report: IPInfoReport }) {
  return (
    <section className={loading ? "result-area result-area-loading" : "result-area"}>
      <div className="result-header">
        <h1>
          IP Info: <span>{report.target}</span>
        </h1>
        <div className="health-pill health-pill-ok">
          <span />
          {report.details.length} address{report.details.length === 1 ? "" : "es"}
        </div>
      </div>

      {report.details.map((d) => (
        <Panel key={d.ip} className="dns-panel" icon={<Globe />} title={d.ip}>
          <dl className="certificate-grid">
            <Detail label="Reverse" value={(d.reverse ?? []).join(", ") || "—"} />
            {d.asn ? <Detail label="ASN" value={`AS${d.asn.asn} ${d.asn.org ?? ""}`} /> : null}
            {d.asn?.country || d.rdap?.country ? <Detail label="Country" value={d.asn?.country ?? d.rdap?.country ?? "—"} /> : null}
            {d.asn?.prefix ? <Detail label="Prefix" value={d.asn.prefix} /> : null}
            {d.rdap?.registry || d.asn?.registry ? <Detail label="Registry" value={d.rdap?.registry ?? d.asn?.registry ?? "—"} /> : null}
            {d.cdn?.provider ? (
              <Detail label="CDN" value={d.cdn.confidence && d.cdn.reason ? `${d.cdn.provider} (${d.cdn.confidence} — ${d.cdn.reason})` : d.cdn.provider} />
            ) : null}
            {d.rdap?.abuse_email ? <Detail label="Abuse" value={d.rdap.abuse_email} /> : null}
          </dl>
        </Panel>
      ))}
    </section>
  );
}

// ─── Shared building blocks ───────────────────────────────────────────────

function EmptyWorkbench({ mode, onRun }: { mode: CheckMode; onRun: () => void }) {
  const blurb: Record<CheckMode, string> = {
    full: "DNS, TCP, TLS, HTTP, redirects, and timing land in one report.",
    dns: "Query Cloudflare, Google, Quad9, and your system resolver in parallel — see if they agree.",
    route: "Trace the network path with per-hop ASN ownership.",
    ip: "Get reverse DNS, ASN, RDAP, country, and CDN classification for an IP or hostname.",
  };
  return (
    <section className="empty-workbench">
      <div>
        <span>Ready</span>
        <h1>Run a {MODE_LABEL[mode]}.</h1>
        <p>{blurb[mode]}</p>
      </div>
      <button className="run-button" onClick={onRun} type="button">
        <Play />
        <span>Run Check</span>
      </button>
    </section>
  );
}

function SummaryCard({ error, label, ms, value }: { error?: string; label: string; ms?: number; value: string }) {
  return (
    <article className="summary-card">
      <span>{label}</span>
      <div>
        <strong className={error ? "value-fail" : "value-ok"}>{error ? "Failed" : value}</strong>
        <code>{formatMS(ms)}</code>
      </div>
    </article>
  );
}

function Panel({ children, className = "", icon, title }: { children: ReactNode; className?: string; icon?: ReactNode; title: string }) {
  return (
    <section className={`panel ${className}`}>
      <header>
        <span>{title}</span>
        {icon}
      </header>
      <div className="panel-body">{children}</div>
    </section>
  );
}

function Detail({ error = false, label, value }: { error?: boolean; label: string; value: string }) {
  return (
    <>
      <dt>{label}:</dt>
      <dd className={error ? "detail-error" : ""}>{value}</dd>
    </>
  );
}

function Metric({ label, ok = false, value, wide = false }: { label: string; ok?: boolean; value: number | string; wide?: boolean }) {
  return (
    <div className={wide ? "metric metric-wide" : "metric"}>
      <span>{label}</span>
      <strong className={ok ? "value-ok" : ""}>{value}</strong>
    </div>
  );
}

function ErrorBanner({ message }: { message: string }) {
  return (
    <section className="error-banner" role="alert">
      {message}
    </section>
  );
}

function IconButton({
  children,
  className = "",
  disabled = false,
  expanded,
  label,
  onClick,
}: {
  children: ReactNode;
  className?: string;
  disabled?: boolean;
  expanded?: boolean;
  label: string;
  onClick: () => void;
}) {
  return (
    <button
      aria-expanded={expanded}
      aria-label={label}
      className={`icon-button ${className}`}
      disabled={disabled}
      onClick={onClick}
      title={label}
      type="button"
    >
      {children}
    </button>
  );
}

// ─── Pure helpers ─────────────────────────────────────────────────────────

function readRecents(): RecentCheck[] {
  try {
    const saved = localStorage.getItem(HISTORY_KEY);
    if (!saved) {
      return [];
    }
    const parsed = JSON.parse(saved) as Array<Partial<RecentCheck>>;
    // Migrate any pre-v1.2 entries that didn't have a mode field.
    return parsed
      .filter((item): item is RecentCheck & { mode?: CheckMode } => !!item && typeof item.target === "string")
      .map((item) => ({
        ok: !!item.ok,
        ranAt: item.ranAt ?? new Date().toISOString(),
        target: item.target as string,
        mode: (item.mode as CheckMode) ?? "full",
      }));
  } catch {
    return [];
  }
}

function upsertRecent(current: RecentCheck[], report: AnyReport, mode: CheckMode): RecentCheck[] {
  const next: RecentCheck = {
    ok: reportOK(report),
    ranAt: report.started_at,
    target: reportTarget(report),
    mode,
  };
  return [next, ...current.filter((item) => !(item.target === next.target && item.mode === next.mode))].slice(0, MAX_RECENTS);
}

function reportTarget(report: AnyReport): string {
  switch (report.kind) {
    case "full":
      return report.target.raw;
    case "dns":
    case "route":
      return report.host;
    case "ip":
      return report.target;
  }
}

function reportOK(report: AnyReport): boolean {
  switch (report.kind) {
    case "full":
      return report.ok;
    case "dns":
      return report.queries.every((q) => q.verdict.agree);
    case "route":
      return report.reached;
    case "ip":
      return report.details.length > 0;
  }
}

function timingSegments(report: FullCheckReport) {
  const timing = report.http.timing;
  const segments = [
    { color: "#06b6d4", label: "DNS", value: timing.dns_ms },
    { color: "#e79400", label: "Connect", value: timing.connect_ms },
    { color: "#8b5cf6", label: "SSL", value: timing.tls_ms ?? 0 },
    { color: "#00a572", label: "TTFB", value: timing.ttfb_ms },
  ];
  const total = Math.max(timing.total_ms, segments.reduce((sum, segment) => sum + segment.value, 0), 1);
  return segments.map((segment) => ({
    ...segment,
    width: Math.max((segment.value / total) * 100, segment.value > 0 ? 3 : 0),
  }));
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat("en", { dateStyle: "medium" }).format(new Date(value));
}

function formatRecentTime(value: string) {
  return new Intl.DateTimeFormat("en", {
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    month: "short",
  }).format(new Date(value));
}

function formatMS(value?: number) {
  return value && value > 0 ? `${value}ms` : "-";
}

function httpStatusLabel(status: number) {
  if (!status) {
    return "Failed";
  }
  return status < 400 ? `${status} OK` : status;
}
