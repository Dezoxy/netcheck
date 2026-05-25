import {
  AlertTriangle,
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
  runArchCheck,
  runAuditCheck,
  runDNSCheck,
  runEnumCheck,
  runFullCheck,
  runHeadersCheck,
  runIPCheck,
  runPortsCheck,
  runReverseCheck,
  runRouteCheck,
  runSubsCheck,
  runTakeoverCheck,
  runTechCheck,
  runTLSAuditCheck,
  saveReport,
} from "./api";
import type {
  AnyReport,
  ArchReport,
  AuditGrade,
  AuditReport,
  CheckMode,
  DNSCompareReport,
  FullCheckReport,
  HeadersReport,
  IPInfoReport,
  PathEnumReport,
  PortScanReport,
  RecentCheck,
  ReverseReport,
  RouteReport,
  SavedReportMeta,
  SubsReport,
  TakeoverReport,
  TechReport,
  TLSAuditReport,
} from "./types";
import { isActiveMode, MODE_GROUPS } from "./types";

const ACTIVE_ACK_KEY = "netcheck.active-ack.v1";

const HISTORY_KEY = "netcheck.recent-checks.v1";
const MAX_RECENTS = 8;

type RunState = "idle" | "loading" | "ready" | "error";
type SideTab = "recent" | "saved";

const MODE_LABEL: Record<CheckMode, string> = {
  full: "Full Check",
  dns: "DNS Compare",
  route: "Route",
  ip: "IP Info",
  headers: "Headers",
  tech: "Tech",
  subs: "Subdomains",
  reverse: "Reverse IP",
  arch: "Wayback",
  tls: "TLS Audit",
  takeover: "Takeover",
  ports: "Ports",
  enum: "Path Enum",
  audit: "Audit",
};

// kindToMode maps the JSON `kind` field on a report back to the UI's
// CheckMode. Most match 1:1; tls-audit is the only asymmetry.
function kindToMode(kind: string): CheckMode {
  if (kind === "tls-audit") {
    return "tls";
  }
  return kind as CheckMode;
}

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
  // activeAcknowledged: the user has confirmed they're authorized to run
  // active scans against the target. Persisted across sessions because
  // re-acknowledging every refresh is friction; the checkbox is still
  // explicit-opt-in the first time, and the user can untick it.
  const [activeAcknowledged, setActiveAcknowledged] = useState<boolean>(() => {
    return localStorage.getItem(ACTIVE_ACK_KEY) === "1";
  });
  // auditIncludeActive: when audit mode is selected, whether to include
  // the active sub-checks (tls / takeover / ports / enum). Independent
  // from `activeAcknowledged` — both must be true to run an active audit.
  const [auditIncludeActive, setAuditIncludeActive] = useState(false);

  useEffect(() => {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(recents));
  }, [recents]);

  useEffect(() => {
    localStorage.setItem(ACTIVE_ACK_KEY, activeAcknowledged ? "1" : "");
  }, [activeAcknowledged]);

  // The current mode triggers the auth-gate UI if either (a) it's an
  // always-active mode (tls/takeover/ports/enum), OR (b) it's audit AND
  // the user has ticked "include active scans".
  const modeIsActive = isActiveMode(mode);
  const requiresAuth = modeIsActive || (mode === "audit" && auditIncludeActive);
  const runBlocked = requiresAuth && !activeAcknowledged;

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
          case "headers":
            next = await runHeadersCheck(effectiveTarget, insecure);
            break;
          case "tech":
            next = await runTechCheck(effectiveTarget, insecure);
            break;
          case "subs":
            next = await runSubsCheck(effectiveTarget);
            break;
          case "reverse":
            next = await runReverseCheck(effectiveTarget);
            break;
          case "arch":
            next = await runArchCheck(effectiveTarget);
            break;
          case "tls":
            next = await runTLSAuditCheck(effectiveTarget);
            break;
          case "takeover":
            next = await runTakeoverCheck(effectiveTarget);
            break;
          case "ports":
            next = await runPortsCheck(effectiveTarget);
            break;
          case "enum":
            next = await runEnumCheck(effectiveTarget, { insecure });
            break;
          case "audit":
            next = await runAuditCheck(effectiveTarget, {
              active: auditIncludeActive,
              insecure,
            });
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
    [auditIncludeActive, insecure, mode, target],
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
      setMode(kindToMode(loaded.kind));
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
                    <time>{MODE_LABEL[kindToMode(item.kind)] || item.kind} · {formatRecentTime(item.saved_at)}</time>
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
            <button className="run-button" disabled={runState === "loading" || runBlocked} type="submit">
              <Play />
              <span>{runState === "loading" ? "Running" : "Run Check"}</span>
            </button>
          </div>
          <div className="mode-groups" role="tablist" aria-label="Check mode">
            {MODE_GROUPS.map((group) => (
              <div className="mode-group" key={group.label}>
                <span className="mode-group-label">{group.label}</span>
                <div className="mode-tabs">
                  {group.modes.map((key) => (
                    <button
                      key={key}
                      aria-selected={mode === key}
                      className={`mode-tab ${mode === key ? "mode-tab-active" : ""} ${
                        isActiveMode(key) ? "mode-tab-active-tier" : ""
                      }`}
                      onClick={() => setMode(key)}
                      role="tab"
                      type="button"
                    >
                      {MODE_LABEL[key]}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </form>

        {mode === "audit" ? (
          <section className="audit-options" aria-label="Audit options">
            <label className="auth-gate-check">
              <input
                checked={auditIncludeActive}
                onChange={(event) => setAuditIncludeActive(event.target.checked)}
                type="checkbox"
              />
              <span>Also run active scans (TLS audit, takeover, ports, path enum)</span>
            </label>
          </section>
        ) : null}

        {requiresAuth ? (
          <section className={`auth-gate ${activeAcknowledged ? "auth-gate-ack" : "auth-gate-pending"}`} aria-label="Active scan authorization">
            <div className="auth-gate-icon">
              <AlertTriangle />
            </div>
            <div className="auth-gate-body">
              <strong>
                {mode === "audit" ? "Active audit" : MODE_LABEL[mode]} sends probes to the target.
              </strong>
              <p>
                Running this against a system you do not own or do not have written permission to test
                is illegal in most jurisdictions. Read{" "}
                <a href="https://github.com/Dezoxy/netcheck/blob/main/docs/ETHICS.md" rel="noreferrer" target="_blank">
                  docs/ETHICS.md
                </a>
                .
              </p>
              <label className="auth-gate-check">
                <input
                  checked={activeAcknowledged}
                  onChange={(event) => setActiveAcknowledged(event.target.checked)}
                  type="checkbox"
                />
                <span>I am authorized to actively probe this target.</span>
              </label>
            </div>
          </section>
        ) : null}

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
    case "headers":
      return <HeadersWorkbench loading={loading} report={report} />;
    case "tech":
      return <TechWorkbench loading={loading} report={report} />;
    case "subs":
      return <SubsWorkbench loading={loading} report={report} />;
    case "reverse":
      return <ReverseWorkbench loading={loading} report={report} />;
    case "arch":
      return <ArchWorkbench loading={loading} report={report} />;
    case "tls-audit":
      return <TLSAuditWorkbench loading={loading} report={report} />;
    case "takeover":
      return <TakeoverWorkbench loading={loading} report={report} />;
    case "ports":
      return <PortScanWorkbench loading={loading} report={report} />;
    case "enum":
      return <PathEnumWorkbench loading={loading} report={report} />;
    case "audit":
      return <AuditWorkbench loading={loading} report={report} />;
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

// ─── v1.4 passive recon panels ────────────────────────────────────────────

function HeadersWorkbench({ loading, report }: { loading: boolean; report: HeadersReport }) {
  return (
    <section className={loading ? "result-area result-area-loading" : "result-area"}>
      <div className="result-header">
        <h1>Headers: <span>{report.url}</span></h1>
        <div className={`health-pill ${report.summary.missing === 0 && report.summary.weak === 0 ? "health-pill-ok" : "health-pill-fail"}`}>
          <span />
          {report.summary.pass} pass · {report.summary.weak} weak · {report.summary.missing} missing
        </div>
      </div>
      {report.error ? <ErrorBanner message={report.error} /> : null}
      <Panel className="dns-panel" icon={<LockKeyhole />} title="Security headers">
        <div className="dns-table">
          <div className="dns-header dns-row-3">
            <span>Grade</span>
            <span>Header</span>
            <span>Note</span>
          </div>
          {(report.findings ?? []).map((f) => (
            <div className="dns-row dns-row-3" key={f.name}>
              <span className={gradeClass(f.grade)}>{f.grade.toUpperCase()}</span>
              <span>
                <strong>{f.name}</strong>
                {f.value ? <code style={{ display: "block", marginTop: 4 }}>{f.value}</code> : null}
              </span>
              <span className="muted">{f.comment ?? "—"}</span>
            </div>
          ))}
        </div>
      </Panel>
    </section>
  );
}

function gradeClass(grade: "pass" | "weak" | "missing" | "info"): string {
  switch (grade) {
    case "pass":
      return "value-ok";
    case "weak":
      return "value-warn";
    case "missing":
      return "value-fail";
    default:
      return "muted";
  }
}

function TechWorkbench({ loading, report }: { loading: boolean; report: TechReport }) {
  const matches = report.matches ?? [];
  return (
    <section className={loading ? "result-area result-area-loading" : "result-area"}>
      <div className="result-header">
        <h1>Tech: <span>{report.url}</span></h1>
        <div className="health-pill health-pill-ok">
          <span />
          {matches.length} match{matches.length === 1 ? "" : "es"}
        </div>
      </div>
      {report.error ? <ErrorBanner message={report.error} /> : null}
      {matches.length === 0 ? (
        <p className="muted">No known technologies fingerprinted.</p>
      ) : (
        <Panel className="dns-panel" icon={<FileText />} title="Detected stack">
          <div className="dns-table">
            <div className="dns-header dns-row-4">
              <span>Technology</span>
              <span>Category</span>
              <span>Version</span>
              <span>Confidence</span>
            </div>
            {matches.map((m, i) => (
              <div className="dns-row dns-row-4" key={`${m.name}-${i}`}>
                <span><strong>{m.name}</strong></span>
                <code>{m.category}</code>
                <code>{m.version ?? "—"}</code>
                <span>{m.confidence}</span>
              </div>
            ))}
          </div>
        </Panel>
      )}
    </section>
  );
}

function SubsWorkbench({ loading, report }: { loading: boolean; report: SubsReport }) {
  const subs = report.subdomains ?? [];
  const errors = report.source_errors ?? {};
  return (
    <section className={loading ? "result-area result-area-loading" : "result-area"}>
      <div className="result-header">
        <h1>Subdomains: <span>{report.domain}</span></h1>
        <div className="health-pill health-pill-ok">
          <span />
          {subs.length} found
        </div>
      </div>
      {report.error ? <ErrorBanner message={report.error} /> : null}
      <Panel className="dns-panel" icon={<Globe />} title="From CT logs">
        {subs.length === 0 ? (
          <p className="muted">No subdomains found in CT logs.</p>
        ) : (
          <div className="dns-table">
            <div className="dns-header">
              <span>Name</span>
              <span>Sources</span>
            </div>
            {subs.map((s) => (
              <div className="dns-row" key={s.name}>
                <code>{s.name}</code>
                <span className="muted">{s.sources.join(", ")}</span>
              </div>
            ))}
          </div>
        )}
      </Panel>
      {Object.keys(errors).length > 0 ? (
        <Panel className="dns-panel" icon={<AlertTriangle />} title="Source errors">
          <ul>
            {Object.entries(errors).map(([name, msg]) => (
              <li key={name}><strong>{name}:</strong> <span className="muted">{msg}</span></li>
            ))}
          </ul>
        </Panel>
      ) : null}
    </section>
  );
}

function ReverseWorkbench({ loading, report }: { loading: boolean; report: ReverseReport }) {
  const hostnames = report.hostnames ?? [];
  return (
    <section className={loading ? "result-area result-area-loading" : "result-area"}>
      <div className="result-header">
        <h1>Reverse IP: <span>{report.ip}</span></h1>
        <div className="health-pill health-pill-ok">
          <span />
          {hostnames.length} hostname{hostnames.length === 1 ? "" : "s"}
        </div>
      </div>
      {report.error ? <ErrorBanner message={report.error} /> : null}
      <Panel className="dns-panel" icon={<Globe />} title="Hostnames on this IP">
        {hostnames.length === 0 ? (
          <p className="muted">No hostnames found.</p>
        ) : (
          <div className="dns-table">
            <div className="dns-header">
              <span>Hostname</span>
              <span>Sources</span>
            </div>
            {hostnames.map((h) => (
              <div className="dns-row" key={h.name}>
                <code>{h.name}</code>
                <span className="muted">{h.sources.join(", ")}</span>
              </div>
            ))}
          </div>
        )}
      </Panel>
      {report.source_disabled && report.source_disabled.length > 0 ? (
        <p className="muted">Disabled (no API key): {report.source_disabled.join(", ")}</p>
      ) : null}
    </section>
  );
}

function ArchWorkbench({ loading, report }: { loading: boolean; report: ArchReport }) {
  return (
    <section className={loading ? "result-area result-area-loading" : "result-area"}>
      <div className="result-header">
        <h1>Wayback: <span>{report.domain}</span></h1>
        <div className="health-pill health-pill-ok">
          <span />
          {report.total} snapshot{report.total === 1 ? "" : "s"}
        </div>
      </div>
      {report.error ? <ErrorBanner message={report.error} /> : null}
      <Panel className="dns-panel" icon={<History />} title="Coverage">
        <dl className="certificate-grid">
          <Detail label="Total snapshots" value={String(report.total)} />
          <Detail label="Unique URLs" value={String(report.unique_urls)} />
          {report.first ? <Detail label="First seen" value={formatDate(report.first)} /> : null}
          {report.last ? <Detail label="Last seen" value={formatDate(report.last)} /> : null}
        </dl>
      </Panel>
      {report.recent_samples && report.recent_samples.length > 0 ? (
        <Panel className="dns-panel" icon={<FileText />} title={`Recent snapshots (${report.recent_samples.length})`}>
          <div className="dns-table">
            <div className="dns-header dns-row-3">
              <span>Date</span>
              <span>Status</span>
              <span>URL</span>
            </div>
            {report.recent_samples.map((s, i) => (
              <div className="dns-row dns-row-3" key={`${s.url}-${i}`}>
                <span>{formatDate(s.timestamp)}</span>
                <code>{s.status ? s.status : "—"}</code>
                <code style={{ wordBreak: "break-all" }}>{s.url}</code>
              </div>
            ))}
          </div>
        </Panel>
      ) : null}
    </section>
  );
}

// ─── v1.4 active scanning panels ──────────────────────────────────────────

function TLSAuditWorkbench({ loading, report }: { loading: boolean; report: TLSAuditReport }) {
  const highCount = (report.findings ?? []).filter((f) => f.severity === "high").length;
  return (
    <section className={loading ? "result-area result-area-loading" : "result-area"}>
      <div className="result-header">
        <h1>TLS Audit: <span>{report.host}:{report.port}</span></h1>
        <div className={`health-pill ${highCount === 0 ? "health-pill-ok" : "health-pill-fail"}`}>
          <span />
          {highCount === 0 ? "No high-severity findings" : `${highCount} high-severity finding${highCount === 1 ? "" : "s"}`}
        </div>
      </div>
      {report.error ? <ErrorBanner message={report.error} /> : null}

      <Panel className="dns-panel" icon={<LockKeyhole />} title="Protocols">
        <div className="dns-table">
          <div className="dns-header dns-row-4">
            <span>Protocol</span>
            <span>Supported</span>
            <span>Deprecated</span>
            <span>Cipher</span>
          </div>
          {(report.protocols ?? []).map((p) => (
            <div className="dns-row dns-row-4" key={p.name}>
              <span><strong>{p.name}</strong></span>
              <span className={p.supported ? "value-ok" : "muted"}>{p.supported ? "yes" : "no"}</span>
              <span className={p.deprecated ? "value-fail" : "muted"}>{p.deprecated ? "deprecated" : "—"}</span>
              <code>{p.cipher ?? "—"}</code>
            </div>
          ))}
        </div>
      </Panel>

      {report.ciphers && report.ciphers.length > 0 ? (
        <Panel className="dns-panel" icon={<LockKeyhole />} title={`Supported cipher suites (${report.ciphers.length})`}>
          <div className="dns-table">
            <div className="dns-header dns-row-3">
              <span>Version</span>
              <span>Cipher</span>
              <span>Notes</span>
            </div>
            {report.ciphers.map((c) => (
              <div className="dns-row dns-row-3" key={c.name}>
                <span>{c.version ?? "—"}</span>
                <code>{c.name}</code>
                <span className={c.insecure ? "value-fail" : "muted"}>{c.insecure ? "WEAK" : ""}</span>
              </div>
            ))}
          </div>
        </Panel>
      ) : null}

      {report.cert ? (
        <Panel className="dns-panel" icon={<LockKeyhole />} title="Certificate">
          <dl className="certificate-grid">
            <Detail label="Subject" value={report.cert.subject} />
            <Detail label="Issuer" value={report.cert.issuer} />
            <Detail label="Validity" value={`${formatDate(report.cert.not_before)} → ${formatDate(report.cert.not_after)} (${report.cert.days_remaining}d)`} />
            <Detail label="Chain length" value={String(report.cert.chain_len)} />
            {report.cert.self_signed ? <Detail label="Self-signed" value="yes" /> : null}
            {report.cert.expired ? <Detail error label="Expired" value="yes" /> : null}
          </dl>
        </Panel>
      ) : null}

      {report.findings && report.findings.length > 0 ? (
        <Panel className="dns-panel" icon={<AlertTriangle />} title="Findings">
          <ul>
            {report.findings.map((f, i) => (
              <li key={i}>
                <strong className={severityClass(f.severity)}>[{f.severity.toUpperCase()}]</strong> {f.title}
                {f.detail ? <div className="muted">{f.detail}</div> : null}
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}
    </section>
  );
}

function severityClass(severity: string): string {
  switch (severity) {
    case "high":
      return "value-fail";
    case "medium":
      return "value-warn";
    default:
      return "muted";
  }
}

function TakeoverWorkbench({ loading, report }: { loading: boolean; report: TakeoverReport }) {
  const findings = report.findings ?? [];
  const vuln = findings.some((f) => f.verdict === "vulnerable");
  return (
    <section className={loading ? "result-area result-area-loading" : "result-area"}>
      <div className="result-header">
        <h1>Takeover: <span>{report.domain}</span></h1>
        <div className={`health-pill ${vuln ? "health-pill-fail" : "health-pill-ok"}`}>
          <span />
          {vuln ? "VULNERABLE" : report.has_cname ? "No takeover detected" : "No CNAME"}
        </div>
      </div>
      {report.error ? <ErrorBanner message={report.error} /> : null}
      {!report.has_cname ? (
        <p className="muted">No CNAME record on this domain. Nothing to check.</p>
      ) : null}
      {findings.map((f, i) => (
        <Panel className="dns-panel" icon={<AlertTriangle />} key={i} title={f.provider || "Unknown provider"}>
          <dl className="certificate-grid">
            <Detail label="CNAME" value={f.cname} />
            {f.provider ? <Detail label="Provider" value={f.provider} /> : null}
            <Detail
              error={f.verdict === "vulnerable"}
              label="Verdict"
              value={f.verdict === "vulnerable" ? "VULNERABLE — this CNAME can be taken over" : f.verdict}
            />
            {f.status ? <Detail label="Status" value={String(f.status)} /> : null}
            {f.detail ? <Detail label="Detail" value={f.detail} /> : null}
            {f.notes ? <Detail label="Notes" value={f.notes} /> : null}
          </dl>
        </Panel>
      ))}
    </section>
  );
}

// PortsTable renders the open-port list. When at least one port has a banner
// we widen to a 3-column layout (port / service / banner); otherwise it stays
// at the original 2 columns. This avoids burning real estate on an empty
// banner column when banners are off or every open port is TLS-wrapped.
function PortsTable({ ports }: { ports: NonNullable<PortScanReport["ports"]> }) {
  const showBanner = ports.some((p) => p.banner && p.banner.length > 0);
  if (!showBanner) {
    return (
      <div className="dns-table">
        <div className="dns-header">
          <span>Port</span>
          <span>Service</span>
        </div>
        {ports.map((p) => (
          <div className="dns-row" key={p.port}>
            <code>{p.port}</code>
            <span>{p.service || "—"}</span>
          </div>
        ))}
      </div>
    );
  }
  return (
    <div className="dns-table">
      <div className="dns-header dns-row-3">
        <span>Port</span>
        <span>Service</span>
        <span>Banner</span>
      </div>
      {ports.map((p) => (
        <div className="dns-row dns-row-3" key={p.port}>
          <code>{p.port}</code>
          <span>{p.service || "—"}</span>
          <code className="banner-cell" title={p.banner || ""}>
            {p.banner || "—"}
          </code>
        </div>
      ))}
    </div>
  );
}

function PortScanWorkbench({ loading, report }: { loading: boolean; report: PortScanReport }) {
  const ports = report.ports ?? [];
  return (
    <section className={loading ? "result-area result-area-loading" : "result-area"}>
      <div className="result-header">
        <h1>
          Ports: <span>{report.host}</span>
          {report.ip && report.ip !== report.host ? <span className="muted"> ({report.ip})</span> : null}
        </h1>
        <div className="health-pill health-pill-ok">
          <span />
          {report.stats.open} open / {report.stats.total} scanned
        </div>
      </div>
      {report.error ? <ErrorBanner message={report.error} /> : null}
      <div className="summary-strip">
        <SummaryCard label="Open" value={String(report.stats.open)} />
        <SummaryCard label="Closed" value={String(report.stats.closed)} />
        <SummaryCard label="Filtered" value={String(report.stats.filtered)} />
        <SummaryCard label="Total" value={String(report.stats.total)} />
      </div>
      <Panel className="dns-panel" icon={<Globe />} title={`Open ports (${ports.length})`}>
        {ports.length === 0 ? (
          <p className="muted">No open ports found.</p>
        ) : (
          <PortsTable ports={ports} />
        )}
      </Panel>
    </section>
  );
}

function PathEnumWorkbench({ loading, report }: { loading: boolean; report: PathEnumReport }) {
  const findings = report.findings ?? [];
  return (
    <section className={loading ? "result-area result-area-loading" : "result-area"}>
      <div className="result-header">
        <h1>Path Enum: <span>{report.base_url}</span></h1>
        <div className="health-pill health-pill-ok">
          <span />
          {report.stats.interesting} interesting / {report.stats.total} scanned
        </div>
      </div>
      {report.error ? <ErrorBanner message={report.error} /> : null}
      <div className="summary-strip">
        <SummaryCard label="Interesting" value={String(report.stats.interesting)} />
        <SummaryCard label="404 / 410" value={String(report.stats.not_found)} />
        <SummaryCard label="Errors" value={String(report.stats.errors)} />
        <SummaryCard label="Total" value={String(report.stats.total)} />
      </div>
      <Panel className="dns-panel" icon={<FileText />} title={`Findings (${findings.length})`}>
        {findings.length === 0 ? (
          <p className="muted">No interesting paths found.</p>
        ) : (
          <div className="dns-table">
            <div className="dns-header dns-row-4">
              <span>Status</span>
              <span>Category</span>
              <span>Path</span>
              <span>Notes</span>
            </div>
            {findings.map((f, i) => (
              <div className="dns-row dns-row-4" key={`${f.path}-${i}`}>
                <code>{f.status}</code>
                <span>{f.category}</span>
                <code style={{ wordBreak: "break-all" }}>{f.path}</code>
                <span className="muted">
                  {f.redirect ? `→ ${f.redirect}` : f.length ? `${f.length} bytes` : ""}
                </span>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </section>
  );
}

// ─── v1.6 audit aggregate panel ──────────────────────────────────────────
//
// Compact, single-table grade matrix — mirrors the CLI's text renderer.
// Full per-section detail isn't stitched together here; users wanting that
// can run the individual command in its own tab, or pipe the audit through
// `--output json`.

function AuditWorkbench({ loading, report }: { loading: boolean; report: AuditReport }) {
  const rows = useMemo(() => auditRows(report), [report]);
  const highs = rows.filter((r) => r.grade === "high").length;
  const weaks = rows.filter((r) => r.grade === "weak").length;
  const pillClass = highs > 0 ? "health-pill-fail" : "health-pill-ok";
  const pillText =
    highs > 0
      ? `${highs} high · ${weaks} weak`
      : weaks > 0
        ? `${weaks} weak finding${weaks === 1 ? "" : "s"}`
        : "No findings";
  const mode = report.active ? "passive + active" : "passive";
  return (
    <section className={loading ? "result-area result-area-loading" : "result-area"}>
      <div className="result-header">
        <h1>
          Audit: <span>{report.target}</span>
          {report.host && report.host !== report.target ? (
            <span className="muted"> (host: {report.host})</span>
          ) : null}
        </h1>
        <div className={`health-pill ${pillClass}`}>
          <span />
          {pillText}
        </div>
      </div>
      <p className="muted">Mode: {mode} · {report.took_ms}ms</p>
      {report.error ? <ErrorBanner message={report.error} /> : null}

      <Panel className="dns-panel" icon={<FileText />} title="Sections">
        <div className="dns-table">
          <div className="dns-header dns-row-3">
            <span>Grade</span>
            <span>Section</span>
            <span>Summary</span>
          </div>
          {rows.map((row) => (
            <div className="dns-row dns-row-3" key={row.label}>
              <span className={auditGradeClass(row.grade)}>{auditGradeTag(row.grade)}</span>
              <span><strong>{row.label}</strong></span>
              <span className="muted">{row.summary}</span>
            </div>
          ))}
        </div>
      </Panel>

      {report.errors && Object.keys(report.errors).length > 0 ? (
        <Panel className="dns-panel" icon={<AlertTriangle />} title="Sub-command errors">
          <ul>
            {Object.entries(report.errors).map(([name, msg]) => (
              <li key={name}>
                <strong>{name}:</strong> <span className="muted">{msg}</span>
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}
    </section>
  );
}

type AuditRow = { label: string; grade: AuditGrade; summary: string };

function auditRows(r: AuditReport): AuditRow[] {
  const rows: AuditRow[] = [];
  if (r.ip) {
    rows.push({ label: "IP", grade: r.ip.details.length === 0 ? "err" : "ok", summary: ipSummary(r.ip) });
  }
  if (r.reverse) {
    rows.push({
      label: "Reverse",
      grade: r.reverse.error ? "err" : "ok",
      summary: r.reverse.error ?? `${(r.reverse.hostnames ?? []).length} hostname(s)`,
    });
  }
  if (r.subs) {
    const n = (r.subs.subdomains ?? []).length;
    const errs = Object.keys(r.subs.source_errors ?? {}).length;
    rows.push({
      label: "Subdomains",
      grade: r.subs.error ? "err" : "ok",
      summary: r.subs.error ?? (errs > 0 ? `${n} found · ${errs} source(s) errored` : `${n} found`),
    });
  }
  if (r.arch) {
    rows.push({
      label: "Wayback",
      grade: r.arch.error ? "err" : "ok",
      summary: r.arch.error ?? archSummary(r.arch),
    });
  }
  if (r.headers) {
    const grade: AuditGrade = r.headers.error
      ? "err"
      : r.headers.summary.missing > 0
        ? "high"
        : r.headers.summary.weak > 0
          ? "weak"
          : "ok";
    rows.push({
      label: "Headers",
      grade,
      summary:
        r.headers.error ??
        `${r.headers.summary.pass} pass · ${r.headers.summary.weak} weak · ${r.headers.summary.missing} missing`,
    });
  }
  if (r.tech) {
    rows.push({
      label: "Tech",
      grade: r.tech.error ? "err" : "ok",
      summary: r.tech.error ?? techSummary(r.tech),
    });
  }
  if (r.tls) {
    rows.push({ label: "TLS", grade: tlsAuditGrade(r.tls), summary: tlsAuditSummary(r.tls) });
  }
  if (r.takeover) {
    const hasVuln = (r.takeover.findings ?? []).some((f) => f.verdict === "vulnerable");
    rows.push({
      label: "Takeover",
      grade: r.takeover.error ? "err" : hasVuln ? "high" : "ok",
      summary: takeoverSummary(r.takeover),
    });
  }
  if (r.ports) {
    rows.push({
      label: "Ports",
      grade: r.ports.error ? "err" : "ok",
      summary: r.ports.error ?? `${r.ports.stats.open} open / ${r.ports.stats.total} scanned`,
    });
  }
  if (r.enum) {
    rows.push({
      label: "Path enum",
      grade: r.enum.error ? "err" : r.enum.stats.interesting > 0 ? "weak" : "ok",
      summary:
        r.enum.error ?? `${r.enum.stats.interesting} interesting / ${r.enum.stats.total} scanned`,
    });
  }
  return rows;
}

function ipSummary(d: IPInfoReport): string {
  const parts: string[] = [`${d.details.length} address(es)`];
  const asn = d.details.find((det) => det.asn)?.asn;
  if (asn) parts.push(`AS${asn.asn} ${asn.org ?? ""}`.trim());
  const cdn = d.details.find((det) => det.cdn?.provider)?.cdn;
  if (cdn?.provider) parts.push(`CDN: ${cdn.provider}`);
  return parts.join(" · ");
}

function archSummary(d: ArchReport): string {
  if (d.total === 0) return "no snapshots";
  if (d.first && d.last) {
    return `${d.total} snapshots · ${d.first.slice(0, 10)} → ${d.last.slice(0, 10)}`;
  }
  return `${d.total} snapshots`;
}

function techSummary(d: TechReport): string {
  const matches = d.matches ?? [];
  if (matches.length === 0) return "no fingerprints matched";
  const top = matches.slice(0, 4).map((m) => (m.version ? `${m.name} ${m.version}` : m.name));
  if (matches.length > 4) top.push(`+${matches.length - 4} more`);
  return top.join(", ");
}

function tlsAuditSummary(d: TLSAuditReport): string {
  if (d.error) return d.error;
  const highs = (d.findings ?? []).filter((f) => f.severity === "high").length;
  if (highs > 0) return `${highs} high-severity finding(s)`;
  return "no high-severity findings";
}

function tlsAuditGrade(d: TLSAuditReport): AuditGrade {
  if (d.error) return "err";
  const sev = (d.findings ?? []).map((f) => f.severity);
  if (sev.includes("high")) return "high";
  if (sev.includes("medium")) return "weak";
  return "ok";
}

function takeoverSummary(d: TakeoverReport): string {
  if (d.error) return d.error;
  if (!d.has_cname) return "no CNAME (nothing to check)";
  const vuln = (d.findings ?? []).find((f) => f.verdict === "vulnerable");
  if (vuln) return `VULNERABLE — ${vuln.provider ?? "unknown provider"}`;
  return "no takeover detected";
}

function auditGradeTag(g: AuditGrade): string {
  return g === "ok" ? "OK" : g === "weak" ? "WEAK" : g === "high" ? "HIGH" : "ERR";
}

function auditGradeClass(g: AuditGrade): string {
  return g === "ok"
    ? "value-ok"
    : g === "weak"
      ? "value-warn"
      : g === "high"
        ? "value-fail"
        : "muted";
}

// ─── Shared building blocks ───────────────────────────────────────────────

function EmptyWorkbench({ mode, onRun }: { mode: CheckMode; onRun: () => void }) {
  const blurb: Record<CheckMode, string> = {
    full: "DNS, TCP, TLS, HTTP, redirects, and timing land in one report.",
    dns: "Query Cloudflare, Google, Quad9, and your system resolver in parallel — see if they agree.",
    route: "Trace the network path with per-hop ASN ownership.",
    ip: "Get reverse DNS, ASN, RDAP, country, and CDN classification for an IP or hostname.",
    headers: "Grade HSTS, CSP, X-Frame-Options, and the other security headers from one HTTP GET.",
    tech: "Fingerprint CMS, JS framework, server, CDN, and language from one passive GET.",
    subs: "Enumerate subdomains from public Certificate Transparency logs.",
    reverse: "List other hostnames pointing at the IP via PTR records, Hackertarget, and Shodan if configured.",
    arch: "Show what the Wayback Machine remembers about this domain — first/last snapshots and recent URLs.",
    tls: "Probe every TLS protocol and cipher suite; grade deprecated protocols, weak ciphers, expiring certs.",
    takeover: "Check the CNAME against a catalog of takeover-able services (GitHub Pages, S3, Heroku, …).",
    ports: "Parallel TCP connect scan against the top-100 nmap ports (or a custom list).",
    enum: "Send one GET per wordlist entry; report 200 / 301 / 401 / 403 / 5xx responses.",
    audit: "Run the passive recon suite (ip + headers + tech + subs + arch) in parallel. Tick the box above for the active add-ons.",
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
    case "headers":
    case "tech":
      return report.url;
    case "subs":
    case "arch":
    case "takeover":
      return report.domain;
    case "reverse":
      return report.ip;
    case "tls-audit":
    case "ports":
      return report.host;
    case "enum":
      return report.base_url;
    case "audit":
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
    case "headers":
      return report.summary.missing === 0 && report.summary.weak === 0;
    case "tech":
      return !report.error;
    case "subs":
      return (report.subdomains?.length ?? 0) > 0;
    case "reverse":
      return (report.hostnames?.length ?? 0) > 0;
    case "arch":
      return report.total > 0;
    case "tls-audit":
      return (report.findings ?? []).every((f) => f.severity !== "high");
    case "takeover":
      return !(report.findings ?? []).some((f) => f.verdict === "vulnerable");
    case "ports":
      return report.stats.open > 0;
    case "enum":
      return report.stats.interesting > 0;
    case "audit":
      // Audit is "OK" iff no sub-section came back HIGH-severity.
      return auditRowGrades(report).every((g) => g !== "high");
  }
}

// auditRowGrades returns the per-section grade for every sub-report that
// ran. Mirrors the CLI renderer's `audit*Grade` helpers but lives in the
// UI so we can colour the cells without round-tripping through the server.
function auditRowGrades(report: AuditReport): AuditGrade[] {
  const grades: AuditGrade[] = [];
  if (report.ip) {
    grades.push(report.ip.details.length === 0 ? "err" : "ok");
  }
  if (report.reverse) {
    grades.push(report.reverse.error ? "err" : "ok");
  }
  if (report.subs) {
    if (report.subs.error) grades.push("err");
    else grades.push("ok");
  }
  if (report.arch) {
    grades.push(report.arch.error ? "err" : "ok");
  }
  if (report.headers) {
    if (report.headers.error) grades.push("err");
    else if (report.headers.summary.missing > 0) grades.push("high");
    else if (report.headers.summary.weak > 0) grades.push("weak");
    else grades.push("ok");
  }
  if (report.tech) {
    grades.push(report.tech.error ? "err" : "ok");
  }
  if (report.tls) {
    if (report.tls.error) grades.push("err");
    else if ((report.tls.findings ?? []).some((f) => f.severity === "high")) grades.push("high");
    else if ((report.tls.findings ?? []).some((f) => f.severity === "medium")) grades.push("weak");
    else grades.push("ok");
  }
  if (report.takeover) {
    if (report.takeover.error) grades.push("err");
    else if ((report.takeover.findings ?? []).some((f) => f.verdict === "vulnerable")) grades.push("high");
    else grades.push("ok");
  }
  if (report.ports) {
    grades.push(report.ports.error ? "err" : "ok");
  }
  if (report.enum) {
    if (report.enum.error) grades.push("err");
    else if (report.enum.stats.interesting > 0) grades.push("weak");
    else grades.push("ok");
  }
  return grades;
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
