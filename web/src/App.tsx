import {
  Download,
  FileText,
  Globe,
  History,
  LockKeyhole,
  Menu,
  Play,
  RotateCcw,
  Settings2,
  X,
} from "lucide-react";
import { FormEvent, ReactNode, useEffect, useMemo, useState } from "react";
import { runFullCheck } from "./api";
import type { FullCheckReport, RecentCheck } from "./types";

const HISTORY_KEY = "netcheck.recent-checks.v1";
const MAX_RECENTS = 8;

type RunState = "idle" | "loading" | "ready" | "error";

export default function App() {
  const [target, setTarget] = useState("google.com");
  const [report, setReport] = useState<FullCheckReport | null>(null);
  const [runState, setRunState] = useState<RunState>("idle");
  const [error, setError] = useState("");
  const [insecure, setInsecure] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [recents, setRecents] = useState<RecentCheck[]>(readRecents);

  useEffect(() => {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(recents));
  }, [recents]);

  async function submitCheck(event?: FormEvent<HTMLFormElement>) {
    event?.preventDefault();
    const nextTarget = target.trim();
    if (!nextTarget) {
      setError("Enter a URL, host, or IP address.");
      setRunState("error");
      return;
    }

    setRunState("loading");
    setError("");
    try {
      const nextReport = await runFullCheck(nextTarget, insecure);
      setReport(nextReport);
      setRunState("ready");
      setHistoryOpen(false);
      setRecents((current) => upsertRecent(current, nextReport));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The check could not start.");
      setRunState("error");
    }
  }

  function exportReport() {
    if (!report) {
      return;
    }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = `netcheck-${report.target.host || "report"}.json`;
    anchor.click();
    URL.revokeObjectURL(href);
  }

  function rerunRecent(recent: RecentCheck) {
    setTarget(recent.target);
    setHistoryOpen(false);
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
          <button className="nav-item nav-item-active" type="button">
            <RotateCcw />
            <span>Recent Checks</span>
          </button>
          <button className="nav-item" type="button">
            <FileText />
            <span>Saved Reports</span>
          </button>
        </nav>
        <section className="recent-list" aria-label="Recent checks">
          {recents.map((recent) => (
            <button className="recent-item" key={`${recent.target}-${recent.ranAt}`} onClick={() => rerunRecent(recent)} type="button">
              <span className={`recent-dot ${recent.ok ? "recent-dot-ok" : "recent-dot-fail"}`} />
              <span>
                <strong>{recent.target}</strong>
                <time>{formatRecentTime(recent.ranAt)}</time>
              </span>
            </button>
          ))}
        </section>
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
            <button aria-selected="true" className="mode-tab mode-tab-active" role="tab" type="button">
              Full Check
            </button>
            <button className="mode-tab" disabled role="tab" type="button">
              DNS Compare
            </button>
            <button className="mode-tab" disabled role="tab" type="button">
              Route
            </button>
            <button className="mode-tab" disabled role="tab" type="button">
              IP Info
            </button>
          </div>
        </form>

        {settingsOpen ? (
          <section className="settings-panel" aria-label="Check settings">
            <div>
              <strong>Check Settings</strong>
              <p>TLS verification stays on unless this run needs inspection of an invalid certificate.</p>
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

        {runState === "idle" ? <EmptyWorkbench onRun={() => void submitCheck()} /> : null}
        {runState === "error" ? <ErrorBanner message={error} /> : null}
        {report ? <FullCheckWorkbench loading={runState === "loading"} report={report} /> : null}
      </main>
    </div>
  );
}

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

function EmptyWorkbench({ onRun }: { onRun: () => void }) {
  return (
    <section className="empty-workbench">
      <div>
        <span>Ready</span>
        <h1>Run a full network check.</h1>
        <p>DNS, TCP, TLS, HTTP, redirects, and timing land in one report.</p>
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

function readRecents(): RecentCheck[] {
  try {
    const saved = localStorage.getItem(HISTORY_KEY);
    return saved ? (JSON.parse(saved) as RecentCheck[]) : [];
  } catch {
    return [];
  }
}

function upsertRecent(current: RecentCheck[], report: FullCheckReport): RecentCheck[] {
  const next = {
    ok: report.ok,
    ranAt: report.started_at,
    target: report.target.raw,
  };
  return [next, ...current.filter((item) => item.target !== next.target)].slice(0, MAX_RECENTS);
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
