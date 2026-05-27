import {
  AlertTriangle,
  Bookmark,
  Check,
  ChevronLeft,
  Download,
  FileText,
  GitCompare,
  Globe,
  History,
  Layers,
  LockKeyhole,
  Play,
  Search,
  Settings2,
  ShieldAlert,
  Telescope,
  Terminal,
  Trash2,
} from "lucide-react";
import { ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import {
  deleteSavedReport,
  diffReports,
  listSavedReports,
  loadSavedReport,
  runArchCheck,
  runAuditCheck,
  runDNSCheck,
  runEnumCheck,
  runFullCheck,
  runHeadersCheck,
  runIPCheck,
  streamPortsCheck,
  type PortProgress,
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
  DiffReport,
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
import { isActiveMode } from "./types";

const ACTIVE_ACK_KEY = "netcheck.active-ack.v1";

const HISTORY_KEY = "netcheck.recent-checks.v1";
const MAX_RECENTS = 8;

type RunState = "idle" | "loading" | "ready" | "error";

// R-1 redesign: top-level navigation routes (sidenav on desktop,
// bottom-nav on mobile). Workbench is the default; history / reports /
// settings are placeholder routes whose visual content R-8 redesigns.
// For R-1 they reuse the existing inline content via shared state.
type Route = "workbench" | "history" | "reports" | "settings";

// Category groups the 14 check modes for the landing-screen card grid.
// "aggregate" is the fourth category — covers audit + diff + watch.
type Category = "network" | "recon" | "scanning" | "aggregate";

type CategoryDef = {
  key: Category;
  label: string;
  blurb: string;
  modes: CheckMode[];
};

// Single source of truth for the category → mode mapping. The landing
// CategoryCard reads `label`/`blurb`; the category-detail screen (R-2)
// will read `modes` to render per-mode ModeCards.
const CATEGORIES: CategoryDef[] = [
  {
    key: "network",
    label: "Network",
    blurb: "Connectivity, DNS, routing, IP ownership.",
    modes: ["full", "dns", "route", "ip"],
  },
  {
    key: "recon",
    label: "Recon",
    blurb: "Passive intel — headers, tech stack, subdomains, history.",
    modes: ["headers", "tech", "subs", "reverse", "arch"],
  },
  {
    key: "scanning",
    label: "Scanning",
    blurb: "Active probes — TLS audit, takeover, ports, paths. Requires authorization.",
    modes: ["tls", "takeover", "ports", "enum"],
  },
  {
    key: "aggregate",
    label: "Aggregate",
    blurb: "Run an audit across categories, or diff two saved scans.",
    modes: ["audit"],
  },
];

// modeCategory returns the category that owns a given check mode. Used
// to set the category state when the user reruns from history or opens
// a saved report (so the workbench shows the right category context).
function modeCategory(mode: CheckMode): Category {
  for (const cat of CATEGORIES) {
    if (cat.modes.includes(mode)) {
      return cat.key;
    }
  }
  return "network";
}

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

// MODE_BLURB is the one-liner description shown on each ModeCard inside
// a category-detail screen. R-2 surface.
const MODE_BLURB: Record<CheckMode, string> = {
  full: "DNS + TCP + TLS + HTTP probe with redirect chain and timing.",
  dns: "Compare A/AAAA/MX/TXT answers across Cloudflare, Google, Quad9, system, and any custom resolvers.",
  route: "Traceroute to the target with per-hop ASN annotation.",
  ip: "RDAP, reverse DNS, CDN affiliation, ASN ownership.",
  headers:
    "Grade HSTS, CSP, X-Frame-Options, and the rest of the security-relevant response headers.",
  tech: "Fingerprint the CMS, framework, server, CDN, and language from one passive GET.",
  subs: "Enumerate subdomains from Certificate Transparency logs (crt.sh + CertSpotter).",
  reverse: "Other hostnames pointing at this IP — reverse DNS, Hackertarget, optional Shodan.",
  arch: "Wayback Machine snapshot history — first/last seen, total snapshots, recent URLs.",
  tls: "Protocol matrix + cipher suites + certificate chain + expiry. Active.",
  takeover: "Is this CNAME pointing at an unclaimed third-party service? Active.",
  ports: "Parallel TCP connect scan with banner grab. Active.",
  enum: "HTTP path enumeration against a curated wordlist. Active.",
  audit: "Aggregate report across Network + Recon (passive) — optionally also Scanning (active).",
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
  // R-1 redesign state. `route` is the top-level page (workbench /
  // history / reports / settings); `category` is null on the landing
  // screen and set once the user picks a category card. When a report
  // is loaded (run or replayed from saved), category is auto-set to
  // the mode's owning category so the workbench shows the right context.
  const [route, setRoute] = useState<Route>("workbench");
  const [category, setCategory] = useState<Category | null>(null);
  // portsProgress is the live counter shown during a streaming ports scan.
  // null when no scan is in flight (or when running a non-streaming mode).
  const [portsProgress, setPortsProgress] = useState<{
    scanned: number;
    total: number;
    open: number;
  } | null>(null);
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
  // R-13: port-scan protocol selector. "tcp" everywhere is the default
  // (matches the CLI). "udp" probes only the curated UDP top-50 with
  // service-aware payloads; "both" runs TCP first, then UDP.
  const [portsProto, setPortsProto] = useState<"tcp" | "udp" | "both">("tcp");

  useEffect(() => {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(recents));
  }, [recents]);

  useEffect(() => {
    localStorage.setItem(ACTIVE_ACK_KEY, activeAcknowledged ? "1" : "");
  }, [activeAcknowledged]);

  const refreshSaved = useCallback(async () => {
    setSavedError("");
    try {
      setSaved(await listSavedReports());
    } catch (cause) {
      setSavedError(cause instanceof Error ? cause.message : "could not load saved reports");
    }
  }, []);

  // RouteReportsList triggers its own refresh on mount (see the useEffect
  // inside that component). No global watcher needed here in R-1.

  const runCheck = useCallback(
    async (overrideMode?: CheckMode, overrideTarget?: string, overrideAuditActive?: boolean) => {
      const effectiveMode = overrideMode ?? mode;
      const effectiveTarget = (overrideTarget ?? target).trim();
      // overrideAuditActive lets the ModeCard force the audit-active
      // flag synchronously — without it we'd read the stale
      // auditIncludeActive captured in this useCallback's closure.
      const effectiveAuditActive = overrideAuditActive ?? auditIncludeActive;
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
            // Streaming variant: per-port progress events tick a live counter
            // while the scan runs. The final `done` event carries the same
            // PortScanReport shape as the non-streaming endpoint, so the rest
            // of the flow (save, diff, recent) is unchanged.
            next = await new Promise<PortScanReport>((resolve, reject) => {
              setPortsProgress({ scanned: 0, total: 0, open: 0 });
              // Translate the UI's 3-option selector into the API's
              // `protocols` array. "tcp" stays `undefined` so the request
              // body is byte-identical to pre-R-13 (engine defaults to TCP
              // when the field is missing).
              const protocols =
                portsProto === "tcp"
                  ? undefined
                  : portsProto === "udp"
                    ? (["udp"] as Array<"tcp" | "udp">)
                    : (["tcp", "udp"] as Array<"tcp" | "udp">);
              streamPortsCheck(
                effectiveTarget,
                {
                  onProgress: (p: PortProgress) => {
                    setPortsProgress((prev) => ({
                      scanned: p.index,
                      total: p.total,
                      open: (prev?.open ?? 0) + (p.state === "open" ? 1 : 0),
                    }));
                  },
                  onDone: (r) => resolve(r),
                  onError: (e) => reject(e),
                },
                { protocols },
              );
            });
            setPortsProgress(null);
            break;
          case "enum":
            next = await runEnumCheck(effectiveTarget, { insecure });
            break;
          case "audit":
            next = await runAuditCheck(effectiveTarget, {
              active: effectiveAuditActive,
              insecure,
            });
            break;
          default:
            next = await runFullCheck(effectiveTarget, insecure);
        }
        setReport(next);
        setRunState("ready");
        setRecents((current) => upsertRecent(current, next, effectiveMode));
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : "The check could not start.");
        setRunState("error");
        // If a streaming scan errored mid-flight, drop the live counter so
        // it doesn't stick around from the failed run.
        setPortsProgress(null);
      }
    },
    [auditIncludeActive, insecure, mode, portsProto, target],
  );

  async function saveCurrent() {
    if (!report) {
      return;
    }
    setSavingNow(true);
    setSavedJustNow(false);
    try {
      await saveReport(report);
      setSavedJustNow(true);
      // RouteReportsList refreshes itself on mount when the Reports route
      // opens — no need to push state across routes here.
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
    setCategory(modeCategory(recent.mode));
    setRoute("workbench");
    void runCheck(recent.mode, recent.target);
  }

  async function openSaved(meta: SavedReportMeta) {
    try {
      const { report: loaded } = await loadSavedReport(meta.id);
      const m = kindToMode(loaded.kind);
      setReport(loaded);
      setMode(m);
      setCategory(modeCategory(m));
      setRoute("workbench");
      setTarget(reportTarget(loaded));
      setRunState("ready");
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

  // R-1 redesign: when the user picks a category card on the landing,
  // also default the mode to the first one in that category so the
  // existing per-category form has something selected. R-2 will replace
  // the inline form with ModeCards.
  function pickCategory(cat: Category) {
    setCategory(cat);
    const def = CATEGORIES.find((c) => c.key === cat);
    if (def && !def.modes.includes(mode)) {
      setMode(def.modes[0]);
    }
  }

  // backToLanding clears the category picker, leaving the report in
  // place so the user can come back to it; the workbench just shows
  // the landing again at the top.
  function backToLanding() {
    setCategory(null);
  }

  // R-12: when a check is running, blur the underlying shell + show a
  // fixed-position progress overlay above it. `app-shell-loading` adds
  // the blur and disables pointer interaction; the overlay handles its
  // own dismissal animation when runState flips away from "loading".
  const isLoading = runState === "loading";

  return (
    <div className={`app-shell ${isLoading ? "app-shell-loading" : ""}`}>
      <LoadingOverlay visible={isLoading} mode={mode} portsProgress={portsProgress} />
      <header className="topbar">
        <div className="topbar-leading">
          <div className="brand">
            <BrandMark />
            <span>netcheck</span>
          </div>
        </div>
        <div className="topbar-actions">
          <IconButton
            disabled={!report || savingNow}
            label={savedJustNow ? "Saved" : "Save report"}
            onClick={saveCurrent}
          >
            {savedJustNow ? <Check /> : <Bookmark />}
          </IconButton>
          <IconButton disabled={!report} label="Export JSON" onClick={exportReport}>
            <Download />
          </IconButton>
        </div>
      </header>

      <SideNavV2 route={route} onRouteChange={setRoute} />

      <main className="workbench">
        {route === "workbench" && category === null ? (
          <Landing
            target={target}
            onTargetChange={setTarget}
            onPickCategory={pickCategory}
            onRunDefault={() => {
              // Codex P1 on #73: the landing screen doesn't render the
              // report or the error banner. If we only called runCheck
              // here, a successful run would silently update `report`
              // state but the user would still see the landing — no
              // visible feedback. Navigate into the Network category
              // (which owns the Full check) and set mode=full BEFORE
              // kicking off the run, so CategoryDetail mounts with the
              // result area visible.
              setMode("full");
              setCategory("network");
              void runCheck("full");
            }}
            runDisabled={runState === "loading"}
          />
        ) : null}

        {route === "workbench" && category !== null ? (
          <CategoryDetail
            categoryDef={CATEGORIES.find((c) => c.key === category)!}
            target={target}
            onTargetChange={setTarget}
            onBack={backToLanding}
            onRun={(m, opts) => {
              setMode(m);
              if (opts?.auditActive !== undefined) {
                setAuditIncludeActive(opts.auditActive);
              }
              // Pass auditActive as a third arg to dodge the stale
              // closure on auditIncludeActive — the setState above
              // won't be visible inside this same render's runCheck.
              void runCheck(m, undefined, opts?.auditActive);
            }}
            runState={runState}
            runningMode={mode}
            activeAcknowledged={activeAcknowledged}
            onAcknowledge={setActiveAcknowledged}
            error={error}
            report={report}
            portsProgress={portsProgress}
            portsProto={portsProto}
            onPortsProtoChange={setPortsProto}
          />
        ) : null}

        {route === "history" ? <RouteHistoryList recents={recents} onRerun={rerunRecent} /> : null}

        {route === "reports" ? (
          <RouteReportsList
            saved={saved}
            savedError={savedError}
            onRefresh={refreshSaved}
            onOpen={openSaved}
            onRemove={removeSaved}
          />
        ) : null}

        {route === "settings" ? (
          <RouteSettings insecure={insecure} onInsecureChange={setInsecure} />
        ) : null}
      </main>

      <BottomNav route={route} onRouteChange={setRoute} />
      <StatusFooter lastScanAt={recents[0]?.ranAt} />
    </div>
  );
}

// ─── R-1 redesign: shell components ───────────────────────────────────────

// SideNavV2 renders the desktop sidenav with four top-level routes.
// Mobile users get a fixed BottomNav instead — see CSS media queries.
// BrandMark is the inline SVG icon next to the "netcheck" wordmark. R-11
// redrew this from the R-10 X+bars shape to the atom-style mark from the
// Stitch Modern v1 mockup: two crossing diagonal connectors with four dot
// endpoints (and a tiny center marker), evoking a network-of-nodes feel.
// Strokes pick up `currentColor`; dot fills pick up the same. Sized to
// match the wordmark cap height; pass `size` to override.
function BrandMark({ size = 20 }: { size?: number }) {
  return (
    <svg
      aria-hidden="true"
      className="brand-mark"
      fill="none"
      height={size}
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="1.6"
      viewBox="0 0 24 24"
      width={size}
      xmlns="http://www.w3.org/2000/svg"
    >
      {/* Crossing diagonals between the four corner nodes. */}
      <path d="M6 6 L18 18 M18 6 L6 18" />
      {/* Four endpoint nodes — filled so they read as solid dots. */}
      <circle cx="6" cy="6" fill="currentColor" r="2" stroke="none" />
      <circle cx="18" cy="6" fill="currentColor" r="2" stroke="none" />
      <circle cx="6" cy="18" fill="currentColor" r="2" stroke="none" />
      <circle cx="18" cy="18" fill="currentColor" r="2" stroke="none" />
      {/* Center node — a touch smaller so the X dominates. */}
      <circle cx="12" cy="12" fill="currentColor" r="1.2" stroke="none" />
    </svg>
  );
}

// LoadingOverlay — fixed-position glass card with animated progress ring,
// percentage readout, and cycling status messages. Mounted whenever a
// check is running; the underlying app-shell is blurred + scaled down
// via the `app-shell-loading` class.
//
// Two progress models:
//   - Real progress (ports SSE): pass `portsProgress` and the overlay
//     mirrors the scanned/total ratio.
//   - Synthetic ramp (every other mode): no real signal, so we ramp
//     smoothly from 0 → 90% over ~6 seconds and hold at 90% until the
//     check completes, then snap to 100% briefly before unmounting.
//     Matches the Stitch animation feel without lying about progress.
//
// Status messages cycle every 1.6s through a per-mode list — gives the
// user something to read while waiting. CSS pulse animation on the
// status text reinforces the "working" feeling.
function LoadingOverlay({
  visible,
  mode,
  portsProgress,
}: {
  visible: boolean;
  mode: CheckMode;
  portsProgress: { scanned: number; total: number; open: number } | null;
}) {
  const [shown, setShown] = useState(visible);
  const [progress, setProgress] = useState(0);
  const [statusIdx, setStatusIdx] = useState(0);

  // Mount/unmount with a brief delay so the exit animation can play.
  useEffect(() => {
    if (visible) {
      // TODO(react19-effects): rewrite these three effects to derive
      // state instead of setState-in-effect. Flagged by react-hooks v7's
      // new set-state-in-effect rule (introduced when #101 bumped the
      // plugin from v5 → v7). Suppressed inline to land the CI safety
      // net in #104 without expanding scope.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setShown(true);
      return;
    }
    // After fade-out, unmount.
    const t = window.setTimeout(() => setShown(false), 280);
    return () => window.clearTimeout(t);
  }, [visible]);

  // Reset progress + status whenever the overlay becomes visible.
  useEffect(() => {
    if (!visible) return;
    // TODO(react19-effects): see App.tsx setShown comment above.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setProgress(0);
    setStatusIdx(0);
  }, [visible]);

  // Drive progress.
  useEffect(() => {
    if (!visible) {
      // When the check finishes, snap to 100% so the ring fills before
      // the overlay fades out.
      // TODO(react19-effects): see App.tsx setShown comment above.
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setProgress(100);
      return;
    }
    // Real progress wins when available (ports SSE).
    if (portsProgress && portsProgress.total > 0) {
      setProgress(Math.min(99, (portsProgress.scanned / portsProgress.total) * 100));
      return;
    }
    // Synthetic ramp toward 90%, slowing as it gets there. 80ms tick
    // with variable increment matches the Stitch demo's feel.
    const interval = window.setInterval(() => {
      setProgress((current) => {
        if (current >= 90) return current;
        const step = (90 - current) * 0.02 + Math.random() * 0.4;
        return Math.min(90, current + step);
      });
    }, 80);
    return () => window.clearInterval(interval);
  }, [visible, portsProgress]);

  // Cycle status messages every 1.6s.
  useEffect(() => {
    if (!visible) return;
    const interval = window.setInterval(() => {
      setStatusIdx((idx) => idx + 1);
    }, 1600);
    return () => window.clearInterval(interval);
  }, [visible]);

  if (!shown) return null;

  const messages = LOADING_MESSAGES[mode as CheckMode] ?? LOADING_MESSAGES.default;
  const status = visible ? messages[statusIdx % messages.length] : "Done";

  // Progress ring math: r=54, circumference = 2πr ≈ 339.292.
  const RADIUS = 54;
  const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
  const offset = CIRCUMFERENCE - (progress / 100) * CIRCUMFERENCE;

  return (
    <div
      className={`loading-overlay ${visible ? "loading-overlay-visible" : "loading-overlay-leaving"}`}
      role="status"
      aria-live="polite"
    >
      <div className="loading-card">
        <div className="loading-card-glow" aria-hidden="true" />

        <div className="progress-ring">
          <svg viewBox="0 0 120 120" width="176" height="176">
            <circle
              cx="60"
              cy="60"
              r={RADIUS}
              fill="transparent"
              stroke="rgba(255,255,255,0.05)"
              strokeWidth="4"
            />
            <circle
              className="progress-ring-arc"
              cx="60"
              cy="60"
              r={RADIUS}
              fill="transparent"
              stroke="var(--accent)"
              strokeWidth="4"
              strokeLinecap="round"
              strokeDasharray={CIRCUMFERENCE}
              strokeDashoffset={offset}
            />
          </svg>
          <span className="progress-ring-value">{Math.floor(progress)}%</span>
        </div>

        <div className="loading-status">
          <span className="loading-status-text">{status}</span>
          <span className="loading-dots" aria-hidden="true">
            <span />
            <span />
            <span />
          </span>
        </div>
      </div>
    </div>
  );
}

// Per-mode status message lists. `default` is required (it's the
// fallback when a mode doesn't have a dedicated list); the per-mode
// keys are optional. Keeping the data table-style makes future per-mode
// flavor text a one-line edit away.
const LOADING_MESSAGES: { default: string[] } & Partial<Record<CheckMode, string[]>> = {
  default: [
    "Initializing protocol…",
    "Fetching network topology…",
    "Probing target…",
    "Establishing secure tunnel…",
    "Calibrating analytics…",
    "Streaming results…",
  ],
  ports: [
    "Scanning open ports…",
    "Probing TCP handshakes…",
    "Reading service banners…",
    "Classifying responses…",
  ],
  route: ["Tracing network path…", "Resolving hop ASNs…", "Probing intermediate routers…"],
  dns: ["Querying resolvers in parallel…", "Comparing answers…", "Detecting CDN edge variance…"],
};

function SideNavV2({
  route,
  onRouteChange,
}: {
  route: Route;
  onRouteChange: (next: Route) => void;
}) {
  // R-11: brand moves INTO the sidebar at the top (matching the Modern v1
  // mockup), and the active item uses the BrandMark icon to reinforce the
  // workbench-as-default-route metaphor. Documentation/Support footer
  // links are gone — they weren't in the mockup and the bottom of the
  // sidebar is intentionally empty / gradient-faded.
  return (
    <aside className="sidenav sidenav-v2" aria-label="Primary">
      <div className="sidenav-brand">
        <BrandMark size={28} />
        <span>netcheck</span>
      </div>
      <nav className="sidenav-nav" aria-label="Top-level routes">
        <NavItem
          icon={route === "workbench" ? <BrandMark size={18} /> : <Terminal />}
          label="Network Workbench"
          active={route === "workbench"}
          onClick={() => onRouteChange("workbench")}
        />
        <NavItem
          icon={<History />}
          label="Recent Checks"
          active={route === "history"}
          onClick={() => onRouteChange("history")}
        />
        <NavItem
          icon={<FileText />}
          label="Saved Reports"
          active={route === "reports"}
          onClick={() => onRouteChange("reports")}
        />
        <NavItem
          icon={<Settings2 />}
          label="Settings"
          active={route === "settings"}
          onClick={() => onRouteChange("settings")}
        />
      </nav>
    </aside>
  );
}

function NavItem({
  icon,
  label,
  active,
  onClick,
}: {
  icon: ReactNode;
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      aria-current={active ? "page" : undefined}
      className={`nav-item ${active ? "nav-item-active" : ""}`}
      onClick={onClick}
      type="button"
    >
      {icon}
      <span>{label}</span>
    </button>
  );
}

// BottomNav is the mobile counterpart to SideNavV2 — fixed to the
// viewport bottom with safe-area padding. Hidden by CSS on ≥720px.
function BottomNav({
  route,
  onRouteChange,
}: {
  route: Route;
  onRouteChange: (next: Route) => void;
}) {
  return (
    <nav className="bottom-nav" aria-label="Primary (mobile)">
      <BottomNavItem
        icon={<Terminal />}
        label="Workbench"
        active={route === "workbench"}
        onClick={() => onRouteChange("workbench")}
      />
      <BottomNavItem
        icon={<History />}
        label="History"
        active={route === "history"}
        onClick={() => onRouteChange("history")}
      />
      <BottomNavItem
        icon={<FileText />}
        label="Reports"
        active={route === "reports"}
        onClick={() => onRouteChange("reports")}
      />
      <BottomNavItem
        icon={<Settings2 />}
        label="Settings"
        active={route === "settings"}
        onClick={() => onRouteChange("settings")}
      />
    </nav>
  );
}

function BottomNavItem({
  icon,
  label,
  active,
  onClick,
}: {
  icon: ReactNode;
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      aria-current={active ? "page" : undefined}
      className={`bottom-nav-item ${active ? "bottom-nav-item-active" : ""}`}
      onClick={onClick}
      type="button"
    >
      {icon}
      <span>{label}</span>
    </button>
  );
}

// StatusFooter is the desktop-only footer strip. Left: which config the
// CLI would load. Right: app version + most-recent scan timestamp from
// the recents list. No fake "system operational" — just real, useful info.
function StatusFooter({ lastScanAt }: { lastScanAt: string | undefined }) {
  // The web app can't actually read ~/.config/netcheck/config.yaml from
  // the browser. We surface a stable summary based on what the server
  // told the UI about the config it loaded; for R-1 that's a static
  // hint, R-8 will wire the /api/config endpoint to fill it in.
  return (
    <footer className="status-footer" aria-label="Status">
      <span className="status-footer-left">
        <span className="muted">Config:</span> <code>~/.config/netcheck/config.yaml</code>
      </span>
      <span className="status-footer-right">
        {lastScanAt ? (
          <>
            <span className="muted">Last scan:</span> <time>{formatRecentTime(lastScanAt)}</time>
            <span className="muted"> · </span>
          </>
        ) : null}
        <span>v2.0.1</span>
      </span>
    </footer>
  );
}

// Landing is the workbench-route default view. Big target input + a 2x2
// grid of category cards. Picking a card → setCategory → enters the
// category-detail view (R-1 reuses the existing form + mode tabs; R-2
// replaces them with ModeCards).
//
// R-10: added the central "Run Check" CTA below the grid (matches the
// Modern v1 mockup). Clicking it runs a Full Check on the target without
// requiring a category pick — the default-action shortcut for users who
// just typed a URL and want the headline check.
function Landing({
  target,
  onTargetChange,
  onPickCategory,
  onRunDefault,
  runDisabled,
}: {
  target: string;
  onTargetChange: (next: string) => void;
  onPickCategory: (cat: Category) => void;
  onRunDefault: () => void;
  runDisabled: boolean;
}) {
  return (
    <section className="landing" aria-label="Workbench landing">
      <label className="landing-input">
        <Search />
        <span className="sr-only">Target</span>
        <input
          autoCapitalize="none"
          autoCorrect="off"
          onChange={(event) => onTargetChange(event.target.value)}
          onKeyDown={(event) => {
            // Enter on the landing input fires the default Run Check action,
            // matching the v1 form-submit keyboard behavior.
            if (event.key === "Enter" && !runDisabled) {
              event.preventDefault();
              onRunDefault();
            }
          }}
          placeholder="Enter target URL (e.g. https://example.com) or IP address…"
          spellCheck="false"
          value={target}
        />
      </label>

      <div className="category-grid">
        {CATEGORIES.map((cat) => (
          <CategoryCard key={cat.key} def={cat} onClick={() => onPickCategory(cat.key)} />
        ))}
      </div>

      <button className="run-check-cta" disabled={runDisabled} onClick={onRunDefault} type="button">
        <Play />
        <span>Run Check</span>
      </button>
    </section>
  );
}

// CategoryCard is one of the four cards on the landing — icon, name,
// blurb, Select CTA. Whole card is clickable; the Select pill is
// visual + accessible label.
function CategoryCard({ def, onClick }: { def: CategoryDef; onClick: () => void }) {
  const icon =
    def.key === "network" ? (
      <Globe />
    ) : def.key === "recon" ? (
      <Telescope />
    ) : def.key === "scanning" ? (
      <ShieldAlert />
    ) : (
      <Layers />
    );
  return (
    <button className={`category-card category-card-${def.key}`} onClick={onClick} type="button">
      <div className="category-card-icon">{icon}</div>
      <div className="category-card-body">
        <strong>{def.label}</strong>
        <p>{def.blurb}</p>
      </div>
      <span className="category-card-cta">Select</span>
    </button>
  );
}

// CategoryDetail is the screen shown after the user picks a category
// card. Layout: back link → target input bar → optional auth banner
// (for Scanning) → list of ModeCards → result area.
//
// R-2 collapses the previous per-mode "form + tabs + auth + audit-
// options" flow into one card per mode. Clicking a card's Run pill
// sets the mode and kicks off the check in a single action.
function CategoryDetail({
  categoryDef,
  target,
  onTargetChange,
  onBack,
  onRun,
  runState,
  runningMode,
  activeAcknowledged,
  onAcknowledge,
  error,
  report,
  portsProgress,
  portsProto,
  onPortsProtoChange,
}: {
  categoryDef: CategoryDef;
  target: string;
  onTargetChange: (next: string) => void;
  onBack: () => void;
  onRun: (mode: CheckMode, opts?: { auditActive?: boolean }) => void;
  runState: RunState;
  runningMode: CheckMode;
  activeAcknowledged: boolean;
  onAcknowledge: (next: boolean) => void;
  error: string;
  report: AnyReport | null;
  portsProgress: { scanned: number; total: number; open: number } | null;
  // R-13: port-scan protocol selector lives on the App and is threaded
  // through here so the Ports modecard can surface a TCP/UDP/Both
  // segmented control next to its Run button.
  portsProto: "tcp" | "udp" | "both";
  onPortsProtoChange: (next: "tcp" | "udp" | "both") => void;
}) {
  const isScanning = categoryDef.key === "scanning";
  const isAggregate = categoryDef.key === "aggregate";
  // Predicate used by the onKeyDown Enter handler — only Audit lives in
  // Aggregate today, so this is just `m === "audit"` for now, but keep
  // the categoryDef.key check explicit for when R-7 adds diff/watch.
  const isAuditAggregateMode = (m: CheckMode) => isAggregate && m === "audit";
  // Within the Aggregate category, the audit mode card surfaces both
  // Passive and Active run buttons. Active reuses the same auth scope
  // as the Scanning category (one checkbox unlocks all active probes).
  const showAuthBanner = isScanning || isAggregate;
  const runDisabled = runState === "loading";

  return (
    <section className="category-detail" aria-label={categoryDef.label}>
      <button className="back-link" onClick={onBack} type="button">
        <ChevronLeft />
        <span>Categories</span>
      </button>

      <div className="category-detail-header">
        <h1>{categoryDef.label}</h1>
        <p>{categoryDef.blurb}</p>
      </div>

      <label className="landing-input category-detail-input">
        <Globe />
        <span className="sr-only">Target</span>
        <input
          autoCapitalize="none"
          autoCorrect="off"
          onChange={(event) => onTargetChange(event.target.value)}
          onKeyDown={(event) => {
            // Codex P2 on #64: Enter used to submit the v1 form.
            // R-2 replaced the form with ModeCards, so Enter became a
            // no-op. Restore the keyboard-flow expectation by running
            // the first mode in the category that isn't auth-blocked.
            // Aggregate's audit defaults to Passive; Scanning needs the
            // category-level checkbox first or Enter is suppressed.
            if (event.key !== "Enter" || runDisabled) {
              return;
            }
            const firstMode = categoryDef.modes.find((m) => {
              if (isAuditAggregateMode(m)) return true; // Passive always OK
              return !isActiveMode(m) || activeAcknowledged;
            });
            if (firstMode) {
              event.preventDefault();
              const opts = isAuditAggregateMode(firstMode) ? { auditActive: false } : undefined;
              onRun(firstMode, opts);
            }
          }}
          placeholder="Enter target URL (e.g. https://example.com) or IP address…"
          spellCheck="false"
          value={target}
        />
      </label>

      {showAuthBanner ? (
        <section
          className={`auth-banner ${activeAcknowledged ? "auth-banner-ack" : "auth-banner-pending"}`}
          aria-label="Active scan authorization"
        >
          <div className="auth-banner-icon">
            <AlertTriangle />
          </div>
          <div className="auth-banner-body">
            <strong>
              {isScanning
                ? "These probes actively touch the target."
                : "Audit can include active probes."}
            </strong>
            <p>
              Running active probes against a system you do not own — or do not have written
              permission to test — is illegal in most jurisdictions. Read{" "}
              <a
                href="https://github.com/Dezoxy/netcheck/blob/main/docs/ETHICS.md"
                rel="noreferrer"
                target="_blank"
              >
                docs/ETHICS.md
              </a>
              .
            </p>
            <label className="auth-banner-check">
              <input
                checked={activeAcknowledged}
                onChange={(event) => onAcknowledge(event.target.checked)}
                type="checkbox"
              />
              <span>I am authorized to actively probe this target.</span>
            </label>
          </div>
        </section>
      ) : null}

      <div className="modecard-list">
        {categoryDef.modes.map((m) => (
          <ModeCard
            key={m}
            mode={m}
            isActive={isActiveMode(m)}
            isAuditAggregate={isAggregate && m === "audit"}
            runDisabled={runDisabled}
            running={runState === "loading" && runningMode === m}
            authReady={activeAcknowledged}
            onRun={(opts) => onRun(m, opts)}
            extra={
              m === "ports" ? (
                <PortsProtoToggle value={portsProto} onChange={onPortsProtoChange} />
              ) : undefined
            }
          />
        ))}
      </div>

      {runState === "error" ? <ErrorBanner message={error} /> : null}
      {runState === "loading" && portsProgress ? (
        <PortsProgressBanner progress={portsProgress} />
      ) : null}
      {report ? <ReportView loading={runState === "loading"} report={report} /> : null}
    </section>
  );
}

// ModeCard is one row inside a category-detail screen. Title +
// description + Run pill. For audit (Aggregate category) the card
// shows two pills: Passive and Active. Active-tier modes (tls /
// takeover / ports / enum) are gated on the category-level auth
// banner; Run is disabled until the user ticks the checkbox.
function ModeCard({
  mode,
  isActive,
  isAuditAggregate,
  runDisabled,
  running,
  authReady,
  onRun,
  extra,
}: {
  mode: CheckMode;
  isActive: boolean;
  isAuditAggregate: boolean;
  runDisabled: boolean;
  running: boolean;
  authReady: boolean;
  onRun: (opts?: { auditActive?: boolean }) => void;
  // R-13: optional per-mode controls injected by the parent. Currently
  // used by the Ports modecard to surface the TCP/UDP/Both selector
  // without bloating ModeCard with mode-specific props.
  extra?: ReactNode;
}) {
  // Lock the Run pill when the mode is active-tier and the user
  // hasn't acknowledged the auth banner yet. For audit, the Passive
  // button is always available; the Active button is gated.
  const activeBlocked = isActive && !authReady;
  return (
    <article className={`modecard ${isActive ? "modecard-active-tier" : ""}`}>
      <div className="modecard-body">
        <div className="modecard-head">
          <strong>{MODE_LABEL[mode]}</strong>
          {isActive ? <span className="modecard-tier">Active</span> : null}
        </div>
        <p>{MODE_BLURB[mode]}</p>
        {extra}
      </div>
      <div className="modecard-actions">
        {isAuditAggregate ? (
          <>
            <button
              className="modecard-run modecard-run-secondary"
              disabled={runDisabled}
              onClick={() => onRun({ auditActive: false })}
              type="button"
            >
              <Play />
              <span>{running ? "Running…" : "Passive"}</span>
            </button>
            <button
              className="modecard-run"
              disabled={runDisabled || !authReady}
              onClick={() => onRun({ auditActive: true })}
              title={authReady ? undefined : "Confirm authorization above to enable active runs"}
              type="button"
            >
              <Play />
              <span>{running ? "Running…" : "Active"}</span>
            </button>
          </>
        ) : (
          <button
            className="modecard-run"
            disabled={runDisabled || activeBlocked}
            onClick={() => onRun()}
            title={activeBlocked ? "Confirm authorization above to enable active runs" : undefined}
            type="button"
          >
            <Play />
            <span>{running ? "Running…" : "Run"}</span>
          </button>
        )}
      </div>
    </article>
  );
}

// RouteHistoryList renders the existing recents in the main workbench
// area instead of the side drawer. R-8 will redesign the row treatment;
// R-1 keeps the same recent-item markup.
function RouteHistoryList({
  recents,
  onRerun,
}: {
  recents: RecentCheck[];
  onRerun: (recent: RecentCheck) => void;
}) {
  return (
    <section className="route-page" aria-label="History">
      <header className="route-page-head">
        <h1>History</h1>
        <p>Recent checks from this browser. Click one to rerun.</p>
      </header>
      <div className="recent-list recent-list-page">
        {recents.length === 0 ? <p className="empty-list">No recent checks yet.</p> : null}
        {recents.map((recent) => (
          <button
            className="recent-item"
            key={`${recent.target}-${recent.ranAt}`}
            onClick={() => onRerun(recent)}
            type="button"
          >
            <span className={`recent-dot ${recent.ok ? "recent-dot-ok" : "recent-dot-fail"}`} />
            <span>
              <strong>{recent.target}</strong>
              <time>
                {MODE_LABEL[recent.mode] || "Full"} · {formatRecentTime(recent.ranAt)}
              </time>
            </span>
          </button>
        ))}
      </div>
    </section>
  );
}

// RouteReportsList renders the saved reports as a full page.
function RouteReportsList({
  saved,
  savedError,
  onRefresh,
  onOpen,
  onRemove,
}: {
  saved: SavedReportMeta[];
  savedError: string;
  onRefresh: () => void;
  onOpen: (meta: SavedReportMeta) => void;
  onRemove: (meta: SavedReportMeta) => void;
}) {
  useEffect(() => {
    onRefresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // R-7: track which reports the user has picked for compare. Up to two
  // — the first becomes "old", the second "new". Both must share the
  // same kind; cross-kind diffs are surfaced as kind:"mixed" by the
  // server which is rarely useful, so we enforce same-kind in the UI.
  const [compareIds, setCompareIds] = useState<string[]>([]);
  const [diffLoading, setDiffLoading] = useState(false);
  const [diffError, setDiffError] = useState("");
  const [diffResult, setDiffResult] = useState<DiffReport | null>(null);
  const [diffMeta, setDiffMeta] = useState<{
    oldMeta?: SavedReportMeta;
    newMeta?: SavedReportMeta;
  }>({});

  function toggleCompare(meta: SavedReportMeta) {
    setDiffResult(null);
    setDiffError("");
    setCompareIds((prev) => {
      if (prev.includes(meta.id)) {
        return prev.filter((id) => id !== meta.id);
      }
      // Enforce same-kind constraint. If the already-selected item is a
      // different kind, replace it; otherwise append (cap at 2).
      const head = prev[0];
      if (head) {
        const headMeta = saved.find((s) => s.id === head);
        if (headMeta && headMeta.kind !== meta.kind) {
          return [meta.id];
        }
      }
      return [...prev, meta.id].slice(-2);
    });
  }

  async function runCompare() {
    if (compareIds.length !== 2) return;
    // Sort the two picks by saved_at so the older one is "old". Users
    // can pick in either order; the diff is always old→new chronological.
    const a = saved.find((s) => s.id === compareIds[0]);
    const b = saved.find((s) => s.id === compareIds[1]);
    if (!a || !b) return;
    const [oldMeta, newMeta] = a.saved_at <= b.saved_at ? [a, b] : [b, a];

    setDiffLoading(true);
    setDiffError("");
    setDiffResult(null);
    try {
      const [oldFull, newFull] = await Promise.all([
        loadSavedReport(oldMeta.id),
        loadSavedReport(newMeta.id),
      ]);
      const diff = await diffReports(oldFull.report, newFull.report);
      setDiffResult(diff);
      setDiffMeta({ oldMeta, newMeta });
    } catch (cause) {
      setDiffError(cause instanceof Error ? cause.message : "diff failed");
    } finally {
      setDiffLoading(false);
    }
  }

  function clearCompare() {
    setCompareIds([]);
    setDiffResult(null);
    setDiffError("");
    setDiffMeta({});
  }

  const compareReady = compareIds.length === 2;

  return (
    <section className="route-page" aria-label="Reports">
      <header className="route-page-head">
        <h1>Reports</h1>
        <p>
          Reports saved server-side via the Save button. Click a row to open it in the workbench, or
          pick two of the same kind to compare.
        </p>
      </header>

      {compareIds.length > 0 ? (
        <div className="compare-bar">
          <span>
            <strong>{compareIds.length}</strong> selected
            {compareIds.length === 1 ? " — pick one more of the same kind" : ""}
          </span>
          <div className="compare-bar-actions">
            <button
              className="modecard-run-secondary modecard-run"
              disabled={diffLoading}
              onClick={clearCompare}
              type="button"
            >
              <span>Clear</span>
            </button>
            <button
              className="modecard-run"
              disabled={!compareReady || diffLoading}
              onClick={runCompare}
              type="button"
            >
              <GitCompare />
              <span>{diffLoading ? "Diffing…" : "Compare"}</span>
            </button>
          </div>
        </div>
      ) : null}

      {diffError ? <ErrorBanner message={diffError} /> : null}
      {diffResult ? (
        <DiffViewer report={diffResult} oldMeta={diffMeta.oldMeta} newMeta={diffMeta.newMeta} />
      ) : null}

      <div className="recent-list recent-list-page">
        {savedError ? <p className="detail-error">{savedError}</p> : null}
        {saved.length === 0 && !savedError ? (
          <p className="empty-list">No saved reports yet.</p>
        ) : null}
        {saved.map((item) => {
          const picked = compareIds.includes(item.id);
          return (
            <div
              className={`recent-item recent-item-saved ${picked ? "recent-item-picked" : ""}`}
              key={item.id}
            >
              <button className="recent-item-main" onClick={() => onOpen(item)} type="button">
                <span
                  className={`recent-dot ${item.ok === false ? "recent-dot-fail" : "recent-dot-ok"}`}
                />
                <span>
                  <strong>{item.target}</strong>
                  <time>
                    {MODE_LABEL[kindToMode(item.kind)] || item.kind} ·{" "}
                    {formatRecentTime(item.saved_at)}
                  </time>
                </span>
              </button>
              <IconButton
                label={picked ? "Remove from compare" : "Add to compare"}
                onClick={() => toggleCompare(item)}
              >
                <GitCompare />
              </IconButton>
              <IconButton label="Delete saved report" onClick={() => onRemove(item)}>
                <Trash2 />
              </IconButton>
            </div>
          );
        })}
      </div>
    </section>
  );
}

// DiffViewer renders the server's pkg/diff.Report as a stack of
// section cards. Each section's title sits at the top, then a list
// of changes each with a severity-coded chip and message.
//
// "info"  → blue chip (neutral observation, e.g. new subdomain)
// "ok"    → green chip (improvement, e.g. port closed, header→pass)
// "warn"  → orange chip (worth attention, e.g. cert closer to expiry)
// "err"   → red chip (regression, e.g. new open port, missing header)
function DiffViewer({
  report,
  oldMeta,
  newMeta,
}: {
  report: DiffReport;
  oldMeta?: SavedReportMeta;
  newMeta?: SavedReportMeta;
}) {
  const sections = report.sections ?? [];
  return (
    <section className="diff-viewer" aria-label="Diff result">
      <header className="diff-viewer-head">
        <h2>
          Diff: <span>{report.target || report.kind}</span>
        </h2>
        <div className="diff-viewer-meta">
          {oldMeta && newMeta ? (
            <span>
              <code>{formatRecentTime(oldMeta.saved_at)}</code> →{" "}
              <code>{formatRecentTime(newMeta.saved_at)}</code>
            </span>
          ) : null}
          <span className={`health-pill ${report.changed ? "health-pill-fail" : "health-pill-ok"}`}>
            <span />
            {report.changed ? "Changed" : "No changes"}
          </span>
        </div>
      </header>

      {sections.length === 0 ? (
        <p className="muted">No meaningful changes between these two reports.</p>
      ) : (
        <div className="diff-section-list">
          {sections.map((section) => (
            <article className="diff-section" key={section.title}>
              <header>
                <strong>{section.title}</strong>
                <span className="muted">
                  {section.changes?.length ?? 0} change
                  {(section.changes?.length ?? 0) === 1 ? "" : "s"}
                </span>
              </header>
              <ul className="diff-change-list">
                {(section.changes ?? []).map((change, i) => (
                  <li key={i} className="diff-change">
                    <span className={`diff-chip diff-chip-${change.severity}`}>
                      {change.severity}
                    </span>
                    <span className="diff-change-msg">{change.message}</span>
                  </li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

// RouteSettings is the new Settings route. R-1 surfaces just the
// insecure-TLS toggle that used to live in the floating settings
// panel; R-8 will fold in more global preferences.
function RouteSettings({
  insecure,
  onInsecureChange,
}: {
  insecure: boolean;
  onInsecureChange: (next: boolean) => void;
}) {
  return (
    <section className="route-page" aria-label="Settings">
      <header className="route-page-head">
        <h1>Settings</h1>
        <p>
          Browser-scoped preferences. CLI config lives in{" "}
          <code>~/.config/netcheck/config.yaml</code>.
        </p>
      </header>
      <div className="settings-list">
        <label className="settings-row">
          <input
            aria-label="Allow insecure TLS"
            checked={insecure}
            onChange={(event) => onInsecureChange(event.target.checked)}
            type="checkbox"
          />
          <div>
            <strong>Allow insecure TLS</strong>
            <p>
              Skip certificate verification on Full Check. Same as <code>--insecure</code> on the
              CLI.
            </p>
          </div>
        </label>
      </div>
    </section>
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
        <SummaryCard
          error={report.dns.error}
          label="DNS Resolution"
          ms={report.dns.took_ms}
          value="Success"
        />
        <SummaryCard
          error={tcp?.error}
          label="TCP Connection"
          ms={tcp?.took_ms}
          value={tcp ? "Success" : "Unavailable"}
        />
        <SummaryCard
          error={report.tls?.error}
          label="TLS Handshake"
          ms={report.tls?.took_ms}
          value={report.tls ? "Success" : "Skipped"}
        />
        <SummaryCard
          error={report.http.error}
          label="HTTP Response"
          ms={report.http.timing.total_ms}
          value={
            report.http.status
              ? `${report.http.status} ${report.http.status < 400 ? "OK" : ""}`.trim()
              : "Failed"
          }
        />
      </div>

      <Panel className="timing-panel" title="Timing Waterfall">
        <div className="waterfall" aria-label="HTTP timing waterfall">
          {timing.map((segment) => (
            <span
              key={segment.label}
              style={{ background: segment.color, width: `${segment.width}%` }}
            />
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
              <Detail
                label="Expiry"
                value={`${formatDate(report.tls.not_after)} (${report.tls.days_remaining}d)`}
              />
              {report.tls.error ? <Detail error label="Error" value={report.tls.error} /> : null}
            </dl>
          ) : (
            <p className="muted">TLS does not run for this target.</p>
          )}
        </Panel>

        <Panel className="http-panel" title="HTTP Response">
          <div className="http-grid">
            <Metric
              label="Status"
              ok={report.http.status > 0 && report.http.status < 400}
              value={httpStatusLabel(report.http.status)}
            />
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
            {q.verdict.agree
              ? "All successful resolvers returned the same answer set."
              : `${q.verdict.groups.length} distinct answer sets:`}
          </p>
          {!q.verdict.agree
            ? q.verdict.groups.map((group, i) => (
                <p className="muted" key={`group-${i}`}>
                  <strong>Set {i + 1}</strong> ({group.resolvers.join(", ")}):{" "}
                  <code>{group.records.join(", ") || "(empty)"}</code>
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
          {report.reached
            ? `Reached in ${report.hops.length} hops`
            : `Stopped after ${report.hops.length} hops`}
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
              {hop.timeout ? <span className="muted">* * *</span> : <code>{hopAddress(hop)}</code>}
              {hop.timeout ? <span className="muted">*</span> : <code>{hopRTT(hop)}</code>}
              {hop.asn ? (
                <span>
                  AS{hop.asn.asn} {hop.asn.org ?? ""}
                </span>
              ) : (
                <span className="muted">—</span>
              )}
            </div>
          ))}
        </div>
        {report.timeouts > 0 ? (
          <p className="muted">
            {report.timeouts} hop(s) timed out — routers commonly drop or rate-limit probes; missing
            hops don't always mean a broken route.
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
            {d.asn?.country || d.rdap?.country ? (
              <Detail label="Country" value={d.asn?.country ?? d.rdap?.country ?? "—"} />
            ) : null}
            {d.asn?.prefix ? <Detail label="Prefix" value={d.asn.prefix} /> : null}
            {d.rdap?.registry || d.asn?.registry ? (
              <Detail label="Registry" value={d.rdap?.registry ?? d.asn?.registry ?? "—"} />
            ) : null}
            {d.cdn?.provider ? (
              <Detail
                label="CDN"
                value={
                  d.cdn.confidence && d.cdn.reason
                    ? `${d.cdn.provider} (${d.cdn.confidence} — ${d.cdn.reason})`
                    : d.cdn.provider
                }
              />
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
        <h1>
          Headers: <span>{report.url}</span>
        </h1>
        <div
          className={`health-pill ${report.summary.missing === 0 && report.summary.weak === 0 ? "health-pill-ok" : "health-pill-fail"}`}
        >
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
        <h1>
          Tech: <span>{report.url}</span>
        </h1>
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
                <span>
                  <strong>{m.name}</strong>
                </span>
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
        <h1>
          Subdomains: <span>{report.domain}</span>
        </h1>
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

function ReverseWorkbench({ loading, report }: { loading: boolean; report: ReverseReport }) {
  const hostnames = report.hostnames ?? [];
  return (
    <section className={loading ? "result-area result-area-loading" : "result-area"}>
      <div className="result-header">
        <h1>
          Reverse IP: <span>{report.ip}</span>
        </h1>
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
        <h1>
          Wayback: <span>{report.domain}</span>
        </h1>
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
        <Panel
          className="dns-panel"
          icon={<FileText />}
          title={`Recent snapshots (${report.recent_samples.length})`}
        >
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
        <h1>
          TLS Audit:{" "}
          <span>
            {report.host}:{report.port}
          </span>
        </h1>
        <div className={`health-pill ${highCount === 0 ? "health-pill-ok" : "health-pill-fail"}`}>
          <span />
          {highCount === 0
            ? "No high-severity findings"
            : `${highCount} high-severity finding${highCount === 1 ? "" : "s"}`}
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
              <span>
                <strong>{p.name}</strong>
              </span>
              <span className={p.supported ? "value-ok" : "muted"}>
                {p.supported ? "yes" : "no"}
              </span>
              <span className={p.deprecated ? "value-fail" : "muted"}>
                {p.deprecated ? "deprecated" : "—"}
              </span>
              <code>{p.cipher ?? "—"}</code>
            </div>
          ))}
        </div>
      </Panel>

      {report.ciphers && report.ciphers.length > 0 ? (
        <Panel
          className="dns-panel"
          icon={<LockKeyhole />}
          title={`Supported cipher suites (${report.ciphers.length})`}
        >
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
                <span className={c.insecure ? "value-fail" : "muted"}>
                  {c.insecure ? "WEAK" : ""}
                </span>
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
            <Detail
              label="Validity"
              value={`${formatDate(report.cert.not_before)} → ${formatDate(report.cert.not_after)} (${report.cert.days_remaining}d)`}
            />
            <Detail label="Chain length" value={String(report.cert.chain_count)} />
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
                <strong className={severityClass(f.severity)}>[{f.severity.toUpperCase()}]</strong>{" "}
                {f.title}
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
        <h1>
          Takeover: <span>{report.domain}</span>
        </h1>
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
        <Panel
          className="dns-panel"
          icon={<AlertTriangle />}
          key={i}
          title={f.provider || "Unknown provider"}
        >
          <dl className="certificate-grid">
            <Detail label="CNAME" value={f.cname} />
            {f.provider ? <Detail label="Provider" value={f.provider} /> : null}
            <Detail
              error={f.verdict === "vulnerable"}
              label="Verdict"
              value={
                f.verdict === "vulnerable" ? "VULNERABLE — this CNAME can be taken over" : f.verdict
              }
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

// PortsProtoToggle is the TCP / UDP / Both segmented control rendered
// inside the Ports modecard. Default is TCP everywhere — matches the
// CLI default and keeps pre-R-13 behaviour byte-identical when the user
// just hits Run. The UDP option falls back to the engine's curated top-
// 50 UDP list; the user can still narrow via the (not-yet-surfaced)
// `udp_ports` field for one-off probes via the CLI.
function PortsProtoToggle({
  value,
  onChange,
}: {
  value: "tcp" | "udp" | "both";
  onChange: (next: "tcp" | "udp" | "both") => void;
}) {
  const opts: Array<{ key: "tcp" | "udp" | "both"; label: string }> = [
    { key: "tcp", label: "TCP" },
    { key: "udp", label: "UDP" },
    { key: "both", label: "Both" },
  ];
  return (
    <div className="ports-proto-toggle" role="radiogroup" aria-label="Port scan protocol">
      {opts.map((o) => (
        <button
          aria-checked={value === o.key}
          className={`ports-proto-option ${value === o.key ? "ports-proto-option-active" : ""}`}
          key={o.key}
          onClick={(event) => {
            // The toggle lives inside a modecard whose default action is
            // Run — prevent the click from bubbling up and accidentally
            // launching a scan when the user just wanted to switch
            // protocols.
            event.stopPropagation();
            onChange(o.key);
          }}
          role="radio"
          type="button"
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

// PortsTable renders the open-port list. Column set is adaptive:
//   - PROTO + STATE columns appear only when the result includes UDP
//     entries (otherwise everything is TCP/"open" and the columns are
//     pure noise)
//   - BANNER column appears only when at least one port has one
// Keeps the table compact for the common TCP-only-no-banner case while
// staying expressive for mixed-protocol scans where state really matters.
function PortsTable({ ports }: { ports: NonNullable<PortScanReport["ports"]> }) {
  const showBanner = ports.some((p) => p.banner && p.banner.length > 0);
  const showProto = ports.some((p) => p.proto === "udp");
  // Use a unique key so duplicate ports across protocols (53/tcp + 53/udp)
  // don't collide.
  const rowKey = (p: NonNullable<PortScanReport["ports"]>[number]) =>
    `${p.proto || "tcp"}-${p.port}`;
  if (showProto) {
    // Use a ports-specific 4-col class — the existing `dns-row-4` is
    // tuned for the Route panel (hop/address/rtt/asn) and would distort
    // these columns.
    const cols = showBanner ? "dns-row-5" : "dns-row-4-ports";
    return (
      <div className="dns-table">
        <div className={`dns-header ${cols}`}>
          <span>Proto</span>
          <span>Port</span>
          <span>State</span>
          <span>Service</span>
          {showBanner ? <span>Banner</span> : null}
        </div>
        {ports.map((p) => (
          <div className={`dns-row ${cols}`} key={rowKey(p)}>
            <code>{p.proto || "tcp"}</code>
            <code>{p.port}</code>
            <span>{p.state || "open"}</span>
            <span>{p.service || "—"}</span>
            {showBanner ? (
              <code className="banner-cell" title={p.banner || ""}>
                {p.banner || "—"}
              </code>
            ) : null}
          </div>
        ))}
      </div>
    );
  }
  if (!showBanner) {
    return (
      <div className="dns-table">
        <div className="dns-header">
          <span>Port</span>
          <span>Service</span>
        </div>
        {ports.map((p) => (
          <div className="dns-row" key={rowKey(p)}>
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
        <div className="dns-row dns-row-3" key={rowKey(p)}>
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

// PortsProgressBanner shows the live counter during a streaming ports scan.
// Renders only between the "user clicked Run" and the "done" SSE frame.
function PortsProgressBanner({
  progress,
}: {
  progress: { scanned: number; total: number; open: number };
}) {
  const pct =
    progress.total > 0 ? Math.min(100, Math.round((progress.scanned / progress.total) * 100)) : 0;
  return (
    <section className="ports-progress" aria-live="polite">
      <div className="ports-progress-line">
        <span>
          Scanning <strong>{progress.scanned}</strong> / {progress.total || "?"}
        </span>
        <span className="ports-progress-open">
          <strong>{progress.open}</strong> open so far
        </span>
        <span className="muted">{pct}%</span>
      </div>
      <div className="ports-progress-bar" aria-hidden="true">
        <div className="ports-progress-bar-fill" style={{ width: `${pct}%` }} />
      </div>
    </section>
  );
}

function PortScanWorkbench({ loading, report }: { loading: boolean; report: PortScanReport }) {
  const ports = report.ports ?? [];
  return (
    <section className={loading ? "result-area result-area-loading" : "result-area"}>
      <div className="result-header">
        <h1>
          Ports: <span>{report.host}</span>
          {report.ip && report.ip !== report.host ? (
            <span className="muted"> ({report.ip})</span>
          ) : null}
        </h1>
        <div className="health-pill health-pill-ok">
          <span />
          {report.stats.open} open / {report.stats.total} scanned
        </div>
      </div>
      {report.error ? <ErrorBanner message={report.error} /> : null}
      <div className="summary-strip">
        <SummaryCard label="Open" value={String(report.stats.open)} />
        {report.stats.open_filtered ? (
          <SummaryCard label="Open|Filtered" value={String(report.stats.open_filtered)} />
        ) : null}
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
        <h1>
          Path Enum: <span>{report.base_url}</span>
        </h1>
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
      <p className="muted">
        Mode: {mode} · {report.took_ms}ms
      </p>
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
              <span>
                <strong>{row.label}</strong>
              </span>
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
    rows.push({
      label: "IP",
      grade: r.ip.details.length === 0 ? "err" : "ok",
      summary: ipSummary(r.ip),
    });
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

function SummaryCard({
  error,
  label,
  ms,
  value,
}: {
  error?: string;
  label: string;
  ms?: number;
  value: string;
}) {
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

function Panel({
  children,
  className = "",
  icon,
  title,
}: {
  children: ReactNode;
  className?: string;
  icon?: ReactNode;
  title: string;
}) {
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

function Detail({
  error = false,
  label,
  value,
}: {
  error?: boolean;
  label: string;
  value: string;
}) {
  return (
    <>
      <dt>{label}:</dt>
      <dd className={error ? "detail-error" : ""}>{value}</dd>
    </>
  );
}

function Metric({
  label,
  ok = false,
  value,
  wide = false,
}: {
  label: string;
  ok?: boolean;
  value: number | string;
  wide?: boolean;
}) {
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
      .filter(
        (item): item is RecentCheck & { mode?: CheckMode } =>
          !!item && typeof item.target === "string",
      )
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
  return [
    next,
    ...current.filter((item) => !(item.target === next.target && item.mode === next.mode)),
  ].slice(0, MAX_RECENTS);
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
    else if ((report.takeover.findings ?? []).some((f) => f.verdict === "vulnerable"))
      grades.push("high");
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
  const total = Math.max(
    timing.total_ms,
    segments.reduce((sum, segment) => sum + segment.value, 0),
    1,
  );
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
