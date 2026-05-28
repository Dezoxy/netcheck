import {
  AlertTriangle,
  FileText,
  GitCompare,
  Globe,
  History,
  LockKeyhole,
  Settings2,
  Terminal,
  Trash2,
} from "lucide-react";
import {
  Component,
  ErrorInfo,
  ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
// PR 6 dashboard restructure: CategoryBento → CategoryDropdown +
// SelectedModePanel, target input → TargetInput. The old CategoryDetail
// "page" dissolved; everything renders on the single Dashboard route.
import { CategoryDropdown } from "./components/CategoryDropdown";
import { CommandPalette } from "./components/CommandPalette";
import { DataRow } from "./components/DataRow";
import { LandingHero } from "./components/LandingHero";
import { LiveEventStream } from "./components/LiveEventStream";
// Panel from ./components/Panel replaces the legacy local Panel
// helper for all 14 workbench renderers (PR 7 restyle).
import { Panel } from "./components/Panel";
import { SelectedModePanel } from "./components/SelectedModePanel";
import { SideNav } from "./components/SideNav";
import { StatusPill } from "./components/StatusPill";
import { TargetInput } from "./components/TargetInput";
import { TargetTopography } from "./components/TargetTopography";
import { TelemetryStrip } from "./components/TelemetryStrip";
import { TopAppBar } from "./components/TopAppBar";
import { useCommandPalette } from "./hooks/useCommandPalette";
import {
  deleteSavedReport,
  diffReports,
  DNS_DEFAULT_TYPES,
  DNS_DNSSEC_TYPES,
  DNS_EXTENDED_TYPES,
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
// isActiveMode moved into CategoryDropdown + SelectedModePanel after
// PR 6 — App.tsx no longer needs the predicate at this layer.

const ACTIVE_ACK_KEY = "netcheck.active-ack.v1";

const HISTORY_KEY = "netcheck.recent-checks.v1";
const MAX_RECENTS = 8;

type RunState = "idle" | "loading" | "ready" | "error";

// Route type and the PLACEHOLDER_ROUTES set live in ./routes — the
// HUD redesign (PR 2) added analytics/nodes/support which several
// components share. See `web/src/routes.ts` for the union.
//
// Originally a local type in this file from the R-1 redesign;
// promoted to a shared module so SideNav + TopAppBar import it
// without a circular App ↔ component dependency.
import type { Route } from "./routes";
import { PLACEHOLDER_ROUTES } from "./routes";

// Category / CategoryDef / CATEGORIES were App-level types tracking
// the category → modes mapping. PR 6 (dashboard restructure) removed
// the category state entirely; CategoryDropdown
// (`web/src/components/CategoryDropdown.tsx`) ships its own annotated
// copy of the mapping. The "Category" label strings that remain
// elsewhere in this file are static text inside DNS panels — not
// type references.

// modeCategory was removed in PR 6 (dashboard restructure). The
// Dashboard renders SelectedModePanel based on `selectedMode`
// directly — no "category" indirection is needed any more for
// rerun-from-history or open-saved-report flows.

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

// MODE_BLURB moved into SelectedModePanel (PR 6) — it's the only
// consumer now that ModeCard is gone. Keeping a local copy here
// would just create drift risk.

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
  // Monotonic counter bumped at the start of every run. Used as the
  // ReportErrorBoundary key so a render crash on one report doesn't
  // permanently poison the panel — the next run mounts a fresh
  // boundary and gets a clean shot at rendering.
  const [runSeq, setRunSeq] = useState(0);
  const [error, setError] = useState("");
  const [insecure, setInsecure] = useState(false);
  // R-1 redesign state. `route` is the top-level page (workbench /
  // history / reports / settings); `category` is null on the landing
  // screen and set once the user picks a category card. When a report
  // is loaded (run or replayed from saved), category is auto-set to
  // the mode's owning category so the workbench shows the right context.
  const [route, setRoute] = useState<Route>("workbench");
  // PR 6 dashboard restructure: `category` state is gone — the
  // CategoryDropdown is stateless (each button manages its own open
  // state), and the user's mode pick is tracked directly as
  // `selectedMode` + `selectedAuditActive`. SelectedModePanel renders
  // inline below the dropdown row when selectedMode is non-null.
  const [selectedMode, setSelectedMode] = useState<CheckMode | null>(null);
  const [selectedAuditActive, setSelectedAuditActive] = useState(false);
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
      setRunSeq((s) => s + 1);
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
    // PR 6: the Dashboard auto-shows the SelectedModePanel when the
    // mode is set. modeCategory() is no longer needed for routing.
    setSelectedMode(recent.mode);
    setRoute("workbench");
    void runCheck(recent.mode, recent.target);
  }

  async function openSaved(meta: SavedReportMeta) {
    try {
      const { report: loaded } = await loadSavedReport(meta.id);
      const m = kindToMode(loaded.kind);
      setReport(loaded);
      setMode(m);
      setSelectedMode(m);
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

  // PR 6 dashboard restructure: pickCategory + backToLanding are
  // gone with the Category state. CategoryDropdown picks a mode
  // directly via onSelectMode below; SelectedModePanel hosts the Run
  // button. The "select a category to drill down" interaction is
  // replaced by "pick a mode from a dropdown and the panel appears."

  // R-12: when a check is running, blur the underlying shell + show a
  // fixed-position progress overlay above it. `app-shell-loading` adds
  // the blur and disables pointer interaction; the overlay handles its
  // own dismissal animation when runState flips away from "loading".
  const isLoading = runState === "loading";

  // PR 8 — Cmd/Ctrl-K now opens a CommandPalette modal instead of
  // focusing the dashboard input. The TargetInput's `inputRef` is
  // kept for accessibility / programmatic focus but is no longer
  // the K-binding target. Palette open state lives in the hook so
  // the TopAppBar's K-button can also flip it via the same setter.
  const dashboardTargetRef = useRef<HTMLInputElement | null>(null);
  const { open: paletteOpen, setOpen: setPaletteOpen } = useCommandPalette();

  // Run the selected mode against the current target. Used by the
  // TargetInput's Run pill, the SelectedModePanel's Run pill, and
  // Enter inside the TargetInput. Falls back to a Full check on
  // Network if no mode is picked yet (legacy onRunDefault behaviour).
  function runSelected() {
    if (selectedMode === null) {
      setMode("full");
      setSelectedMode("full");
      void runCheck("full");
      return;
    }
    setMode(selectedMode);
    if (selectedMode === "audit") {
      setAuditIncludeActive(selectedAuditActive);
      void runCheck("audit", undefined, selectedAuditActive);
      return;
    }
    void runCheck(selectedMode);
  }

  return (
    <div className={`app-shell ${isLoading ? "app-shell-loading" : ""}`}>
      <LoadingOverlay visible={isLoading} mode={mode} portsProgress={portsProgress} />

      {/* HUD ambient background — two soft cyan radial glows. Fixed
          and pointer-events:none so they never intercept clicks.
          z-0 keeps them behind everything in the shell. */}
      <div className="pointer-events-none fixed inset-0 z-0">
        <div
          className="absolute left-[-10%] top-[-20%] h-[50%] w-[50%] rounded-full bg-primary-fixed-dim/10"
          style={{ filter: "blur(120px)" }}
        />
        <div
          className="absolute bottom-[-20%] right-[-10%] h-[40%] w-[40%] rounded-full bg-primary-fixed-dim/5"
          style={{ filter: "blur(100px)" }}
        />
      </div>

      <SideNav route={route} onRouteChange={setRoute} />

      <TopAppBar
        onOpenPalette={() => setPaletteOpen(true)}
        actions={[
          {
            icon: "bookmark_add",
            activeIcon: savedJustNow ? "check" : undefined,
            label: savedJustNow ? "Saved" : "Save report",
            onClick: saveCurrent,
            disabled: !report || savingNow,
          },
          {
            icon: "download",
            label: "Export JSON",
            onClick: exportReport,
            disabled: !report,
          },
        ]}
      />

      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        recents={recents}
        saved={saved}
        onRoute={(r) => setRoute(r)}
        onMode={(mode, opts) => {
          setSelectedMode(mode);
          setSelectedAuditActive(opts?.auditActive ?? false);
          setRoute("workbench");
        }}
        onRecent={(recent) => rerunRecent(recent)}
        onSaved={(meta) => {
          void openSaved(meta);
        }}
      />

      <main className="workbench md:ml-64">
        {route === "workbench" ? (
          // PR 6 dashboard restructure — one continuous page:
          //   hero → target input → 3 category dropdowns → optional
          //   selected-mode panel (auth banner + extras + Run + report)
          //   → live data trio (event stream / topography / telemetry).
          //
          // Picking a mode from a dropdown reveals SelectedModePanel
          // inline. Click Run there or hit Enter in the TargetInput
          // to run. No navigation away from the page.
          <section className="flex flex-col gap-margin px-margin py-margin">
            <LandingHero lastScanAt={recents[0]?.ranAt} />

            <TargetInput
              target={target}
              onTargetChange={setTarget}
              onSubmit={runSelected}
              runDisabled={isLoading}
              inputRef={dashboardTargetRef}
            />

            <CategoryDropdown
              selectedMode={selectedMode}
              selectedAuditActive={selectedAuditActive}
              onSelectMode={(mode, opts) => {
                setSelectedMode(mode);
                setSelectedAuditActive(opts?.auditActive ?? false);
              }}
            />

            {selectedMode !== null ? (
              <SelectedModePanel
                mode={selectedMode}
                auditActive={selectedAuditActive}
                activeAcknowledged={activeAcknowledged}
                onAcknowledge={setActiveAcknowledged}
                loading={isLoading}
                runningMode={isLoading ? mode : null}
                extras={
                  selectedMode === "ports" ? (
                    <PortsProtoToggle value={portsProto} onChange={setPortsProto} />
                  ) : undefined
                }
                onRun={runSelected}
                error={runState === "error" ? error : ""}
                report={report}
                runSeq={runSeq}
                reportSlot={
                  report ? (
                    <ReportErrorBoundary key={runSeq}>
                      <ReportView loading={isLoading} report={report} />
                    </ReportErrorBoundary>
                  ) : null
                }
              />
            ) : null}

            {/* Ports SSE progress lives at the page level so the
                banner is visible whether or not SelectedModePanel
                has a report in flight yet. */}
            {isLoading && portsProgress ? <PortsProgressBanner progress={portsProgress} /> : null}

            <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
              <div className="lg:col-span-2">
                <LiveEventStream />
              </div>
              <TargetTopography />
              <div className="lg:col-span-3">
                <TelemetryStrip />
              </div>
            </div>
          </section>
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

        {PLACEHOLDER_ROUTES.has(route) ? (
          <RoutePlaceholder route={route} onBackHome={() => setRoute("workbench")} />
        ) : null}
      </main>

      <BottomNav route={route} onRouteChange={setRoute} />
      <StatusFooter lastScanAt={recents[0]?.ranAt} />
    </div>
  );
}

// ─── R-1 redesign: shell components ───────────────────────────────────────

// BrandMark (inline atom-style SVG used by the old SideNavV2 brand
// row and topbar leading) was removed in the HUD redesign PR 2. The
// new SideNav uses Material Symbols' "hub" glyph (a similar
// network-of-nodes shape) directly via <Icon name="hub" filled />,
// so the bespoke SVG no longer earns its bytes.
//
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
  // syntheticProgress is the local ramp state; the displayed progress
  // is derived below from this + visible + portsProgress. Splitting
  // "what we drive in a timer" from "what we render" is what lets us
  // drop the setState-in-effect calls that the old three-effect form
  // needed for the snap-to-100 / mirror-ports-ratio / reset-on-show
  // transitions.
  const [syntheticProgress, setSyntheticProgress] = useState(0);
  const [statusIdx, setStatusIdx] = useState(0);

  // React 19 + react-hooks v7 discourage setState inside effect bodies
  // (cascading renders) AND mutating refs during render. The "show" /
  // "reset" transitions used to be three effects with setState in the
  // synchronous path; here we collapse them into a single render-time
  // check against the previous visible value, using a state slot
  // (not a ref) for that previous value. setState during render is
  // documented and allowed when guarded by an equality check — React
  // batches it into the current render rather than scheduling a
  // follow-up. Reference:
  // https://react.dev/reference/react/useState#storing-information-from-previous-renders
  const [lastVisible, setLastVisible] = useState(visible);
  if (visible !== lastVisible) {
    setLastVisible(visible);
    if (visible) {
      // visible just flipped true: snap shown immediately so the
      // overlay mounts before the entrance animation starts, and
      // reset the per-session ramp + status cursor.
      setShown(true);
      setSyntheticProgress(0);
      setStatusIdx(0);
    }
    // visible flipped false: leave shown=true so the fade-out can
    // play; the effect below schedules setShown(false) after 280ms.
  }

  // Unmount delay: after visible flips false, wait for the exit
  // animation to finish before pulling the DOM. setState lives in the
  // setTimeout callback (rule-compliant — not in the effect body).
  useEffect(() => {
    if (visible) return;
    const t = window.setTimeout(() => setShown(false), 280);
    return () => window.clearTimeout(t);
  }, [visible]);

  // Synthetic progress ramp — only runs when there's no real progress
  // source. Real ports-scan progress is derived inline below; this
  // interval just keeps the ring moving for non-streaming checks. The
  // setState here is inside the interval callback, so the rule
  // doesn't flag it.
  useEffect(() => {
    if (!visible) return;
    if (portsProgress && portsProgress.total > 0) return;
    const interval = window.setInterval(() => {
      setSyntheticProgress((current) => {
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

  // Derived display progress, replacing the old `progress` state.
  //   - !visible → snap to 100 (ring fills before the overlay fades).
  //   - real ports-scan progress → mirror its scanned/total ratio,
  //     capped at 99 so the final tick comes from the !visible branch.
  //   - otherwise → the synthetic ramp.
  let displayProgress: number;
  if (!visible) {
    displayProgress = 100;
  } else if (portsProgress && portsProgress.total > 0) {
    displayProgress = Math.min(99, (portsProgress.scanned / portsProgress.total) * 100);
  } else {
    displayProgress = syntheticProgress;
  }

  // Progress ring math: r=54, circumference = 2πr ≈ 339.292.
  const RADIUS = 54;
  const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
  const offset = CIRCUMFERENCE - (displayProgress / 100) * CIRCUMFERENCE;

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
          <span className="progress-ring-value">{Math.floor(displayProgress)}%</span>
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

// SideNavV2 was replaced by SideNav (web/src/components/SideNav.tsx)
// in the HUD redesign PR 2. The inline NavItem helper that supported
// it is gone with it — the new SideNav embeds its own button styling
// since the visual contract (glass + left-accent border + glow) only
// applies in that one context.
//
// RoutePlaceholder renders a "Coming soon" stub for the new nav
// entries (Analytics, Nodes, Support) added by the HUD redesign.
// Each route is a real top-level Route value so the SideNav can
// highlight it; real content is a separate PR.

function RoutePlaceholder({ route, onBackHome }: { route: Route; onBackHome: () => void }) {
  const titleMap: Partial<Record<Route, string>> = {
    analytics: "Analytics",
    nodes: "Nodes",
    support: "Support",
  };
  const title = titleMap[route] ?? "Coming soon";
  return (
    <section className="result-area" aria-label={`${title} (under construction)`}>
      <div className="result-header">
        <h1>{title}</h1>
      </div>
      <p className="muted" style={{ padding: "var(--space-4)" }}>
        This area is reserved for future work and currently has no content. The nav entry exists so
        the layout stays stable; real implementation lands in a follow-up.
      </p>
      <button type="button" className="back-pill" onClick={onBackHome}>
        ← Back to dashboard
      </button>
    </section>
  );
}

// NavItem (the inline desktop-sidenav button helper) was removed
// with SideNavV2 in the HUD redesign PR 2. BottomNav still uses its
// own `BottomNavItem` for the mobile bar.

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

// Landing + CategoryCard were removed in the HUD redesign PR 3.
// The replacement renders directly in App's <main>:
//   <LandingHero /> + <CategoryBento onPick={pickCategory} />
// The target input is gone from the landing — it lives in the
// TopAppBar's global command line now (PR 2). Pressing Enter there
// fires the same Full check that the old "Run Check" button did.

// CategoryDetail was deleted in PR 6 (dashboard restructure). Its
// content moved onto the Dashboard as CategoryDropdown + SelectedModePanel,
// so the per-category drill-down page is no longer reachable.

// ModeCard was deleted in PR 6 (dashboard restructure). The
// SelectedModePanel component (web/src/components/SelectedModePanel.tsx)
// hosts the inline mode controls + Run pill that ModeCard provided.

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
  const timing = useMemo(() => timingSegments(report), [report]);
  const overallTone = report.ok ? "ok" : "crit";

  return (
    <section className={`flex flex-col gap-4 ${loading ? "opacity-70" : ""}`}>
      <div className="flex items-center justify-between">
        <h1 className="font-sans text-on-surface" style={{ fontSize: "20px", fontWeight: 600 }}>
          Full Check:{" "}
          <span className="data-value text-primary-fixed-dim">{report.target.host}</span>
        </h1>
        <StatusPill tone={overallTone} size="md">
          {report.ok ? "Healthy" : "Needs attention"}
        </StatusPill>
      </div>

      {/* Top status strip — 4 SummaryRow tiles in a grid. Each row uses
          the report's data to derive ok/crit tone + a short status word. */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <SummaryTile
          label="DNS Resolution"
          ms={report.dns.took_ms}
          tone={report.dns.error ? "crit" : "ok"}
          value={report.dns.error ? "Failed" : "Success"}
        />
        <SummaryTile
          label="TCP Connection"
          ms={tcp?.took_ms}
          tone={tcp?.error ? "crit" : tcp ? "ok" : "warn"}
          value={tcp?.error ? "Failed" : tcp ? "Success" : "Unavailable"}
        />
        <SummaryTile
          label="TLS Handshake"
          ms={report.tls?.took_ms}
          tone={report.tls?.error ? "crit" : report.tls ? "ok" : "info"}
          value={report.tls?.error ? "Failed" : report.tls ? "Success" : "Skipped"}
        />
        <SummaryTile
          label="HTTP Response"
          ms={report.http.timing.total_ms}
          tone={
            report.http.error
              ? "crit"
              : report.http.status > 0 && report.http.status < 400
                ? "ok"
                : "warn"
          }
          value={
            report.http.status
              ? `${report.http.status} ${report.http.status < 400 ? "OK" : ""}`.trim()
              : "Failed"
          }
        />
      </div>

      <Panel title="Timing Waterfall" icon="schedule">
        <div className="flex h-2 w-full overflow-hidden rounded" aria-label="HTTP timing waterfall">
          {timing.map((segment) => (
            <span
              key={segment.label}
              style={{ background: segment.color, width: `${segment.width}%` }}
            />
          ))}
        </div>
        <div
          className="mt-3 flex flex-wrap gap-3 font-sans text-on-surface-variant"
          style={{ fontSize: "11px" }}
        >
          {timing.map((segment) => (
            <span key={segment.label} className="flex items-center gap-1.5">
              <i
                className="inline-block h-2 w-2 rounded-sm"
                style={{ background: segment.color }}
              />
              {segment.label}
            </span>
          ))}
        </div>
      </Panel>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <Panel title="DNS Records" icon={<FileText />}>
          <div className="flex flex-col gap-1">
            {report.dns.a.map((ip) => (
              <DataRow key={`a-${ip}`} label="A" value={ip} />
            ))}
            {report.dns.aaaa.map((ip) => (
              <DataRow key={`aaaa-${ip}`} label="AAAA" value={ip} />
            ))}
            {report.dns.error ? (
              <p className="mt-2 font-mono text-error" style={{ fontSize: "12px" }}>
                {report.dns.error}
              </p>
            ) : null}
          </div>
        </Panel>

        <Panel title="TLS Certificate" icon={<LockKeyhole />}>
          {report.tls ? (
            <div className="flex flex-col gap-1">
              <DataRow label="Protocol" value={report.tls.version} />
              <DataRow label="Cipher" value={report.tls.cipher_suite} />
              <DataRow label="Issuer" value={report.tls.issuer} wide />
              <DataRow
                label="Expiry"
                value={`${formatDate(report.tls.not_after)} (${report.tls.days_remaining}d)`}
              />
              {report.tls.error ? (
                <p className="mt-2 font-mono text-error" style={{ fontSize: "12px" }}>
                  {report.tls.error}
                </p>
              ) : null}
            </div>
          ) : (
            <p className="font-sans text-on-surface-variant/70" style={{ fontSize: "12px" }}>
              TLS does not run for this target.
            </p>
          )}
        </Panel>

        <Panel title="HTTP Response" icon="public">
          <div className="flex flex-col gap-1">
            <DataRow
              label="Status"
              value={httpStatusLabel(report.http.status)}
              accessory={
                <StatusPill
                  tone={
                    report.http.status > 0 && report.http.status < 400
                      ? "ok"
                      : report.http.status >= 500
                        ? "crit"
                        : report.http.status >= 400
                          ? "warn"
                          : "info"
                  }
                >
                  {report.http.status || "—"}
                </StatusPill>
              }
            />
            <DataRow label="Redirects" value={report.http.hops.length} />
            <DataRow label="Server" value={report.http.server || "-"} />
            <DataRow label="Final URL" value={report.http.final_url || "-"} wide />
          </div>
          {report.http.error ? (
            <p className="mt-2 font-mono text-error" style={{ fontSize: "12px" }}>
              {report.http.error}
            </p>
          ) : null}
        </Panel>
      </div>
    </section>
  );
}

// SummaryTile is a single status cell in the Full Check top strip.
// Replaces the legacy SummaryCard pattern with the HUD tone system.
function SummaryTile({
  label,
  value,
  ms,
  tone,
}: {
  label: string;
  value: string;
  ms?: number;
  tone: "ok" | "warn" | "crit" | "info";
}) {
  return (
    <div className="glass-card rounded-lg p-3">
      <div
        className="font-sans uppercase tracking-wider text-on-surface-variant"
        style={{ fontSize: "10px", letterSpacing: "0.08em" }}
      >
        {label}
      </div>
      <div className="mt-2 flex items-end justify-between gap-2">
        <StatusPill tone={tone} size="md">
          {value}
        </StatusPill>
        <code className="data-value font-mono text-on-surface-variant" style={{ fontSize: "11px" }}>
          {formatMS(ms)}
        </code>
      </div>
    </div>
  );
}

// ─── DNS compare view ─────────────────────────────────────────────────────

// DNS_DNSSEC_TYPE_SET is a Set lookup of Tier-3 qtypes — used to split the
// rendered report into "core" vs "DNSSEC" panel groups.
const DNS_DNSSEC_TYPE_SET = new Set<string>(DNS_DNSSEC_TYPES);

function DNSCompareWorkbench({ loading, report }: { loading: boolean; report: DNSCompareReport }) {
  // Two opt-in toggles drive a re-fetch:
  //   - showMore: include Tier-2 extended types in the query
  //   - dnssec:   include Tier-3 DNSSEC types AND set the DO bit
  // When both are off, the parent-supplied `report` is rendered as-is
  // (no re-fetch). When either is on, we re-query and use the override.
  const [showMore, setShowMore] = useState(false);
  const [dnssec, setDnssec] = useState(false);
  const [override, setOverride] = useState<DNSCompareReport | null>(null);
  const [refetchLoading, setRefetchLoading] = useState(false);
  const [refetchError, setRefetchError] = useState("");

  // Parent re-running a check (whether for a new host or the same one)
  // discards both toggles and the local override. We key on
  // report.started_at — a fresh report always has a new timestamp, so
  // this also resets when the user reruns DNS Compare for the same
  // hostname, which a host-only dep would miss.
  // TODO(react19-effects): same setState-in-effect class as the effect
  // below; refactor together once the follow-up PR lands.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setShowMore(false);
    setDnssec(false);
    setOverride(null);
    setRefetchError("");
  }, [report.started_at]);

  // Compose the query whenever a toggle flips. With both toggles off we
  // clear the override so the parent report shows through; otherwise we
  // re-query with the combined type set.
  //
  // TODO(react19-effects): same setState-in-effect pattern that #110 fixed
  // for LoadingOverlay. Suppressing inline here so the show-more / DNSSEC
  // feature can land — proper refactor (derive override-vs-parent at
  // render, hoist loading/error into a small fetch-state reducer) is a
  // follow-up PR. react-hooks v7 introduced the rule; existing logic is
  // semantically correct, just triggers a cascading render.
  useEffect(() => {
    if (!showMore && !dnssec) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setOverride(null);
      setRefetchError("");
      return;
    }
    let cancelled = false;
    const types = [
      ...DNS_DEFAULT_TYPES,
      ...(showMore ? DNS_EXTENDED_TYPES : []),
      ...(dnssec ? DNS_DNSSEC_TYPES : []),
    ];
    setRefetchLoading(true);
    setRefetchError("");
    runDNSCheck(report.host, { types, dnssec })
      .then((next) => {
        if (!cancelled) setOverride(next);
      })
      .catch((err) => {
        if (!cancelled) setRefetchError((err as Error).message || "request failed");
      })
      .finally(() => {
        if (!cancelled) setRefetchLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [report.host, showMore, dnssec]);

  const view = override ?? report;
  const coreQueries = view.queries.filter((q) => !DNS_DNSSEC_TYPE_SET.has(q.qtype));
  const dnssecQueries = view.queries.filter((q) => DNS_DNSSEC_TYPE_SET.has(q.qtype));
  const allAgree = coreQueries.every((q) => q.verdict.agree);

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

      <div className="dns-settings">
        <label className="dns-settings-toggle">
          <input
            type="checkbox"
            checked={showMore}
            onChange={(e) => setShowMore(e.target.checked)}
            disabled={refetchLoading}
          />
          <span>Show more record types</span>
          <span className="muted">({DNS_EXTENDED_TYPES.join(", ")})</span>
        </label>
        <label className="dns-settings-toggle">
          <input
            type="checkbox"
            checked={dnssec}
            onChange={(e) => setDnssec(e.target.checked)}
            disabled={refetchLoading}
          />
          <span>DNSSEC mode</span>
          <span className="muted">(sets DO bit; queries {DNS_DNSSEC_TYPES.join(", ")})</span>
        </label>
        {refetchLoading ? <span className="muted">Re-querying…</span> : null}
        {refetchError ? <span className="detail-error">{refetchError}</span> : null}
      </div>

      {coreQueries.map((q) => (
        <DNSCompareQueryPanel key={q.qtype} query={q} />
      ))}

      {dnssecQueries.length > 0 ? (
        <>
          <h2 className="dns-section-heading">
            DNSSEC records
            <span className="muted"> — DO bit set on query; resolver may or may not validate</span>
          </h2>
          {dnssecQueries.map((q) => (
            <DNSCompareQueryPanel key={q.qtype} query={q} />
          ))}
        </>
      ) : null}
    </section>
  );
}

// DNSCompareQueryPanel renders one per-qtype panel. Extracted so the core
// and DNSSEC sections share the same renderer.
function DNSCompareQueryPanel({ query: q }: { query: DNSCompareReport["queries"][number] }) {
  return (
    <Panel className="dns-panel" icon={<FileText />} title={`${q.qtype} records`}>
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

// SummaryCard / Detail / Metric — adapters that delegate to the
// shared HUD components introduced in PR 7. Every legacy call site
// in the 13 not-yet-touched renderers below picks up the HUD look
// (status pills, mono data rows, glass cards) automatically. The
// adapters can be removed once per-call-site conversion is done.
//
// The old local `Panel` helper is gone — its consumers import the
// new richer Panel from ./components/Panel.

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
  const tone = error ? "crit" : "ok";
  return (
    <div className="glass-card rounded-lg p-3">
      <div
        className="font-sans uppercase tracking-wider text-on-surface-variant"
        style={{ fontSize: "10px", letterSpacing: "0.08em" }}
      >
        {label}
      </div>
      <div className="mt-2 flex items-end justify-between gap-2">
        <StatusPill tone={tone} size="md">
          {error ? "Failed" : value}
        </StatusPill>
        <code className="data-value font-mono text-on-surface-variant" style={{ fontSize: "11px" }}>
          {formatMS(ms)}
        </code>
      </div>
    </div>
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
    <DataRow
      label={label}
      value={
        error ? (
          <span className="text-error" style={{ fontWeight: 600 }}>
            {value}
          </span>
        ) : (
          value
        )
      }
    />
  );
}

// Metric adapter was removed — its callsites all came from
// FullCheckWorkbench which now uses DataRow directly. SummaryCard
// and Detail adapters stay for the not-yet-converted renderers.

function ErrorBanner({ message }: { message: string }) {
  return (
    <section className="error-banner" role="alert">
      {message}
    </section>
  );
}

// Contains render-time crashes inside the report panel so one bad
// shape (e.g. an unexpected null) doesn't blank the entire app.
// React requires class components for error boundaries (no hooks
// equivalent yet). Reset via `key` from the parent — incrementing
// runSeq on each new run remounts a fresh boundary.
class ReportErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Report render crashed:", error, info.componentStack);
  }
  render() {
    if (this.state.error) {
      return (
        <ErrorBanner
          message={`Couldn't render this report: ${this.state.error.message}. Run again or check the browser console.`}
        />
      );
    }
    return this.props.children;
  }
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
