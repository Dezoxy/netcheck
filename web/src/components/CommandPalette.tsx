// HUD-redesign CommandPalette (PR 8 of the redesign).
//
// Cmd/Ctrl-K opens a centered modal with a search input + a
// scrollable result list, grouped by category. Substring match
// (not real fuzzy — the list is small enough that substring is
// fine and avoids pulling in a fuzzy library). Arrow keys move
// the selection, Enter fires it, ESC closes.
//
// Action sources, in priority order:
//   1. Routes (Dashboard, Logs, Settings, Analytics, Nodes, Support)
//   2. Modes (13 entries — each maps to selectedMode + runs)
//   3. Recent targets (from recents)
//   4. Saved reports (from saved metadata)
//
// The palette is render-only: every action is dispatched via a
// callback the parent supplies. Keeps it testable in isolation
// and avoids coupling the modal to App state.

import { useEffect, useMemo, useRef, useState } from "react";
import type { CheckMode, RecentCheck, SavedReportMeta } from "../types";
import type { Route } from "../routes";
import { Icon } from "./Icon";

export type PaletteAction =
  | { kind: "route"; route: Route; label: string; icon: string }
  | {
      kind: "mode";
      mode: CheckMode;
      auditActive?: boolean;
      label: string;
      icon: string;
      active: boolean; // true for active-tier modes (shows AUTH chip)
    }
  | { kind: "recent"; recent: RecentCheck; label: string }
  | { kind: "saved"; saved: SavedReportMeta; label: string };

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  recents: RecentCheck[];
  saved: SavedReportMeta[];
  // Callbacks for each action kind. The parent (App) wires these
  // up to the existing dispatchers (setRoute, runCheck, openSaved).
  onRoute: (route: Route) => void;
  onMode: (mode: CheckMode, opts?: { auditActive?: boolean }) => void;
  onRecent: (recent: RecentCheck) => void;
  onSaved: (meta: SavedReportMeta) => void;
}

const ROUTE_ACTIONS: Array<{ route: Route; label: string; icon: string }> = [
  { route: "workbench", label: "Dashboard", icon: "dashboard" },
  { route: "history", label: "Logs", icon: "terminal" },
  { route: "reports", label: "Saved reports", icon: "bookmark" },
  { route: "settings", label: "Settings", icon: "settings" },
  { route: "analytics", label: "Analytics", icon: "analytics" },
  { route: "nodes", label: "Nodes", icon: "hub" },
  { route: "support", label: "Support", icon: "help" },
];

// Modes catalog: label + icon + active-tier flag for the AUTH chip
// in the palette row. Audit splits into two entries (Passive /
// Active), matching CategoryDropdown.
const MODE_ACTIONS: Array<{
  mode: CheckMode;
  auditActive?: boolean;
  label: string;
  icon: string;
  active: boolean;
}> = [
  { mode: "full", label: "Full Check", icon: "language", active: false },
  { mode: "dns", label: "DNS Compare", icon: "compare_arrows", active: false },
  { mode: "route", label: "Route (Traceroute)", icon: "route", active: false },
  { mode: "ip", label: "IP Info", icon: "location_on", active: false },
  { mode: "headers", label: "HTTP Headers", icon: "list", active: false },
  { mode: "tech", label: "Tech Stack", icon: "memory", active: false },
  { mode: "subs", label: "Subdomain Enum", icon: "search", active: false },
  { mode: "reverse", label: "Reverse DNS", icon: "swap_horiz", active: false },
  { mode: "arch", label: "Archive (Wayback)", icon: "history", active: false },
  { mode: "audit", auditActive: false, label: "Audit (Passive)", icon: "verified", active: false },
  { mode: "audit", auditActive: true, label: "Audit (Active)", icon: "verified", active: true },
  { mode: "tls", label: "TLS Audit", icon: "lock", active: true },
  { mode: "takeover", label: "Subdomain Takeover", icon: "warning", active: true },
  { mode: "ports", label: "Port Scan", icon: "radar", active: true },
  { mode: "enum", label: "Path Enum", icon: "folder_open", active: true },
];

export function CommandPalette({
  open,
  onClose,
  recents,
  saved,
  onRoute,
  onMode,
  onRecent,
  onSaved,
}: CommandPaletteProps) {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);

  // Build the full action list each render. Cheap — the list is
  // small (~30 items) and rebuilding keeps the filter logic in one
  // place. Routes first, then modes, then recents, then saved.
  const allActions = useMemo<PaletteAction[]>(() => {
    const route: PaletteAction[] = ROUTE_ACTIONS.map((r) => ({
      kind: "route" as const,
      ...r,
    }));
    const mode: PaletteAction[] = MODE_ACTIONS.map((m) => ({
      kind: "mode" as const,
      ...m,
    }));
    const recent: PaletteAction[] = recents.map((r) => ({
      kind: "recent" as const,
      recent: r,
      label: `${r.target} — ${r.mode}`,
    }));
    const savedActions: PaletteAction[] = saved.map((s) => ({
      kind: "saved" as const,
      saved: s,
      label: `${s.target} — ${s.kind}`,
    }));
    return [...route, ...mode, ...recent, ...savedActions];
  }, [recents, saved]);

  // Filter by substring match across the action's label. Empty
  // query → everything (paged by the 8-item viewport).
  const filtered = useMemo(() => {
    if (!query.trim()) return allActions;
    const q = query.toLowerCase().trim();
    return allActions.filter((a) => a.label.toLowerCase().includes(q));
  }, [query, allActions]);

  // Reset selection + clear query whenever the modal toggles open.
  // Render-time setState (guarded by lastOpen) — the React-docs
  // "storing information from previous renders" pattern. Same
  // approach PR #110 used for LoadingOverlay; avoids the
  // react-hooks/set-state-in-effect rule.
  const [lastOpen, setLastOpen] = useState(open);
  if (open !== lastOpen) {
    setLastOpen(open);
    if (open) {
      setQuery("");
      setSelected(0);
    }
  }
  // Input focus DOES need an effect because the input ref is null
  // until after mount. `open` as the only dep means it runs each
  // time the modal opens, deferred via rAF.
  useEffect(() => {
    if (!open) return;
    const id = requestAnimationFrame(() => inputRef.current?.focus());
    return () => cancelAnimationFrame(id);
  }, [open]);

  // Clamp selection at render time so a shrinking filter doesn't
  // leave `selected` out of range. Cheaper than an effect and
  // avoids the react-hooks/set-state-in-effect rule.
  const clampedSelected = filtered.length === 0 ? 0 : Math.min(selected, filtered.length - 1);

  // ESC closes; ArrowUp/Down navigate; Enter fires.
  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelected((s) => Math.min(filtered.length - 1, s + 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelected((s) => Math.max(0, s - 1));
      } else if (e.key === "Enter") {
        e.preventDefault();
        const action = filtered[clampedSelected];
        if (action) fire(action);
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, filtered, clampedSelected, onClose]);

  // Scroll the selected row into view when navigating.
  useEffect(() => {
    if (!open || !listRef.current) return;
    const row = listRef.current.querySelector<HTMLElement>(`[data-row-index="${clampedSelected}"]`);
    row?.scrollIntoView({ block: "nearest" });
  }, [clampedSelected, open]);

  function fire(action: PaletteAction) {
    onClose();
    switch (action.kind) {
      case "route":
        onRoute(action.route);
        break;
      case "mode":
        onMode(
          action.mode,
          action.auditActive !== undefined ? { auditActive: action.auditActive } : undefined,
        );
        break;
      case "recent":
        onRecent(action.recent);
        break;
      case "saved":
        onSaved(action.saved);
        break;
    }
  }

  if (!open) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
      className="fixed inset-0 z-50 flex items-start justify-center"
      style={{ paddingTop: "12vh" }}
    >
      {/* Backdrop is a button so click-outside-to-close has real
          keyboard semantics — clicking or pressing Enter on it
          fires onClose. aria-hidden because screen readers don't
          need to announce it; ESC at document level closes too. */}
      <button
        type="button"
        aria-label="Close command palette"
        aria-hidden
        tabIndex={-1}
        onClick={onClose}
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
      />
      <div className="relative z-10 glass-panel w-full max-w-2xl overflow-hidden rounded-xl shadow-2xl">
        {/* Search bar */}
        <div className="flex items-center gap-3 border-b border-white/10 bg-[#0a0c12]/80 px-5 py-4">
          <Icon name="search" size="md" className="text-on-surface-variant" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search modes, routes, recent targets, saved reports…"
            className="flex-1 bg-transparent font-sans text-on-surface placeholder:text-on-surface-variant/40 focus:outline-none"
            style={{ fontSize: "15px" }}
          />
          <kbd
            className="rounded border border-white/10 bg-surface-container-highest/80 px-2 py-0.5 font-sans text-on-surface-variant"
            style={{ fontSize: "10px" }}
          >
            ESC
          </kbd>
        </div>

        {/* Results list */}
        <div ref={listRef} className="max-h-[60vh] overflow-y-auto p-2">
          {filtered.length === 0 ? (
            <p
              className="px-4 py-8 text-center font-sans text-on-surface-variant/50"
              style={{ fontSize: "12px" }}
            >
              No matches for {JSON.stringify(query)}
            </p>
          ) : (
            filtered.map((action, idx) => (
              <ActionRow
                key={paletteKey(action, idx)}
                action={action}
                selected={idx === clampedSelected}
                onMouseEnter={() => setSelected(idx)}
                onClick={() => fire(action)}
                index={idx}
              />
            ))
          )}
        </div>

        {/* Footer hints */}
        <div
          className="flex items-center gap-4 border-t border-white/10 bg-[#0a0c12]/80 px-5 py-3 font-sans text-on-surface-variant/70"
          style={{ fontSize: "11px" }}
        >
          <span className="flex items-center gap-1.5">
            <kbd className="rounded border border-white/10 bg-surface-container-highest/80 px-1.5 py-0.5">
              ↑↓
            </kbd>
            navigate
          </span>
          <span className="flex items-center gap-1.5">
            <kbd className="rounded border border-white/10 bg-surface-container-highest/80 px-1.5 py-0.5">
              ↵
            </kbd>
            select
          </span>
          <span className="flex items-center gap-1.5">
            <kbd className="rounded border border-white/10 bg-surface-container-highest/80 px-1.5 py-0.5">
              ESC
            </kbd>
            close
          </span>
          <span className="ml-auto data-value text-on-surface-variant/50">
            {filtered.length} / {allActions.length}
          </span>
        </div>
      </div>
    </div>
  );
}

function paletteKey(action: PaletteAction, idx: number): string {
  switch (action.kind) {
    case "route":
      return `r-${action.route}`;
    case "mode":
      return `m-${action.mode}-${action.auditActive ? "active" : "passive"}`;
    case "recent":
      return `recent-${action.recent.target}-${action.recent.mode}-${idx}`;
    case "saved":
      return `saved-${action.saved.id}`;
  }
}

interface ActionRowProps {
  action: PaletteAction;
  selected: boolean;
  index: number;
  onMouseEnter: () => void;
  onClick: () => void;
}

function ActionRow({ action, selected, index, onMouseEnter, onClick }: ActionRowProps) {
  const kindLabel: Record<PaletteAction["kind"], string> = {
    route: "ROUTE",
    mode: "MODE",
    recent: "RECENT",
    saved: "SAVED",
  };
  const icon = action.kind === "route" || action.kind === "mode" ? action.icon : "bookmark";
  return (
    <button
      type="button"
      role="option"
      aria-selected={selected}
      data-row-index={index}
      onMouseEnter={onMouseEnter}
      onClick={onClick}
      className={`flex w-full items-center gap-3 rounded px-4 py-2.5 text-left font-sans transition-colors ${
        selected
          ? "bg-primary-fixed-dim/10 text-primary-fixed-dim"
          : "text-on-surface hover:bg-white/5"
      }`}
      style={{ fontSize: "14px" }}
    >
      <Icon
        name={icon}
        size="md"
        className={selected ? "text-primary-fixed-dim" : "text-on-surface-variant"}
      />
      <span className="flex-1 truncate">{action.label}</span>
      <span
        className="font-sans uppercase tracking-wider text-on-surface-variant/50"
        style={{ fontSize: "9px", letterSpacing: "0.08em" }}
      >
        {kindLabel[action.kind]}
      </span>
      {action.kind === "mode" && action.active ? (
        <span className="status-pill status-warn" style={{ fontSize: "9px", padding: "1px 6px" }}>
          AUTH
        </span>
      ) : null}
    </button>
  );
}
