// HUD-redesign SideNav (PR 2 of the redesign).
//
// Glass left rail with the brand + four primary nav items + footer
// secondaries + user card + a START SCAN CTA. Replaces the original
// SideNavV2 from R-1. Stays hidden below the md breakpoint — mobile
// users get the BottomNav (legacy until PR 3) instead.
//
// Route mapping (label in UI → Route value):
//   Dashboard → "workbench"
//   Analytics → "analytics"  (placeholder route, "Coming soon")
//   Nodes     → "nodes"      (placeholder route, "Coming soon")
//   Logs      → "history"    (the recent-checks log)
//   Settings  → "settings"
//   Support   → "support"    (placeholder route, "Coming soon")
//
// The Analytics / Nodes / Support routes are stubs. PR 3+ wires up
// real content if we keep them; otherwise they're trimmed in PR 5.

import type { Route } from "../routes";
import { Icon } from "./Icon";

interface SideNavProps {
  route: Route;
  onRouteChange: (next: Route) => void;
  onStartScan?: () => void;
}

interface NavLink {
  route: Route;
  label: string;
  icon: string; // Material Symbols glyph name
  filled?: boolean; // some icons read better filled when active
}

const PRIMARY_LINKS: NavLink[] = [
  { route: "workbench", label: "Dashboard", icon: "dashboard", filled: true },
  { route: "analytics", label: "Analytics", icon: "analytics" },
  { route: "nodes", label: "Nodes", icon: "hub" },
  { route: "history", label: "Logs", icon: "terminal" },
];

const FOOTER_LINKS: NavLink[] = [
  { route: "settings", label: "Settings", icon: "settings" },
  { route: "support", label: "Support", icon: "help" },
];

export function SideNav({ route, onRouteChange, onStartScan }: SideNavProps) {
  return (
    <nav
      aria-label="Primary"
      className="fixed left-0 top-0 z-40 hidden h-full w-64 flex-col bg-[#0a0c12]/90 p-4 shadow-2xl backdrop-blur-2xl md:flex"
      style={{ borderRight: "1px solid rgb(255 255 255 / 0.1)" }}
    >
      {/* Brand row — hub icon + glowing wordmark. */}
      <div className="mb-10 flex items-center gap-3 px-2 pt-2">
        <Icon
          name="hub"
          filled
          size="xl"
          className="text-primary-fixed-dim"
          aria-label="netcheck brand"
        />
        <span
          className="font-sans tracking-[0.05em] text-primary-fixed-dim glow-text"
          style={{ fontSize: "24px", fontWeight: 600, lineHeight: "32px" }}
        >
          netcheck
        </span>
      </div>

      {/* Primary nav. Active item gets a left-accent border + raised
          background. Inactive items are muted with a subtle hover. */}
      <div className="flex-1 space-y-2">
        {PRIMARY_LINKS.map((link) => (
          <NavLinkButton
            key={link.route}
            link={link}
            active={route === link.route}
            onClick={() => onRouteChange(link.route)}
          />
        ))}
      </div>

      {/* Footer secondaries — settings, support. Same visual rhythm
          as primary links but separated by a divider so the eye
          groups them as "less-frequent actions". */}
      <div className="mt-auto space-y-2 border-t border-white/10 pt-6">
        {FOOTER_LINKS.map((link) => (
          <NavLinkButton
            key={link.route}
            link={link}
            active={route === link.route}
            onClick={() => onRouteChange(link.route)}
          />
        ))}
      </div>

      {/* Operator card — single-user binary so this is decorative,
          but matches the HUD mock. Could surface real info later
          (build version, last sync, etc.). */}
      <div className="mt-6 flex items-center gap-3 rounded-xl border border-white/10 bg-[#121620] px-4 py-3">
        <div
          className="flex h-8 w-8 items-center justify-center rounded-full bg-surface-bright text-primary-fixed-dim"
          style={{
            border: "1px solid rgb(0 219 231 / 0.4)",
            boxShadow: "0 0 10px rgb(0 219 231 / 0.2)",
          }}
        >
          <Icon name="person" size="sm" />
        </div>
        <div className="flex flex-col">
          <span className="font-sans text-[13px] font-medium text-on-surface">Operator</span>
          <span className="font-sans text-[11px] text-on-surface-variant">Local session</span>
        </div>
      </div>

      {/* START SCAN CTA — routes back to Dashboard (where the
          target input lives). When already on Dashboard it stays
          there. The onStartScan callback (when wired) can also
          focus the target input. */}
      <button
        type="button"
        className="mt-4 w-full rounded-lg border border-white/10 bg-[#0a0c12] py-3 font-sans text-[13px] font-bold uppercase tracking-wide text-on-surface-variant transition-all hover:border-primary-fixed-dim/40 hover:bg-primary-fixed-dim/10 hover:text-primary-fixed-dim"
        onClick={() => {
          onRouteChange("workbench");
          onStartScan?.();
        }}
      >
        Start scan
      </button>
    </nav>
  );
}

function NavLinkButton({
  link,
  active,
  onClick,
}: {
  link: NavLink;
  active: boolean;
  onClick: () => void;
}) {
  const baseClasses =
    "flex items-center gap-3 rounded-lg px-4 py-3 font-sans text-[13px] transition-all duration-150 w-full text-left";
  const activeClasses =
    "relative overflow-hidden text-primary-fixed-dim bg-[#121620] border-l-4 border-primary-fixed-dim hover:glow-active";
  const inactiveClasses =
    "text-on-surface-variant border-l-4 border-transparent hover:bg-white/5 hover:text-primary-fixed-dim";
  return (
    <button
      type="button"
      aria-current={active ? "page" : undefined}
      onClick={onClick}
      className={`${baseClasses} ${active ? activeClasses : inactiveClasses}`}
    >
      <Icon name={link.icon} filled={active && link.filled} size="md" />
      <span>{link.label}</span>
    </button>
  );
}
