// HUD-redesign TopAppBar.
//
// PR 2 (#115) shipped this with a global command-line input. PR 6
// (dashboard restructure) removed the input — the prominent target
// field lives on the Dashboard now (TargetInput.tsx). The TopAppBar
// is now a compact bar with:
//   - a placeholder slot on the left where PR 8 (palette modal) will
//     install a "⌘K — Quick actions" button
//   - System Health pill (decorative until PR 4's bus is fully wired
//     to a real liveness signal)
//   - Notifications button (placeholder for the eventbus warn/crit
//     drain)
//   - Right-side report-action cluster (Save / Export — inherited
//     from the v1 topbar)

import { Icon } from "./Icon";

interface TopAppBarProps {
  // Right-side action buttons. Each is rendered as a square icon
  // button with the HUD glow on hover. Disabled state inherited.
  actions?: Array<{
    icon: string;
    label: string;
    onClick: () => void;
    disabled?: boolean;
    /** When set, replaces the icon with this Material Symbols glyph
        for a brief affirmative state (e.g. "check" after save). */
    activeIcon?: string;
  }>;
  /** PR 8 — clicking the left-side "Quick actions / ⌘K" trigger
   *  invokes this. App owns the palette open state; this just
   *  flips it. */
  onOpenPalette?: () => void;
}

export function TopAppBar({ actions = [], onOpenPalette }: TopAppBarProps) {
  return (
    <header
      className="z-30 flex h-20 w-full items-center justify-between bg-[#080a0f]/80 px-margin shadow-md backdrop-blur-xl"
      style={{ borderBottom: "1px solid rgb(255 255 255 / 0.1)" }}
    >
      {/* Quick-actions trigger — opens the CommandPalette modal.
          Visible on md+ so the compact mobile bar isn't cluttered;
          the keyboard shortcut works everywhere either way. */}
      <div className="flex flex-1 items-center gap-3">
        {onOpenPalette ? (
          <button
            type="button"
            onClick={onOpenPalette}
            aria-label="Open command palette"
            className="hidden items-center gap-3 rounded-lg border border-white/10 bg-[#0a0c12] px-4 py-2 text-on-surface-variant transition-colors hover:border-primary-fixed-dim/40 hover:text-primary-fixed-dim md:flex"
          >
            <Icon name="search" size="sm" />
            <span
              className="font-sans uppercase tracking-wider"
              style={{ fontSize: "11px", letterSpacing: "0.05em" }}
            >
              Quick actions
            </span>
            <kbd
              className="rounded border border-white/10 bg-surface-container-highest/80 px-1.5 py-0.5 font-sans text-on-surface-variant"
              style={{ fontSize: "10px" }}
            >
              ⌘K
            </kbd>
          </button>
        ) : null}
      </div>

      {/* Right cluster: actions + system health + notifications. */}
      <div className="ml-6 flex items-center gap-3">
        {actions.map((a) => (
          <button
            key={a.label}
            type="button"
            aria-label={a.label}
            disabled={a.disabled}
            onClick={a.onClick}
            className="group relative rounded-lg p-2 text-on-surface-variant transition-colors hover:bg-white/5 hover:text-primary-fixed-dim disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:bg-transparent disabled:hover:text-on-surface-variant"
            title={a.label}
          >
            <Icon name={a.activeIcon || a.icon} size="md" />
          </button>
        ))}

        {/* System Health pill. Pure decoration for now — real health
            checks land in PR 4 with the event bus. */}
        <div
          className="hidden items-center gap-3 rounded-lg border border-white/10 bg-[#0a0c12] px-4 py-2 transition-colors hover:border-primary-fixed-dim/40 lg:flex"
          style={{ boxShadow: "inset 0 0 10px rgb(0 219 231 / 0.02)" }}
        >
          <Icon name="favorite" filled size="sm" className="heartbeat-icon" />
          <span className="font-sans text-[11px] uppercase tracking-wider text-on-surface">
            System Health
          </span>
          <div className="mx-1 h-4 w-px bg-white/20" />
          <div className="status-dot-online" />
        </div>

        {/* Notifications. Static red badge for now — real wiring
            in PR 4 when the event bus exists. */}
        <button
          type="button"
          aria-label="Notifications"
          className="group relative rounded-full p-2 text-on-surface-variant transition-colors hover:bg-white/5 hover:text-primary-fixed-dim"
        >
          <Icon name="notifications" size="md" className="group-hover:glow-text" />
          <span
            className="absolute right-2 top-2 h-2 w-2 rounded-full bg-error"
            style={{ boxShadow: "0 0 8px rgb(255 180 171 / 0.6)" }}
          />
        </button>
      </div>
    </header>
  );
}
