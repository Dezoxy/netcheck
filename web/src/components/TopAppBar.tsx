// HUD-redesign TopAppBar (PR 2 of the redesign).
//
// 80px-tall sticky bar above the main canvas. Three regions:
//   - Global command line (left, max 768px) — terminal icon + input
//     with a Cmd/Ctrl-K hint chip. Used today to focus + type a
//     target; in PR 5 it becomes a real command palette modal.
//   - System Health pill (lg+ only) — heartbeat icon + green dot,
//     just a presence indicator; no real backend wiring yet.
//   - Notifications + report actions (right).
//
// The Save/Export report buttons that used to live in the old
// `.topbar` are kept here on the right side so the function isn't
// lost mid-migration. They visually fit the HUD aesthetic but will
// likely move to a contextual report toolbar in PR 5.

import type { ChangeEvent, KeyboardEvent, MutableRefObject } from "react";
import { Icon } from "./Icon";

interface TopAppBarProps {
  target: string;
  onTargetChange: (next: string) => void;
  // onTargetSubmit fires when the user presses Enter in the command
  // line. When `category === null` and we're on Dashboard, this
  // should kick off the default Full check (matching the old
  // landing's behavior).
  onTargetSubmit?: () => void;
  // Ref to the input element so a Cmd+K hook elsewhere can focus
  // the field globally.
  inputRef?: MutableRefObject<HTMLInputElement | null>;
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
}

export function TopAppBar({
  target,
  onTargetChange,
  onTargetSubmit,
  inputRef,
  actions = [],
}: TopAppBarProps) {
  function handleChange(e: ChangeEvent<HTMLInputElement>) {
    onTargetChange(e.target.value);
  }

  function handleKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" && onTargetSubmit) {
      e.preventDefault();
      onTargetSubmit();
    }
  }

  return (
    <header
      className="z-30 flex h-20 w-full items-center justify-between bg-[#080a0f]/80 px-margin shadow-md backdrop-blur-xl"
      style={{ borderBottom: "1px solid rgb(255 255 255 / 0.1)" }}
    >
      {/* Global command line. group lets the focus state ripple to
          the icon + glow utility. The kbd chip on the right is a
          visual hint that ⌘K focuses this input (the actual binding
          lives in useCommandPalette). */}
      <div className="group relative flex max-w-3xl flex-1 items-center">
        <Icon
          name="terminal"
          size="md"
          className="absolute left-4 text-on-surface-variant transition-colors group-focus-within:text-primary-fixed-dim group-focus-within:glow-text"
        />
        <input
          ref={inputRef}
          type="text"
          value={target}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck="false"
          placeholder="Enter target URL or IP address... (e.g., example.com)"
          className="input-glow data-value w-full rounded-lg border border-white/10 bg-[#0a0c12] py-3 pl-12 pr-20 font-mono text-[13px] text-primary-fixed-dim transition-all placeholder:text-on-surface-variant/50 focus:bg-[#10131a] focus:outline-none"
        />
        <kbd className="absolute right-3 hidden rounded border border-white/10 bg-surface-container-highest/80 px-2 py-1 font-sans text-[11px] text-on-surface-variant sm:inline-block">
          ⌘K
        </kbd>
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
