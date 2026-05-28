// Panel — the workhorse glass container used by every report
// renderer (PR 7 of the HUD redesign).
//
// One uniform shell: glass background, low-alpha border, optional
// title bar with an icon + uppercase label, optional right-aligned
// accessory slot. Reuses the .glass-panel utility from index.css
// for the depth + blur; this component just adds the structural
// chrome on top.
//
// Each report renderer used to ship its own DOM scaffolding
// (.panel / .dns-panel / .summary-card / etc.). Replacing those
// with <Panel> is a hard prerequisite for PR 10's styles.css
// sunset — the legacy selectors disappear with the consumers.

import type { ReactNode } from "react";
import { Icon } from "./Icon";

export interface PanelProps {
  /** Title-bar icon. Accepts either a Material Symbols glyph name
   *  (`"language"`) — which Panel renders via `<Icon>` — or a
   *  pre-rendered ReactNode (e.g. `<Globe />` from lucide-react)
   *  for the icons not yet ported to Material Symbols. The dual
   *  shape lets PR 7 restyle the renderers without blocking on
   *  PR 10's lucide → Material Symbols sweep. */
  icon?: string | ReactNode;
  /** When `icon` is a string, render the Material Symbols glyph
   *  with FILL=1. Ignored for ReactNode icons. */
  iconFilled?: boolean;
  /** Title text. Rendered as uppercase label-caps when present. */
  title?: string;
  /** Right-aligned slot next to the title (status pill, counter,
   *  link, etc.). Hidden when title is also absent. */
  accessory?: ReactNode;
  /** Body of the panel. */
  children: ReactNode;
  /** Extra utility classes for the outer panel. */
  className?: string;
  /** Tone accent on the left border. Defaults to none (neutral). */
  tone?: "neutral" | "info" | "warn" | "crit" | "ok";
}

const TONE_BORDER: Record<NonNullable<PanelProps["tone"]>, string> = {
  neutral: "",
  info: "border-l-2 border-l-primary-fixed-dim/50",
  warn: "border-l-2 border-l-tertiary-fixed-dim/60",
  crit: "border-l-2 border-l-error/60",
  ok: "border-l-2 border-l-secondary-fixed-dim/60",
};

export function Panel({
  icon,
  iconFilled = false,
  title,
  accessory,
  children,
  className = "",
  tone = "neutral",
}: PanelProps) {
  const showTitleBar = !!title || !!icon || !!accessory;
  return (
    <section className={`glass-panel overflow-hidden rounded-xl ${TONE_BORDER[tone]} ${className}`}>
      {showTitleBar ? (
        <header className="flex items-center justify-between border-b border-white/10 bg-[#0a0c12]/60 px-5 py-3">
          <div className="flex items-center gap-2 text-primary-fixed-dim">
            {typeof icon === "string" ? (
              <Icon name={icon} filled={iconFilled} size="sm" />
            ) : icon ? (
              icon
            ) : null}
            {title ? (
              <h3
                className="font-sans uppercase tracking-widest text-on-surface"
                style={{ fontSize: "11px", fontWeight: 700, letterSpacing: "0.1em" }}
              >
                {title}
              </h3>
            ) : null}
          </div>
          {accessory ? <div className="flex items-center gap-2">{accessory}</div> : null}
        </header>
      ) : null}
      <div className="px-5 py-4">{children}</div>
    </section>
  );
}
