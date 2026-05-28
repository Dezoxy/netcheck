// StatusPill — uniform mini-chip for OK / WARN / FAIL / INFO
// states (PR 7 of the HUD redesign).
//
// Wraps the `.status-pill` + `.status-{info,warn,crit}` utility
// classes from index.css so consumers don't have to remember the
// className combinations. Adds an `ok` tone for healthy/passing
// states (mapped to the secondary green palette).
//
// Use for: TLS Healthy/Failed, HTTP status codes by range, port
// open/closed/filtered, header grade, etc.

import type { ReactNode } from "react";

export type StatusTone = "ok" | "info" | "warn" | "crit";

interface StatusPillProps {
  tone: StatusTone;
  children: ReactNode;
  /** Override the default font size for very small contexts. */
  size?: "sm" | "md";
}

// status-pill {info,warn,crit} exist in index.css already. status-ok
// is added inline since it's only used here for a few panels and the
// extra @layer rule isn't worth it.
const TONE_STYLES: Record<StatusTone, string> = {
  info: "status-pill status-info",
  warn: "status-pill status-warn",
  crit: "status-pill status-crit",
  ok: "inline-block rounded border border-secondary-fixed-dim/40 bg-secondary-fixed-dim/10 px-1.5 py-0.5 font-mono font-bold uppercase tracking-wider text-secondary-fixed-dim",
};

export function StatusPill({ tone, children, size = "sm" }: StatusPillProps) {
  return (
    <span className={TONE_STYLES[tone]} style={{ fontSize: size === "sm" ? "10px" : "11px" }}>
      {children}
    </span>
  );
}
