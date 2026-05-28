// DataRow — uniform "label : value" line used inside report panels
// (PR 7 of the HUD redesign).
//
// Label is Inter (UI font) in muted color; value is JetBrains Mono
// in on-surface color so numeric data and IPs align cleanly down a
// stack of rows. Mirrors the Stitch mock's "metric pair" pattern.
//
// Supports:
//   - wide layout (value spans the full row under the label)
//   - inline accessory (status pill, badge)
//   - children-as-value when the value is a node, not a string

import type { ReactNode } from "react";

interface DataRowProps {
  label: string;
  /** Primary value text — short string for "192.168.1.1", "TLS 1.3", "200 OK", etc. */
  value?: ReactNode;
  /** Optional right-aligned accessory (status pill, timing badge). */
  accessory?: ReactNode;
  /** When true the value wraps onto a new line below the label
   *  (use for long URLs / cert subjects). */
  wide?: boolean;
  /** Children replace `value` when more complex content is needed. */
  children?: ReactNode;
  /** Extra utility classes for the outer row. */
  className?: string;
}

export function DataRow({
  label,
  value,
  accessory,
  wide = false,
  children,
  className = "",
}: DataRowProps) {
  const body = children ?? value;
  if (wide) {
    return (
      <div className={`flex flex-col gap-1 py-2 ${className}`}>
        <div className="flex items-center justify-between">
          <span
            className="font-sans uppercase tracking-wider text-on-surface-variant"
            style={{ fontSize: "10px", letterSpacing: "0.08em" }}
          >
            {label}
          </span>
          {accessory ? <div className="flex items-center gap-2">{accessory}</div> : null}
        </div>
        <div
          className="data-value break-all font-mono text-on-surface"
          style={{ fontSize: "13px" }}
        >
          {body}
        </div>
      </div>
    );
  }
  return (
    <div className={`flex items-center justify-between gap-3 py-1.5 ${className}`}>
      <span
        className="font-sans uppercase tracking-wider text-on-surface-variant"
        style={{ fontSize: "10px", letterSpacing: "0.08em" }}
      >
        {label}
      </span>
      <div className="flex items-center gap-2">
        <span className="data-value font-mono text-on-surface" style={{ fontSize: "13px" }}>
          {body}
        </span>
        {accessory}
      </div>
    </div>
  );
}
