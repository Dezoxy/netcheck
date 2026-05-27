// HUD-redesign LiveEventStream (PR 5 of the redesign).
//
// Subscribes to /api/events/stream and renders the last N events as
// a scrolling list. Per the Stitch mock: a header row with a
// "Recording" pill on the right, then a stack of log rows with
// timestamp, status pill (INFO/WARN/CRIT), and a one-liner message.
//
// Capped at 100 events in state — the bus drops oldest server-side
// at 64 events per subscriber under load, but a slow render of a
// week-long stream would still pile up otherwise.

import { useEffect, useState } from "react";
import { streamEvents, type BusEvent } from "../api";
import { Icon } from "./Icon";

const MAX_EVENTS = 100;

export function LiveEventStream() {
  const [events, setEvents] = useState<BusEvent[]>([]);

  useEffect(() => {
    // streamEvents returns a `close` function; running it in
    // StrictMode dev means the subscription mounts twice but the
    // cleanup runs in between so we never leak connections.
    const close = streamEvents((ev) => {
      setEvents((prev) => {
        const next = [...prev, ev];
        // Trim oldest when over cap. Keeping the latest is what
        // matches the HUD's "fresh log tail" expectation.
        if (next.length > MAX_EVENTS) return next.slice(next.length - MAX_EVENTS);
        return next;
      });
    });
    return close;
  }, []);

  return (
    <div className="glass-panel scanline-container flex flex-col overflow-hidden rounded-xl bg-[#080a0f]/90">
      {/* Title bar. Matches the Stitch mock: small left icon + label
          (label-caps), "Recording" pill on the right. */}
      <div className="relative z-10 flex items-center justify-between border-b border-white/10 bg-[#0a0c12] px-6 py-4">
        <div className="flex items-center gap-2">
          <Icon name="list_alt" size="sm" className="text-primary-fixed-dim" />
          <h3
            className="font-sans uppercase tracking-widest text-on-surface"
            style={{ fontSize: "11px", fontWeight: 700, letterSpacing: "0.1em" }}
          >
            Live Event Stream
          </h3>
        </div>
        <div className="flex items-center gap-2 rounded-full border border-primary-fixed-dim/30 bg-primary-fixed-dim/10 px-3 py-1">
          <span
            className="font-sans uppercase tracking-wider text-primary-fixed-dim"
            style={{ fontSize: "10px", letterSpacing: "0.08em" }}
          >
            Recording
          </span>
        </div>
      </div>

      {/* Log rows. Reverse order — newest at the top for at-a-glance
          tailing. Each row: timestamp (mono) | level pill | message. */}
      <div className="relative z-10 flex max-h-[420px] flex-1 flex-col-reverse gap-1 overflow-y-auto bg-transparent p-3">
        {events.length === 0 ? (
          <p
            className="px-4 py-6 text-center font-sans text-on-surface-variant/50"
            style={{ fontSize: "12px" }}
          >
            Waiting for events…
          </p>
        ) : (
          events.map((ev, i) => <EventRow key={`${ev.ts}-${i}`} ev={ev} />)
        )}
      </div>
    </div>
  );
}

function EventRow({ ev }: { ev: BusEvent }) {
  const time = formatTime(ev.ts);
  const isCrit = ev.level === "CRIT";
  return (
    <div
      className={`flex items-center gap-4 rounded border border-transparent px-4 py-3 transition-colors hover:border-white/10 hover:bg-white/5 ${
        isCrit ? "border-error/20 bg-error/5" : ""
      }`}
    >
      <span
        className={`data-value w-24 shrink-0 font-mono ${isCrit ? "text-error/80" : "text-on-surface-variant/60"}`}
        style={{ fontSize: "11px" }}
      >
        {time}
      </span>
      <span className={`status-pill status-${ev.level.toLowerCase()} w-14 shrink-0 text-center`}>
        {ev.level}
      </span>
      <span
        className={`data-value flex-1 truncate ${isCrit ? "font-bold text-error" : "text-on-surface"}`}
        style={{ fontSize: "13px" }}
      >
        <span className="text-on-surface-variant">{ev.source}</span> <span>{ev.message}</span>
        {ev.latency_ms ? (
          <span className="ml-2 text-primary-fixed-dim">[{ev.latency_ms}ms]</span>
        ) : null}
      </span>
    </div>
  );
}

// formatTime renders HH:MM:SS.mmm in the user's locale's hour
// system. Used for the log-row timestamp column.
function formatTime(iso: string): string {
  const d = new Date(iso);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${ms.slice(0, 2)}`;
}
