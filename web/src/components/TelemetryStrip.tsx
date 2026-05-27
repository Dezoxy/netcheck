// HUD-redesign TelemetryStrip (PR 5 of the redesign).
//
// Polls /api/telemetry every 1s and renders:
//   - Packet Flow bar (with the translateX shimmer keyframe)
//   - Avg Latency sparkline + numeric readout
//   - Subscribers count (debug-ish; small)
//
// "Packets/sec" is the server's count of bus events per second, NOT
// network packets — see pkg/telemetry/telemetry.go. The label
// matches the Stitch mock; the meaning is documented in the API.

import { useEffect, useState } from "react";
import { getTelemetry, type TelemetrySnapshot } from "../api";

const POLL_INTERVAL_MS = 1000;

// Visual ceiling on the packet-flow bar — 5 ev/sec fills it. Real
// numbers during interactive use are way under this; the bar is
// more about "is anything happening" than precise scale.
const FLOW_CEILING = 5;

export function TelemetryStrip() {
  const [snap, setSnap] = useState<TelemetrySnapshot>({
    packets_per_sec: 0,
    avg_latency_ms: 0,
    sparkline: [],
    subscribers: 0,
  });

  useEffect(() => {
    let cancelled = false;
    async function poll() {
      try {
        const s = await getTelemetry();
        if (!cancelled) setSnap(s);
      } catch {
        // Idle on transient errors. The previous reading stays
        // visible — better than a flicker to "0".
      }
    }
    void poll();
    const id = window.setInterval(poll, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  const flowPct = Math.min(100, (snap.packets_per_sec / FLOW_CEILING) * 100);

  return (
    <div className="glass-panel flex flex-col gap-6 overflow-hidden rounded-xl bg-[#080a0f]/90 p-6">
      {/* Packet Flow */}
      <div>
        <div
          className="mb-2 flex justify-between font-sans uppercase tracking-wider text-on-surface-variant"
          style={{ fontSize: "10px" }}
        >
          <span>Packet Flow</span>
          <span className="data-value glow-text text-xs font-bold text-primary-fixed-dim">
            {snap.packets_per_sec.toFixed(2)} ev/s
          </span>
        </div>
        <div className="h-1 w-full overflow-hidden rounded-full bg-white/10">
          <div
            className="relative h-full bg-primary-fixed-dim transition-all"
            style={{
              width: `${flowPct}%`,
              boxShadow: "0 0 8px rgb(0 219 231 / 0.8)",
            }}
          >
            <div
              className="absolute inset-0 w-full bg-gradient-to-r from-transparent to-white/60"
              style={{ animation: "translateX 1s linear infinite" }}
            />
          </div>
        </div>
      </div>

      {/* Avg Latency with sparkline */}
      <div>
        <div
          className="mb-2 flex items-end justify-between font-sans uppercase tracking-wider text-on-surface-variant"
          style={{ fontSize: "10px" }}
        >
          <span>Avg Latency</span>
          <div className="flex items-end gap-2">
            <Sparkline values={snap.sparkline} />
            <span
              className="data-value text-xs font-bold text-tertiary-fixed-dim"
              style={{ textShadow: "0 0 8px rgb(232 196 35 / 0.5)" }}
            >
              {Math.round(snap.avg_latency_ms)}ms
            </span>
          </div>
        </div>
      </div>

      {/* Subscribers (low-key bottom row). */}
      <div
        className="mt-auto flex justify-between border-t border-white/5 pt-3 font-sans uppercase tracking-wider text-on-surface-variant/60"
        style={{ fontSize: "10px" }}
      >
        <span>Stream subscribers</span>
        <span className="data-value text-primary-fixed-dim/80">{snap.subscribers}</span>
      </div>
    </div>
  );
}

// Sparkline draws a tiny 60-sample polyline scaled to its viewBox.
// Width/height are inline SVG attribs (12 × 3 in viewbox units) so
// the line stays crisp at any rendered size.
function Sparkline({ values }: { values: number[] }) {
  if (values.length === 0) {
    return (
      <svg
        className="h-3 w-12 stroke-tertiary-fixed-dim/40"
        fill="none"
        strokeWidth="1.5"
        viewBox="0 0 50 15"
        aria-hidden
      >
        <path d="M0,8 L50,8" />
      </svg>
    );
  }
  const max = Math.max(...values, 1);
  const points = values
    .map((v, i) => {
      const x = (i / (values.length - 1)) * 50;
      const y = 15 - (v / max) * 14;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg
      className="h-3 w-12 stroke-tertiary-fixed-dim"
      fill="none"
      strokeWidth="1.5"
      viewBox="0 0 50 15"
      aria-hidden
    >
      <polyline points={points} />
    </svg>
  );
}
