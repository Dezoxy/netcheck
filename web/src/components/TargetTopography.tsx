// HUD-redesign TargetTopography (PR 5 of the redesign).
//
// Polls /api/topology every 2s and renders the latest traceroute as
// nodes + edges in an SVG. The Stitch mock has decorative random
// nodes; we render real ones from the route check result. The
// active node (target hop) gets the radar-pulse animation; timeout
// hops render dim; everything else cyan.
//
// Empty state (no route check has run): an ambient radial gradient
// + "No active scan" text.

import { useEffect, useState } from "react";
import { getTopology, type TopologyGraph } from "../api";
import { Icon } from "./Icon";

const POLL_INTERVAL_MS = 2000;

export function TargetTopography() {
  const [graph, setGraph] = useState<TopologyGraph>({
    nodes: [],
    edges: [],
    updated_at: undefined,
  });

  useEffect(() => {
    let cancelled = false;
    // First fetch happens immediately; subsequent polls every 2s.
    // Cancelled when the effect tears down (route change, unmount).
    async function poll() {
      try {
        const g = await getTopology();
        if (!cancelled) setGraph(g);
      } catch {
        // Network blip — keep the last graph on screen and try again
        // on the next tick. No need to surface this to the UI.
      }
    }
    void poll();
    const id = window.setInterval(poll, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  const hasNodes = graph.nodes.length > 0;

  return (
    <div className="glass-panel group relative flex flex-col overflow-hidden rounded-xl bg-[#080a0f]/90">
      <div className="relative z-20 border-b border-white/10 bg-[#0a0c12] px-6 py-4">
        <div className="flex items-center gap-2">
          <Icon name="my_location" size="sm" className="text-primary-fixed-dim" />
          <h3
            className="font-sans uppercase tracking-widest text-on-surface"
            style={{ fontSize: "11px", fontWeight: 700, letterSpacing: "0.1em" }}
          >
            Target Topography
          </h3>
        </div>
      </div>

      {/* Ambient backdrop + node graph. The radial gradient fades
          the edges so the SVG stops feeling like a hard rectangle. */}
      <div className="relative z-10 flex flex-1 items-center justify-center bg-transparent">
        <div
          className="absolute inset-0 opacity-60"
          style={{
            background:
              "radial-gradient(circle at center, rgb(0 219 231 / 0.08) 0%, transparent 60%)",
          }}
          aria-hidden
        />

        {hasNodes ? (
          <svg
            className="absolute inset-0 h-full w-full"
            fill="none"
            viewBox="0 0 100 100"
            preserveAspectRatio="none"
            aria-label="Network topology of the last traceroute"
          >
            <defs>
              <filter id="topo-glow">
                <feGaussianBlur stdDeviation="0.4" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>

            {/* Edges first so nodes overpaint them. */}
            {graph.edges.map((e) => {
              const from = graph.nodes.find((n) => n.id === e.from);
              const to = graph.nodes.find((n) => n.id === e.to);
              if (!from || !to) return null;
              return (
                <line
                  key={`${e.from}-${e.to}`}
                  x1={from.x * 100}
                  y1={from.y * 100}
                  x2={to.x * 100}
                  y2={to.y * 100}
                  stroke="rgb(0 219 231 / 0.3)"
                  strokeWidth={0.3}
                />
              );
            })}

            {/* Packets: bright dots streaming from each hop to the next,
                so a static graph still reads as live traffic. Staggered
                begin offsets keep them from marching in lockstep. */}
            {graph.edges.map((e, i) => {
              const from = graph.nodes.find((n) => n.id === e.from);
              const to = graph.nodes.find((n) => n.id === e.to);
              if (!from || !to) return null;
              return (
                <circle
                  key={`pkt-${e.from}-${e.to}`}
                  r={0.45}
                  fill="#00f2ff"
                  filter="url(#topo-glow)"
                >
                  <animateMotion
                    dur="1.8s"
                    begin={`${(i % 5) * 0.36}s`}
                    repeatCount="indefinite"
                    path={`M ${from.x * 100} ${from.y * 100} L ${to.x * 100} ${to.y * 100}`}
                  />
                </circle>
              );
            })}

            {/* Nodes: small dots, with a pulsing ring around the target. */}
            {graph.nodes.map((n) => {
              const color = nodeColor(n.status);
              return (
                <g key={n.id}>
                  <circle
                    cx={n.x * 100}
                    cy={n.y * 100}
                    r={n.status === "target" ? 0.8 : 0.5}
                    fill={color}
                    filter="url(#topo-glow)"
                  />
                  {n.status === "target" ? (
                    <circle
                      cx={n.x * 100}
                      cy={n.y * 100}
                      r={1}
                      fill="none"
                      stroke="rgb(0 219 231 / 0.6)"
                      strokeWidth={0.15}
                      style={{ animation: "radarPulse 3s ease-out infinite" }}
                    />
                  ) : null}
                </g>
              );
            })}
          </svg>
        ) : (
          <div className="relative z-10 flex flex-col items-center gap-2 text-on-surface-variant/60">
            {/* A rotating wedge of light behind the icon keeps the idle
                panel reading as a live radar dish rather than a dead state. */}
            <div className="relative flex h-24 w-24 items-center justify-center">
              <div
                className="absolute inset-0 rounded-full"
                style={{
                  background:
                    "conic-gradient(from 0deg, transparent 0deg, rgb(0 219 231 / 0.18) 40deg, transparent 70deg)",
                  animation: "radarSweep 4s linear infinite",
                }}
                aria-hidden
              />
              <Icon name="radar" size="xl" className="relative text-primary-fixed-dim/40" />
            </div>
            <span className="font-sans uppercase tracking-wider" style={{ fontSize: "11px" }}>
              No active scan
            </span>
          </div>
        )}
      </div>

      {/* Hop count footer for context. */}
      {hasNodes ? (
        <div className="relative z-20 border-t border-white/10 bg-gradient-to-t from-[#080a0f] via-[#080a0f]/80 to-transparent px-6 py-3">
          <div
            className="flex justify-between font-sans uppercase tracking-wider text-on-surface-variant"
            style={{ fontSize: "10px" }}
          >
            <span>
              {graph.nodes.length - 1} {graph.nodes.length === 2 ? "hop" : "hops"}
            </span>
            <span>
              {graph.updated_at ? `updated ${new Date(graph.updated_at).toLocaleTimeString()}` : ""}
            </span>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function nodeColor(status: string): string {
  switch (status) {
    case "self":
      return "#00f2ff";
    case "target":
      return "#00dbe7";
    case "timeout":
      return "#3a494b";
    default:
      return "#00dbe7";
  }
}
