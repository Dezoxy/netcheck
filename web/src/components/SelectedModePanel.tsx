// HUD-redesign SelectedModePanel (PR 6 — dashboard restructure).
//
// Renders below the CategoryDropdown row when a mode is selected.
// Hosts everything that used to live inside CategoryDetail:
//   - mode title + description
//   - mode-specific extras (PortsProtoToggle for "ports")
//   - auth banner (when an active-tier mode is selected, or audit-active)
//   - any in-flight error / loading hints (the actual loading overlay
//     stays in App since it covers the whole shell)
//   - inline report panel under the ReportErrorBoundary
//
// The panel is intentionally a "thin layout" — it imports nothing
// that wasn't already needed in App. The auth banner JSX is inlined
// here to avoid lifting one more component.

import type { ReactNode } from "react";
import type { AnyReport, CheckMode } from "../types";
import { isActiveMode } from "../types";
import { Icon } from "./Icon";

// MODE_LABEL and MODE_BLURB are duplicated from App.tsx so this
// component renders without a circular import. The duplication is
// stable (4 lines of strings); the source of truth stays in App.
const MODE_LABEL: Record<CheckMode, string> = {
  full: "Full Check",
  dns: "DNS Compare",
  route: "Route",
  ip: "IP Info",
  headers: "Headers",
  tech: "Tech",
  subs: "Subdomains",
  reverse: "Reverse DNS",
  arch: "Archive",
  whois: "Registrar",
  tls: "TLS Audit",
  takeover: "Subdomain Takeover",
  ports: "Port Scan",
  enum: "Path Enum",
  audit: "Audit",
};

const MODE_BLURB: Record<CheckMode, string> = {
  full: "DNS + TCP + TLS + HTTP probe with redirect chain and timing.",
  dns: "Compare A/AAAA/MX/TXT answers across Cloudflare, Google, Quad9, system, and any custom resolvers.",
  route: "Traceroute to the target with per-hop ASN annotation.",
  ip: "RDAP, reverse DNS, CDN affiliation, ASN ownership.",
  headers: "HTTP response + security headers (HSTS, CSP, COOP, etc.).",
  tech: "HTTP/HTML/JS fingerprinting — Wappalyzer-style detection.",
  subs: "Passive subdomain enumeration across CT, DNS, and archive sources.",
  reverse: "Find every hostname pointing at an IP via passive sources.",
  arch: "Wayback Machine snapshot history for a domain.",
  whois: "Sponsoring registrar via RDAP — name, IANA ID, and URL. Many ccTLDs expose no RDAP data.",
  tls: "Cipher / protocol / cert audit. Requires authorization.",
  takeover: "Detect dangling DNS records pointing at hijack-prone services.",
  ports: "TCP/UDP port scan. Requires authorization.",
  enum: "HTTP path enumeration. Requires authorization.",
  audit: "Cross-category audit. Passive runs the safe stack; Active includes probes.",
};

interface SelectedModePanelProps {
  mode: CheckMode;
  /** True iff the user picked "Audit (Active)" from the dropdown. */
  auditActive: boolean;
  /** The auth ack checkbox state (shared across the whole app). */
  activeAcknowledged: boolean;
  onAcknowledge: (next: boolean) => void;
  /** True iff a check is currently in flight. */
  loading: boolean;
  /** The mode whose run is in flight, if any (for the spinner). */
  runningMode: CheckMode | null;
  /** Mode-specific controls (e.g. ports protocol toggle). */
  extras?: ReactNode;
  /** Fires when the user clicks the inline Run pill. */
  onRun: () => void;
  /** Most recent error message (rendered as an inline banner). */
  error: string;
  /** Most recent report (rendered by the children prop). */
  report: AnyReport | null;
  /** Bumped on every run — keys the ReportErrorBoundary to reset. */
  runSeq: number;
  /** The actual <ReportView /> wrapped in an error boundary, supplied
   *  by the parent so this component doesn't import ReportView (which
   *  lives inside App.tsx today). */
  reportSlot: ReactNode;
}

export function SelectedModePanel({
  mode,
  auditActive,
  activeAcknowledged,
  onAcknowledge,
  loading,
  runningMode,
  extras,
  onRun,
  error,
  report,
  reportSlot,
}: SelectedModePanelProps) {
  // For audit, "active" doesn't depend on the mode itself but on
  // which variant the user picked. For everything else, the
  // isActiveMode() predicate is the truth.
  const needsAuth = mode === "audit" ? auditActive : isActiveMode(mode);
  const auditPassive = mode === "audit" && !auditActive;
  const runBlocked = loading || (needsAuth && !activeAcknowledged);
  const isRunning = loading && runningMode === mode;

  // Override the label for audit so the panel makes the variant
  // immediately legible without re-deriving from props.
  const displayLabel =
    mode === "audit" ? (auditActive ? "Audit (Active)" : "Audit (Passive)") : MODE_LABEL[mode];

  return (
    <section className="glass-panel rounded-xl p-6" aria-label={`${displayLabel} panel`}>
      {/* Header: mode name + tier chip + Run pill */}
      <div className="mb-4 flex flex-col items-start justify-between gap-3 md:flex-row md:items-center">
        <div className="flex items-center gap-3">
          <h2
            className="font-sans tracking-wide text-on-surface"
            style={{ fontSize: "20px", fontWeight: 600 }}
          >
            {displayLabel}
          </h2>
          {needsAuth ? (
            <span className="status-pill status-warn" style={{ fontSize: "10px" }}>
              ACTIVE
            </span>
          ) : (
            <span className="status-pill status-info" style={{ fontSize: "10px" }}>
              PASSIVE
            </span>
          )}
        </div>

        <button
          type="button"
          onClick={onRun}
          disabled={runBlocked}
          className={`flex items-center gap-2 rounded-lg border px-5 py-2 font-sans uppercase tracking-wider transition-all ${
            !runBlocked
              ? "border-primary-fixed-dim/40 bg-primary-fixed-dim/15 text-primary-fixed-dim hover:bg-primary-fixed-dim/25 hover:glow-active"
              : "cursor-not-allowed border-white/10 bg-transparent text-on-surface-variant/30"
          }`}
          style={{ fontSize: "12px", fontWeight: 600 }}
        >
          {isRunning ? (
            <>
              <Icon name="progress_activity" size="sm" />
              <span>Running…</span>
            </>
          ) : (
            <>
              <Icon name="play_arrow" filled size="sm" />
              <span>Run</span>
            </>
          )}
        </button>
      </div>

      <p
        className="mb-4 font-sans text-on-surface-variant"
        style={{ fontSize: "14px", lineHeight: "20px" }}
      >
        {MODE_BLURB[mode]}
        {auditPassive ? (
          <span className="ml-2 text-on-surface-variant/70">
            (Passive variant — safe to run without target authorization.)
          </span>
        ) : null}
      </p>

      {/* Mode extras: only "ports" currently injects a TCP/UDP/Both
          selector. Hidden when no extras are supplied. */}
      {extras ? <div className="mb-4">{extras}</div> : null}

      {/* Auth banner — only when an active-tier mode is the picked
          mode (or audit-active). Mirrors the old CategoryDetail's
          auth banner shape, restyled to the HUD palette. */}
      {needsAuth ? (
        <section
          className={`mb-4 flex gap-3 rounded-lg border p-4 ${
            activeAcknowledged
              ? "border-secondary-fixed-dim/30 bg-secondary-fixed-dim/5"
              : "border-error/30 bg-error/5"
          }`}
          aria-label="Active scan authorization"
        >
          <Icon name="warning" filled size="md" className="text-error" />
          <div className="flex-1">
            <strong
              className="font-sans text-on-surface"
              style={{ fontSize: "14px", fontWeight: 600 }}
            >
              {mode === "audit"
                ? "Audit (Active) includes live probes against the target."
                : "These probes actively touch the target."}
            </strong>
            <p
              className="mt-1 font-sans text-on-surface-variant"
              style={{ fontSize: "13px", lineHeight: "18px" }}
            >
              Running active probes against a system you do not own — or do not have written
              permission to test — is illegal in most jurisdictions. Read{" "}
              <a
                href="https://github.com/Dezoxy/netcheck/blob/main/docs/ETHICS.md"
                rel="noreferrer"
                target="_blank"
                className="text-primary-fixed-dim underline"
              >
                docs/ETHICS.md
              </a>
              .
            </p>
            <label
              className="mt-3 flex items-center gap-2 font-sans text-on-surface"
              style={{ fontSize: "13px" }}
            >
              <input
                type="checkbox"
                checked={activeAcknowledged}
                onChange={(e) => onAcknowledge(e.target.checked)}
              />
              <span>I am authorized to actively probe this target.</span>
            </label>
          </div>
        </section>
      ) : null}

      {/* Inline error banner — error string is the parent's `error` state
          (latest run failure). Hidden when empty. */}
      {error ? (
        <section
          className="mb-4 flex items-center gap-2 rounded border border-error/30 bg-error/10 px-4 py-3 font-sans text-error"
          role="alert"
          style={{ fontSize: "13px" }}
        >
          <Icon name="error" size="sm" />
          <span>{error}</span>
        </section>
      ) : null}

      {/* The report itself lives in the slot — keeps this component
          from importing the full ReportView dispatch. */}
      {report ? reportSlot : null}
    </section>
  );
}
