// HUD-redesign CategoryDropdown (PR 6 — dashboard restructure).
//
// Three category buttons (Network / Recon / Scanning), each opens a
// popover menu listing its modes. Picking a mode emits onSelectMode
// upward — App stores selectedMode + selectedModeOpts and renders
// the SelectedModePanel below. This component owns:
//   - per-button open/close state (only one menu open at a time)
//   - click-outside + ESC to close
//   - "selected" visual highlight on the category whose mode is active
//
// Audit appears twice in Recon's menu: "Audit (Passive)" and
// "Audit (Active)". Picking either dispatches with the right
// auditActive flag. The Active entry shows a small AUTH chip so the
// difference is visible without expanding the help text.

import { useEffect, useRef, useState } from "react";
import type { CheckMode } from "../types";
import { isActiveMode } from "../types";
import { Icon } from "./Icon";

// Local copies of the labels — pulled from App.tsx MODE_LABEL so the
// dropdown can render without importing all of App. Keep in sync.
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

// Each category has a fixed accent color (matches the bento mockup):
// Network = cyan, Recon = yellow, Scanning = red.
type CategoryKey = "network" | "recon" | "scanning";

interface CategorySpec {
  key: CategoryKey;
  label: string;
  icon: string;
  modes: CheckMode[];
  accentText: string;
  accentBg: string;
  accentBorder: string;
}

// Note: the source-of-truth `CATEGORIES` lives in App.tsx for mode-
// dispatch (modeCategory). This dropdown carries its own annotated
// copy so it can render labels + accents without lifting more props.
const CATEGORIES: CategorySpec[] = [
  {
    key: "network",
    label: "Network",
    icon: "language",
    modes: ["full", "dns", "route", "ip"],
    accentText: "text-primary-fixed-dim",
    accentBg: "bg-primary-fixed-dim/10",
    accentBorder: "border-primary-fixed-dim/30",
  },
  {
    key: "recon",
    label: "Recon",
    icon: "search",
    modes: ["audit", "headers", "tech", "subs", "reverse", "arch", "whois"],
    accentText: "text-tertiary-fixed-dim",
    accentBg: "bg-tertiary-fixed-dim/10",
    accentBorder: "border-tertiary-fixed-dim/30",
  },
  {
    key: "scanning",
    label: "Scanning",
    icon: "radar",
    modes: ["tls", "takeover", "ports", "enum"],
    accentText: "text-error",
    accentBg: "bg-error/10",
    accentBorder: "border-error/30",
  },
];

// Audit splits into two dropdown entries — the dual-pill from the
// old ModeCard collapses into two picks. The split lets the user
// commit to a variant from the dropdown before the SelectedModePanel
// renders the auth ack (Active only).
interface DropdownEntry {
  mode: CheckMode;
  label: string;
  active: boolean; // active-tier flag drives the AUTH chip
  // For audit, opts.auditActive distinguishes the two entries.
  opts?: { auditActive?: boolean };
}

function entriesFor(spec: CategorySpec): DropdownEntry[] {
  return spec.modes.flatMap<DropdownEntry>((m) => {
    if (m === "audit") {
      return [
        {
          mode: "audit",
          label: "Audit (Passive)",
          active: false,
          opts: { auditActive: false },
        },
        {
          mode: "audit",
          label: "Audit (Active)",
          active: true,
          opts: { auditActive: true },
        },
      ];
    }
    return [
      {
        mode: m,
        label: MODE_LABEL[m],
        active: isActiveMode(m),
      },
    ];
  });
}

interface CategoryDropdownProps {
  selectedMode: CheckMode | null;
  selectedAuditActive?: boolean;
  onSelectMode: (mode: CheckMode, opts?: { auditActive?: boolean }) => void;
}

export function CategoryDropdown({
  selectedMode,
  selectedAuditActive,
  onSelectMode,
}: CategoryDropdownProps) {
  // Track which category's menu is open (null = all closed). Only one
  // menu open at a time — simpler UX and avoids overlap on small
  // viewports.
  const [openKey, setOpenKey] = useState<CategoryKey | null>(null);

  return (
    <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
      {CATEGORIES.map((spec) => (
        <CategoryButton
          key={spec.key}
          spec={spec}
          isOpen={openKey === spec.key}
          onToggle={() => setOpenKey((cur) => (cur === spec.key ? null : spec.key))}
          onClose={() => setOpenKey(null)}
          selectedMode={selectedMode}
          selectedAuditActive={selectedAuditActive}
          onSelectMode={(mode, opts) => {
            onSelectMode(mode, opts);
            setOpenKey(null);
          }}
        />
      ))}
    </div>
  );
}

function CategoryButton({
  spec,
  isOpen,
  onToggle,
  onClose,
  selectedMode,
  selectedAuditActive,
  onSelectMode,
}: {
  spec: CategorySpec;
  isOpen: boolean;
  onToggle: () => void;
  onClose: () => void;
  selectedMode: CheckMode | null;
  selectedAuditActive?: boolean;
  onSelectMode: (mode: CheckMode, opts?: { auditActive?: boolean }) => void;
}) {
  // Close on ESC + click-outside. ref scoping keeps the listener
  // cheap — one window-level mousedown, with a contains() check.
  const ref = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (!isOpen) return;
    function onMouseDown(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("mousedown", onMouseDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("mousedown", onMouseDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [isOpen, onClose]);

  const entries = entriesFor(spec);
  // A category is "selected" if its mode list contains the active
  // mode. For audit the auditActive flag also has to match.
  const hasSelection = entries.some(
    (e) =>
      e.mode === selectedMode &&
      (e.mode !== "audit" || (e.opts?.auditActive ?? false) === (selectedAuditActive ?? false)),
  );

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={isOpen}
        aria-haspopup="menu"
        className={`glass-card flex w-full items-center justify-between rounded-xl px-5 py-4 text-left transition-all ${
          hasSelection ? `${spec.accentBg} ${spec.accentBorder} glow-active` : "hover:glow-active"
        }`}
      >
        <span className="flex items-center gap-3">
          <span className={`rounded-lg p-2 ${spec.accentBg} ${spec.accentText}`}>
            <Icon name={spec.icon} filled size="md" />
          </span>
          <span
            className="font-sans tracking-wide text-on-surface"
            style={{ fontSize: "18px", fontWeight: 600 }}
          >
            {spec.label}
          </span>
        </span>
        <Icon
          name={isOpen ? "expand_less" : "expand_more"}
          size="md"
          className="text-on-surface-variant transition-transform"
        />
      </button>

      {isOpen ? (
        <div
          role="menu"
          className="absolute left-0 right-0 top-full z-20 mt-2 overflow-hidden rounded-xl border border-white/10 bg-[#0a0c12]/95 py-2 shadow-2xl backdrop-blur-xl"
        >
          {entries.map((entry) => {
            const isSelected =
              entry.mode === selectedMode &&
              (entry.mode !== "audit" ||
                (entry.opts?.auditActive ?? false) === (selectedAuditActive ?? false));
            return (
              <button
                key={entry.label}
                role="menuitem"
                type="button"
                onClick={() => onSelectMode(entry.mode, entry.opts)}
                className={`flex w-full items-center justify-between px-5 py-3 text-left font-sans transition-colors ${
                  isSelected
                    ? `${spec.accentBg} ${spec.accentText}`
                    : "text-on-surface hover:bg-white/5"
                }`}
                style={{ fontSize: "14px" }}
              >
                <span>{entry.label}</span>
                {entry.active ? (
                  <span
                    className="status-pill status-warn"
                    style={{ fontSize: "9px", padding: "1px 6px" }}
                  >
                    AUTH
                  </span>
                ) : null}
              </button>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}
