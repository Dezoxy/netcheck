// HUD-redesign CategoryBento (PR 3 of the redesign).
//
// 3-card bento grid below the LandingHero. Each card opens its
// category's workbench when clicked. The mockup explicitly drops
// the original 4th "Aggregate" category — its single mode (audit)
// is folded into Recon in App.tsx so the visual rhythm matches.
//
// Color coding mirrors the Stitch design:
//   - Network: cyan (primary)    — connectivity, DNS, routing, IP
//   - Recon:   yellow (tertiary) — passive intel (headers, tech,
//                                   subs, reverse, arch, audit)
//   - Scanning: red (error)      — active probes (TLS, takeover,
//                                   ports, enum) — requires auth
//
// Each card surfaces:
//   - Material Symbols icon (language / search / radar) tinted to
//     the category accent
//   - Title (large)
//   - Multi-line blurb
//   - "Select Module →" pseudo-CTA at the bottom-right that picks
//     up the category accent on hover
//   - Corner ambient blur in the same accent (intensifies on hover
//     via group-hover)

import { Icon } from "./Icon";

export type BentoCategory = "network" | "recon" | "scanning";

interface BentoCardSpec {
  key: BentoCategory;
  label: string;
  icon: string; // Material Symbols glyph name
  blurb: string;
  // Tailwind-arbitrary color tokens for the per-card accent. Kept
  // here as a fixed lookup so Tailwind's tree-shaker can see every
  // class name as a literal string.
  accentText: string;
  accentBg: string;
  accentBgHover: string;
  accentShadow: string;
}

const CARDS: BentoCardSpec[] = [
  {
    key: "network",
    label: "Network",
    icon: "language",
    blurb: "Analyze connectivity, DNS, and routing paths. Check latency and path consistency.",
    accentText: "text-primary-fixed-dim",
    accentBg: "bg-primary-fixed-dim/10",
    accentBgHover: "group-hover:bg-primary-fixed-dim/20",
    accentShadow: "shadow-[inset_0_0_10px_rgb(0_219_231_/_0.1)]",
  },
  {
    key: "recon",
    label: "Recon",
    icon: "search",
    blurb: "Passive intel — headers, tech stack, subdomains, reverse DNS, history. Includes Audit.",
    accentText: "text-tertiary-fixed-dim",
    accentBg: "bg-tertiary-fixed-dim/10",
    accentBgHover: "group-hover:bg-tertiary-fixed-dim/20",
    accentShadow: "shadow-[inset_0_0_10px_rgb(232_196_35_/_0.1)]",
  },
  {
    key: "scanning",
    label: "Scanning",
    icon: "radar",
    blurb: "Active probes — TLS audit, takeover, ports, paths. Requires explicit authorization.",
    accentText: "text-error",
    accentBg: "bg-error/10",
    accentBgHover: "group-hover:bg-error/20",
    accentShadow: "shadow-[inset_0_0_10px_rgb(255_180_171_/_0.1)]",
  },
];

interface CategoryBentoProps {
  onPick: (cat: BentoCategory) => void;
}

export function CategoryBento({ onPick }: CategoryBentoProps) {
  return (
    <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
      {CARDS.map((card) => (
        <BentoCard key={card.key} card={card} onClick={() => onPick(card.key)} />
      ))}
    </div>
  );
}

function BentoCard({ card, onClick }: { card: BentoCardSpec; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={`Select ${card.label} module`}
      className="glass-card group relative flex cursor-pointer flex-col overflow-hidden rounded-xl p-6 text-left transition-all hover:glow-active"
    >
      {/* Ambient corner blur. The two layered tokens (accentBg +
          accentBgHover) let the hover state intensify the glow
          without redefining the geometry. */}
      <div
        className={`absolute -right-10 -top-10 h-40 w-40 rounded-full transition-colors ${card.accentBg} ${card.accentBgHover}`}
        style={{ filter: "blur(40px)" }}
        aria-hidden
      />

      <div className="relative z-10 mb-4 flex items-center gap-4">
        <div
          className={`rounded-lg border border-white/10 bg-surface-container-highest/60 p-3 ${card.accentText} ${card.accentShadow}`}
        >
          <Icon name={card.icon} filled size="xl" />
        </div>
        <h2
          className="font-sans tracking-wide text-on-surface"
          style={{ fontSize: "24px", fontWeight: 600, lineHeight: "32px" }}
        >
          {card.label}
        </h2>
      </div>

      <p
        className="relative z-10 flex-1 font-sans text-on-surface-variant"
        style={{ fontSize: "14px", lineHeight: "20px" }}
      >
        {card.blurb}
      </p>

      <div className="relative z-10 mt-6 flex justify-end">
        <span
          className={`flex items-center gap-2 rounded-lg px-4 py-2 font-sans uppercase tracking-wider text-on-surface-variant transition-colors group-hover:${card.accentText}`}
          style={{ fontSize: "13px", fontWeight: 500 }}
        >
          Select module
          <Icon name="arrow_forward" size="sm" />
        </span>
      </div>
    </button>
  );
}
