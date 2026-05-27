// HUD-redesign LandingHero (PR 3 of the redesign).
//
// Sits at the top of the workbench canvas when no category is
// selected. Big uppercase "NETWORK WORKBENCH" headline + sub-blurb,
// and a small data-styled "LAST SCAN" badge on the right showing
// the timestamp of the most-recent run (or "Never" if the history
// is empty).
//
// The original Landing combined this header with the target input
// and the category grid. HUD redesign splits each concern: the
// target input lives in TopAppBar (PR 2), the category grid lives
// in CategoryBento, and this component is just the hero strip.

interface LandingHeroProps {
  /** ISO timestamp of the most recent check, or undefined when no
      run has happened yet in this session. */
  lastScanAt?: string;
}

export function LandingHero({ lastScanAt }: LandingHeroProps) {
  // Compact time format — the badge is small so we strip the date
  // and keep just HH:MM:SS in the user's locale. Falls back to a
  // muted "Never" state when there's no history yet.
  const formatted = lastScanAt
    ? new Date(lastScanAt).toLocaleTimeString(undefined, {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })
    : "Never";

  return (
    <div className="mb-2 flex flex-col items-start justify-between gap-4 md:flex-row md:items-end">
      <div>
        <h1
          className="font-sans uppercase tracking-wider text-on-surface"
          style={{ fontSize: "32px", fontWeight: 600, lineHeight: "40px", letterSpacing: "0.02em" }}
        >
          Network Workbench
        </h1>
        <p
          className="mt-1 font-sans text-on-surface-variant"
          style={{ fontSize: "14px", lineHeight: "20px" }}
        >
          Select a diagnostic module to initiate analysis.
        </p>
      </div>

      <div
        className="flex gap-4 rounded-md border border-white/10 bg-surface-container-highest/30 px-3 py-1.5 font-sans text-[11px] text-on-surface-variant"
        style={{ letterSpacing: "0.05em" }}
      >
        <span>
          LAST SCAN: <span className="data-value text-primary-fixed-dim">{formatted}</span>
        </span>
      </div>
    </div>
  );
}
