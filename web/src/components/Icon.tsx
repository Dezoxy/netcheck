// Material Symbols Outlined icon wrapper.
//
// The HUD redesign replaces lucide-react with Google's Material
// Symbols Outlined font. The font is one stylesheet loaded once in
// index.html; usage is a `<span>` with class `material-symbols-outlined`
// and the glyph name as text content. This component types that
// pattern and exposes a few common knobs (filled, size, color via
// className passthrough).
//
// During the redesign migration both icon systems live side by side.
// PR 5 removes lucide-react entirely.
//
// Font variation axes:
//   - FILL  (0..1)    — 0 = outlined, 1 = solid fill
//   - wght  (100..700) — stroke weight; 400 matches body weight
//   - GRAD  (-50..200) — fine grade adjustment; we leave at 0
//   - opsz  (20..48)   — optical size; matched to the size prop
//
// See https://fonts.google.com/icons for the full catalog.

import { CSSProperties } from "react";

export type IconSize = "sm" | "md" | "lg" | "xl";

const SIZE_PX: Record<IconSize, number> = {
  sm: 16,
  md: 20,
  lg: 24,
  xl: 28,
};

export interface IconProps {
  /** Material Symbols glyph name (e.g. "hub", "language", "radar"). */
  name: string;
  /** Render as solid fill instead of outlined. Default false. */
  filled?: boolean;
  /** Visual size; controls both font-size and the optical-size axis. */
  size?: IconSize;
  /** Extra Tailwind / utility classes (e.g. text-primary-fixed-dim). */
  className?: string;
  /** ARIA label when the icon conveys meaning on its own. */
  "aria-label"?: string;
  /** Inline style passthrough — escape hatch only. */
  style?: CSSProperties;
}

export function Icon({
  name,
  filled = false,
  size = "md",
  className = "",
  "aria-label": ariaLabel,
  style,
}: IconProps) {
  const px = SIZE_PX[size];
  // font-variation-settings drives the four glyph axes. opsz matches
  // the rendered size for crisp output at each tier.
  const variation = `'FILL' ${filled ? 1 : 0}, 'wght' 400, 'GRAD' 0, 'opsz' ${px}`;
  return (
    <span
      className={`material-symbols-outlined ${className}`}
      aria-hidden={ariaLabel ? undefined : true}
      aria-label={ariaLabel}
      role={ariaLabel ? "img" : undefined}
      style={{
        fontSize: `${px}px`,
        lineHeight: 1,
        fontVariationSettings: variation,
        ...style,
      }}
    >
      {name}
    </span>
  );
}
