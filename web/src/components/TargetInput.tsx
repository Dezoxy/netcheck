// HUD-redesign TargetInput (PR 6 — dashboard restructure).
//
// The Dashboard's prominent target field. Replaces the TopAppBar's
// global command-line input and the old Landing's `<label.landing-input>`
// pattern. Owns nothing except markup + key handling — target state
// stays in App so every consumer (history rerun, palette, etc.) reads
// the same source.
//
// Visual: full-width terminal-styled bar with a left icon, the
// mono input, and a Run pill at the right. Enter inside the input
// also triggers Run (since the Run pill is the primary affordance).
// The pill is enabled only when a target string is present AND a
// run isn't already in flight — the parent owns those gates.
//
// Cmd/Ctrl-K (useCommandPalette) focuses this input from anywhere.

import type { ChangeEvent, KeyboardEvent, MutableRefObject } from "react";
import { Icon } from "./Icon";

interface TargetInputProps {
  target: string;
  onTargetChange: (next: string) => void;
  /** Fired by Enter in the input OR by clicking the Run pill. */
  onSubmit: () => void;
  /** Caller-owned: disable the Run pill (e.g. when a run is in flight). */
  runDisabled?: boolean;
  /** Optional copy override for the Run pill. Defaults to "Run check". */
  runLabel?: string;
  /** Ref passed to the underlying input so external hooks (Cmd-K) can focus it. */
  inputRef?: MutableRefObject<HTMLInputElement | null>;
}

export function TargetInput({
  target,
  onTargetChange,
  onSubmit,
  runDisabled = false,
  runLabel = "Run check",
  inputRef,
}: TargetInputProps) {
  function handleChange(e: ChangeEvent<HTMLInputElement>) {
    onTargetChange(e.target.value);
  }

  function handleKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" && !runDisabled && target.trim()) {
      e.preventDefault();
      onSubmit();
    }
  }

  const canRun = !runDisabled && target.trim().length > 0;

  return (
    <div className="group relative flex items-center gap-3 rounded-xl border border-white/10 bg-[#0a0c12]/80 p-3 backdrop-blur-xl transition-all input-glow">
      {/* Left terminal icon — picks up the cyan glow on focus-within
          via the group selector. */}
      <div className="flex items-center pl-2 pr-1">
        <Icon
          name="terminal"
          size="md"
          className="text-on-surface-variant transition-colors group-focus-within:text-primary-fixed-dim group-focus-within:glow-text"
        />
      </div>

      <input
        ref={inputRef}
        type="text"
        value={target}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck="false"
        placeholder="Enter target URL or IP address — e.g. example.com, 1.1.1.1"
        aria-label="Target"
        className="data-value flex-1 bg-transparent py-2 font-mono text-[15px] text-primary-fixed-dim placeholder:text-on-surface-variant/40 focus:outline-none"
      />

      <button
        type="button"
        onClick={onSubmit}
        disabled={!canRun}
        className={`flex items-center gap-2 rounded-lg border px-5 py-2 font-sans uppercase tracking-wider transition-all ${
          canRun
            ? "border-primary-fixed-dim/40 bg-primary-fixed-dim/15 text-primary-fixed-dim hover:bg-primary-fixed-dim/25 hover:glow-active"
            : "cursor-not-allowed border-white/10 bg-transparent text-on-surface-variant/30"
        }`}
        style={{ fontSize: "12px", fontWeight: 600 }}
        aria-label={runLabel}
      >
        <Icon name="play_arrow" filled size="sm" />
        <span>{runLabel}</span>
      </button>
    </div>
  );
}
