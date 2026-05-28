// useCommandPalette — global Cmd/Ctrl-K binding for the palette modal
// (PR 8 of the HUD redesign).
//
// Previous incarnation (PR 2 → PR 6) focused a top-bar input. PR 8
// replaces that behaviour with a modal palette (CommandPalette.tsx).
// The hook now owns the open/closed state and exposes it; the
// parent renders the modal and reacts to the open prop.
//
// Binding:
//   - Cmd/Ctrl + K  → toggle palette
//   - ESC inside the palette is handled by the modal itself
//
// Usage:
//   const { open, setOpen } = useCommandPalette();
//   <CommandPalette open={open} onClose={() => setOpen(false)} ... />

import { useEffect, useState } from "react";

export function useCommandPalette() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      // Cmd-K on macOS, Ctrl-K elsewhere. Toggle even when typing
      // inside an input — the palette is a global navigation
      // affordance, not a "focus the closest field" gesture.
      if (e.key !== "k" || (!e.metaKey && !e.ctrlKey)) return;
      e.preventDefault();
      setOpen((cur) => !cur);
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  return { open, setOpen };
}
