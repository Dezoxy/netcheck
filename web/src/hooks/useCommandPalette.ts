// useCommandPalette — global Cmd/Ctrl-K binding for the top app bar.
//
// PR 2 wires this to "focus the global command input". PR 5 will
// upgrade the same shortcut to open a command-palette modal
// (jump-to-category, recent target, recent report). The hook itself
// is a one-event listener so the binding stays cheap even with the
// future modal layered on top.
//
// Usage:
//   const inputRef = useRef<HTMLInputElement | null>(null);
//   useCommandPalette(inputRef);
//   <TopAppBar inputRef={inputRef} ... />

import { MutableRefObject, useEffect } from "react";

export function useCommandPalette(inputRef: MutableRefObject<HTMLInputElement | null>) {
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      // Cmd-K on macOS, Ctrl-K elsewhere. Skip when the user is
      // already typing in a contenteditable or another input — that
      // would steal focus from a form they're filling in.
      if (e.key !== "k" || (!e.metaKey && !e.ctrlKey)) return;
      const active = document.activeElement;
      if (
        active instanceof HTMLInputElement ||
        active instanceof HTMLTextAreaElement ||
        (active instanceof HTMLElement && active.isContentEditable)
      ) {
        // Only steal focus if the active input isn't already our
        // own — otherwise pressing ⌘K while in the target field
        // would re-focus the same field (harmless but pointless).
        if (active === inputRef.current) return;
      }
      e.preventDefault();
      inputRef.current?.focus();
      inputRef.current?.select();
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [inputRef]);
}
