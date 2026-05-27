import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
// HUD redesign migration: index.css (Tailwind v4 + design tokens) is
// imported BEFORE styles.css so the legacy hand-rolled rules still
// take priority while the per-component migration is in flight.
// styles.css is deleted at the end of the redesign (PR 5).
import "./index.css";
import "./styles.css";

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);

if ("serviceWorker" in navigator && import.meta.env.PROD) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js");
  });
}
