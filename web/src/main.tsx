import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
// Single stylesheet after the HUD redesign: index.css holds the Tailwind
// v4 layer plus the legacy survivor rules folded in during PR 11 (the
// former styles.css). The old two-file split is gone.
import "./index.css";

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
