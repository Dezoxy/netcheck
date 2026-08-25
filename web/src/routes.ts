// Shared route types.
//
// During the HUD redesign (PR 2) the nav grew from four routes to
// six, three of which are placeholders (analytics, nodes, support).
// The new SideNav, TopAppBar, and the existing App component all
// need the same Route union, so it moved out of App.tsx and into
// this small module.
//
// Route → UI label map (HUD nav labels differ from internal values):
//   workbench → Dashboard
//   history   → Logs
//   reports   → (kept for backwards compat with the old SaveReports
//               panel; no nav entry yet — accessed from contextual
//               toolbar)
//   settings  → Settings
//   analytics → Analytics (placeholder)
//   nodes     → Nodes     (placeholder)
//   support   → Support   (placeholder)

export type Route =
  "workbench" | "history" | "reports" | "settings" | "analytics" | "nodes" | "support";

// PLACEHOLDER_ROUTES is the subset that renders the "Coming soon"
// stub. Kept here so the App component can dispatch on it without
// hardcoding the list in two places.
export const PLACEHOLDER_ROUTES: ReadonlySet<Route> = new Set(["analytics", "nodes", "support"]);
