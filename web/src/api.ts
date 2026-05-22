import type {
  AnyReport,
  DNSCompareReport,
  FullCheckReport,
  IPInfoReport,
  RouteReport,
  SavedReportMeta,
} from "./types";

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(path, {
    body: JSON.stringify(body),
    headers: { "Content-Type": "application/json" },
    method: "POST",
  });
  const payload = (await response.json()) as T | { error?: string };
  if (!response.ok) {
    const message = "error" in (payload as object) ? (payload as { error?: string }).error : "request failed";
    throw new Error(message || "request failed");
  }
  return payload as T;
}

export function runFullCheck(target: string, insecure: boolean): Promise<FullCheckReport> {
  return postJSON<FullCheckReport>("/api/check/full", { target, insecure });
}

export function runDNSCheck(host: string): Promise<DNSCompareReport> {
  return postJSON<DNSCompareReport>("/api/check/dns", { host });
}

export function runRouteCheck(host: string, opts?: { noASN?: boolean; maxHops?: number }): Promise<RouteReport> {
  return postJSON<RouteReport>("/api/check/route", {
    host,
    no_asn: opts?.noASN ?? false,
    max_hops: opts?.maxHops,
  });
}

export function runIPCheck(target: string): Promise<IPInfoReport> {
  return postJSON<IPInfoReport>("/api/check/ip", { target });
}

// ─── Saved reports ─────────────────────────────────────────────────────────

export async function listSavedReports(): Promise<SavedReportMeta[]> {
  const response = await fetch("/api/reports");
  if (!response.ok) {
    throw new Error("failed to load saved reports");
  }
  return (await response.json()) as SavedReportMeta[];
}

export function saveReport(report: AnyReport, label?: string): Promise<SavedReportMeta> {
  return postJSON<SavedReportMeta>("/api/reports", { report, label });
}

export async function loadSavedReport(id: string): Promise<{ report: AnyReport; meta: SavedReportMeta }> {
  const response = await fetch(`/api/reports/${encodeURIComponent(id)}`);
  if (!response.ok) {
    throw new Error("failed to load report");
  }
  const file = (await response.json()) as SavedReportMeta & { report: AnyReport };
  const { report, ...meta } = file;
  return { meta, report };
}

export async function deleteSavedReport(id: string): Promise<void> {
  const response = await fetch(`/api/reports/${encodeURIComponent(id)}`, { method: "DELETE" });
  if (!response.ok && response.status !== 404) {
    throw new Error("failed to delete report");
  }
}
