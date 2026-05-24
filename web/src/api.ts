import type {
  AnyReport,
  ArchReport,
  DNSCompareReport,
  FullCheckReport,
  HeadersReport,
  IPInfoReport,
  PathEnumReport,
  PortScanReport,
  ReverseReport,
  RouteReport,
  SavedReportMeta,
  SubsReport,
  TakeoverReport,
  TechReport,
  TLSAuditReport,
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

// ─── v1.4 passive recon ────────────────────────────────────────────────────

export function runHeadersCheck(url: string, insecure = false): Promise<HeadersReport> {
  return postJSON<HeadersReport>("/api/check/headers", { url, insecure });
}

export function runTechCheck(url: string, insecure = false): Promise<TechReport> {
  return postJSON<TechReport>("/api/check/tech", { url, insecure });
}

export function runSubsCheck(domain: string): Promise<SubsReport> {
  return postJSON<SubsReport>("/api/check/subs", { domain });
}

export function runReverseCheck(ip: string): Promise<ReverseReport> {
  return postJSON<ReverseReport>("/api/check/reverse", { ip });
}

export function runArchCheck(domain: string): Promise<ArchReport> {
  return postJSON<ArchReport>("/api/check/arch", { domain });
}

// ─── v1.4 active scanning ──────────────────────────────────────────────────
//
// Every active check requires `i_have_authorization: true` in the request body.
// The backend will return HTTP 403 otherwise; postJSON surfaces that as a
// thrown Error with the server's message. The UI puts this behind a checkbox.

export function runTLSAuditCheck(host: string): Promise<TLSAuditReport> {
  return postJSON<TLSAuditReport>("/api/check/tls", {
    host,
    i_have_authorization: true,
  });
}

export function runTakeoverCheck(domain: string): Promise<TakeoverReport> {
  return postJSON<TakeoverReport>("/api/check/takeover", {
    domain,
    i_have_authorization: true,
  });
}

export function runPortsCheck(
  host: string,
  opts?: { ports?: string; top?: number; concurrency?: number },
): Promise<PortScanReport> {
  return postJSON<PortScanReport>("/api/check/ports", {
    host,
    ports: opts?.ports,
    top: opts?.top,
    concurrency: opts?.concurrency,
    i_have_authorization: true,
  });
}

export function runEnumCheck(
  url: string,
  opts?: { insecure?: boolean; followRedirects?: boolean },
): Promise<PathEnumReport> {
  return postJSON<PathEnumReport>("/api/check/enum", {
    url,
    insecure: opts?.insecure ?? false,
    follow_redirects: opts?.followRedirects ?? false,
    i_have_authorization: true,
  });
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
