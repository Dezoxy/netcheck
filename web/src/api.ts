import type {
  AnyReport,
  ArchReport,
  AuditReport,
  DiffReport,
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
    const message =
      "error" in (payload as object) ? (payload as { error?: string }).error : "request failed";
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

export function runRouteCheck(
  host: string,
  opts?: { noASN?: boolean; maxHops?: number },
): Promise<RouteReport> {
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

// PortProgress is one progress event from /api/check/ports/stream.
// Mirrors the Go-side `portscan.Progress` shape — keep them in sync.
export type PortProgress = {
  port: number;
  state: "open" | "closed" | "filtered";
  service?: string;
  index: number;
  total: number;
};

export type StreamPortsHandlers = {
  onProgress?: (p: PortProgress) => void;
  onDone?: (report: PortScanReport) => void;
  onError?: (err: Error) => void;
};

// streamPortsCheck POSTs the same body as runPortsCheck but reads back a
// text/event-stream and dispatches `progress` and `done` events to the
// supplied handlers. Returns an `abort` function — call it to cancel the
// scan mid-stream (the server's context cancellation will stop new dials).
//
// We use fetch + ReadableStream rather than EventSource because EventSource
// is GET-only. POST keeps the auth flag in the body where the rest of the
// API expects it.
export function streamPortsCheck(
  host: string,
  handlers: StreamPortsHandlers,
  opts?: { ports?: string; top?: number; concurrency?: number },
): { abort: () => void } {
  const ctrl = new AbortController();
  (async () => {
    let response: Response;
    try {
      response = await fetch("/api/check/ports/stream", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          host,
          ports: opts?.ports,
          top: opts?.top,
          concurrency: opts?.concurrency,
          i_have_authorization: true,
        }),
        signal: ctrl.signal,
      });
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        handlers.onError?.(err as Error);
      }
      return;
    }
    if (!response.ok) {
      // Non-2xx — body is the standard JSON error envelope.
      try {
        const j = (await response.json()) as { error?: string };
        handlers.onError?.(new Error(j.error || `HTTP ${response.status}`));
      } catch {
        handlers.onError?.(new Error(`HTTP ${response.status}`));
      }
      return;
    }
    if (!response.body) {
      handlers.onError?.(new Error("no response body"));
      return;
    }
    // Minimal SSE parser. SSE frames are delimited by `\n\n`; within each
    // frame, `event: NAME` and `data: JSON` are the lines we care about.
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        let frameEnd: number;
        while ((frameEnd = buf.indexOf("\n\n")) !== -1) {
          const frame = buf.slice(0, frameEnd);
          buf = buf.slice(frameEnd + 2);
          dispatchFrame(frame, handlers);
        }
      }
      // Flush any final frame (server should terminate with \n\n, but be
      // defensive against proxy quirks).
      if (buf.trim().length > 0) {
        dispatchFrame(buf, handlers);
      }
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        handlers.onError?.(err as Error);
      }
    }
  })();
  return { abort: () => ctrl.abort() };
}

function dispatchFrame(frame: string, handlers: StreamPortsHandlers) {
  let event = "";
  let data = "";
  for (const line of frame.split("\n")) {
    if (line.startsWith("event: ")) {
      event = line.slice(7);
    } else if (line.startsWith("data: ")) {
      data = line.slice(6);
    }
  }
  if (!event || !data) return;
  let payload: unknown;
  try {
    payload = JSON.parse(data);
  } catch {
    return;
  }
  switch (event) {
    case "progress":
      handlers.onProgress?.(payload as PortProgress);
      break;
    case "done":
      handlers.onDone?.(payload as PortScanReport);
      break;
    case "error":
      handlers.onError?.(
        new Error(String((payload as { error?: string }).error || "stream error")),
      );
      break;
  }
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

// ─── v1.6 aggregate audit ──────────────────────────────────────────────────
//
// Passive audit (active=false) needs no authorization — composition over
// the passive sub-commands which themselves need no auth. With active=true
// the request body must include `i_have_authorization: true`; the backend
// returns 403 otherwise. The UI gates that path behind the same checkbox
// the standalone active commands use.

export function runAuditCheck(
  target: string,
  opts?: { active?: boolean; insecure?: boolean },
): Promise<AuditReport> {
  return postJSON<AuditReport>("/api/check/audit", {
    target,
    active: opts?.active ?? false,
    insecure: opts?.insecure ?? false,
    i_have_authorization: opts?.active === true,
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

export async function loadSavedReport(
  id: string,
): Promise<{ report: AnyReport; meta: SavedReportMeta }> {
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

// ─── Diff (R-7) ────────────────────────────────────────────────────────────

// diffReports compares two report bodies via the server's /api/diff
// endpoint and returns the structured diff. The server delegates to
// pkg/diff so the result is byte-identical to `netcheck diff --output
// json a.json b.json`.
export function diffReports(oldReport: AnyReport, newReport: AnyReport): Promise<DiffReport> {
  return postJSON<DiffReport>("/api/diff", { old: oldReport, new: newReport });
}
