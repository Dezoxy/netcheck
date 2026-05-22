// ─── Full check ───────────────────────────────────────────────────────────

export type FullCheckReport = {
  netcheck_version: string;
  kind: "full";
  started_at: string;
  target: {
    raw: string;
    host: string;
    port: string;
    scheme: string;
  };
  dns: {
    took_ms: number;
    a: string[];
    aaaa: string[];
    error?: string;
  };
  tcp_v4?: TCPResult;
  tcp_v6?: TCPResult;
  tls?: {
    version: string;
    cipher_suite: string;
    issuer: string;
    subject: string;
    not_after: string;
    days_remaining: number;
    took_ms: number;
    error?: string;
  };
  http: {
    status: number;
    final_url: string;
    hops: Array<{
      status: number;
      url: string;
    }>;
    server?: string;
    proto?: string;
    timing: {
      dns_ms: number;
      connect_ms: number;
      tls_ms?: number;
      ttfb_ms: number;
      total_ms: number;
    };
    error?: string;
  };
  ok: boolean;
};

type TCPResult = {
  addr: string;
  took_ms: number;
  error?: string;
};

// ─── DNS compare ──────────────────────────────────────────────────────────

export type DNSCompareReport = {
  netcheck_version: string;
  kind: "dns";
  host: string;
  started_at: string;
  queries: Array<{
    qtype: string;
    results: Array<{
      name: string;
      address: string;
      records?: string[];
      took_ms: number;
      error?: string;
    }>;
    verdict: {
      agree: boolean;
      groups: Array<{
        records: string[];
        resolvers: string[];
      }>;
    };
  }>;
};

// ─── Route ────────────────────────────────────────────────────────────────

export type RouteReport = {
  netcheck_version: string;
  kind: "route";
  host: string;
  dest_ip?: string;
  tool: string;
  tool_args: string[];
  started_at: string;
  hops: Array<{
    n: number;
    timeout: boolean;
    probes?: Array<{
      host?: string;
      ip?: string;
      rtt_ms: number;
    }>;
    ips?: string[];
    asn?: {
      asn: string;
      org?: string;
      country?: string;
      prefix?: string;
      registry?: string;
    };
  }>;
  reached: boolean;
  timeouts: number;
};

// ─── IP info ──────────────────────────────────────────────────────────────

export type IPInfoReport = {
  netcheck_version: string;
  kind: "ip";
  target: string;
  started_at: string;
  from_host: boolean;
  resolve_took_ms?: number;
  details: Array<{
    ip: string;
    reverse?: string[];
    asn?: {
      asn: string;
      org?: string;
      country?: string;
      prefix?: string;
      registry?: string;
    };
    rdap?: {
      name?: string;
      registry?: string;
      country?: string;
      abuse_email?: string;
    };
    cdn?: {
      provider: string;
      confidence?: string;
      reason?: string;
    };
  }>;
};

// ─── Union of all report kinds ────────────────────────────────────────────

export type AnyReport = FullCheckReport | DNSCompareReport | RouteReport | IPInfoReport;

export type CheckMode = "full" | "dns" | "route" | "ip";

// ─── Recent checks (localStorage) ─────────────────────────────────────────

export type RecentCheck = {
  ok: boolean;
  ranAt: string;
  target: string;
  mode: CheckMode;
};

// ─── Saved reports (server-side) ──────────────────────────────────────────

export type SavedReportMeta = {
  id: string;
  saved_at: string;
  kind: CheckMode;
  target: string;
  label?: string;
  ok?: boolean;
};
