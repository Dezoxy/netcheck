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
  resolve_ms?: number;
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

// ─── v1.4 passive recon ───────────────────────────────────────────────────

export type HeadersReport = {
  netcheck_version: string;
  kind: "headers";
  url: string;
  final_url?: string;
  status?: number;
  started_at: string;
  took_ms: number;
  findings?: Array<{
    name: string;
    value?: string;
    grade: "pass" | "weak" | "missing" | "info";
    comment?: string;
  }>;
  summary: {
    pass: number;
    weak: number;
    missing: number;
    info: number;
  };
  error?: string;
};

export type TechReport = {
  netcheck_version: string;
  kind: "tech";
  url: string;
  final_url?: string;
  status?: number;
  started_at: string;
  took_ms: number;
  matches?: Array<{
    name: string;
    category: string;
    version?: string;
    confidence: string;
    evidence?: string;
  }>;
  error?: string;
};

export type SubsReport = {
  netcheck_version: string;
  kind: "subs";
  domain: string;
  started_at: string;
  took_ms: number;
  subdomains?: Array<{
    name: string;
    wildcard?: boolean;
    sources: string[];
  }>;
  source_errors?: Record<string, string>;
  error?: string;
};

export type ReverseReport = {
  netcheck_version: string;
  kind: "reverse";
  ip: string;
  started_at: string;
  took_ms: number;
  hostnames?: Array<{
    name: string;
    sources: string[];
  }>;
  source_errors?: Record<string, string>;
  source_disabled?: string[];
  error?: string;
};

export type ArchReport = {
  netcheck_version: string;
  kind: "arch";
  domain: string;
  started_at: string;
  took_ms: number;
  total: number;
  unique_urls: number;
  first?: string;
  last?: string;
  recent_samples?: Array<{
    timestamp: string;
    url: string;
    status?: number;
  }>;
  error?: string;
};

// ─── v1.4 active scanning ─────────────────────────────────────────────────

export type TLSAuditReport = {
  netcheck_version: string;
  kind: "tls-audit";
  host: string;
  port: string;
  started_at: string;
  took_ms: number;
  protocols?: Array<{
    name: string;
    supported: boolean;
    deprecated?: boolean;
    cipher?: string;
    error?: string;
  }>;
  ciphers?: Array<{
    name: string;
    insecure?: boolean;
    version?: string;
    supported: boolean;
  }>;
  cert?: {
    subject: string;
    issuer: string;
    dns_names?: string[];
    not_before: string;
    not_after: string;
    days_remaining: number;
    chain_count: number;
    self_signed?: boolean;
    expired?: boolean;
  };
  findings?: Array<{
    severity: "high" | "medium" | "info";
    title: string;
    detail?: string;
  }>;
  error?: string;
};

export type TakeoverReport = {
  netcheck_version: string;
  kind: "takeover";
  domain: string;
  has_cname: boolean;
  started_at: string;
  took_ms: number;
  findings?: Array<{
    cname: string;
    provider?: string;
    verdict: "vulnerable" | "unverifiable" | "safe" | "unknown";
    status?: number;
    detail?: string;
    notes?: string;
  }>;
  error?: string;
};

export type PortScanReport = {
  netcheck_version: string;
  kind: "ports";
  host: string;
  ip?: string;
  started_at: string;
  took_ms: number;
  ports?: Array<{
    port: number;
    service?: string;
    // Best-effort banner string from the connect-time banner grab. Empty for
    // TLS-wrapped ports (use a TLS audit instead), silent services, or when
    // banner grab was disabled at the CLI.
    banner?: string;
  }>;
  stats: {
    total: number;
    open: number;
    closed: number;
    filtered: number;
  };
  error?: string;
};

export type PathEnumReport = {
  netcheck_version: string;
  kind: "enum";
  base_url: string;
  started_at: string;
  took_ms: number;
  findings?: Array<{
    path: string;
    url: string;
    status: number;
    length?: number;
    redirect?: string;
    category: "found" | "redirect" | "blocked" | "auth-required" | "server-error";
  }>;
  stats: {
    total: number;
    interesting: number;
    not_found: number;
    errors: number;
  };
  error?: string;
};

// ─── v1.6 audit aggregate ─────────────────────────────────────────────────

// AuditReport is the consolidated envelope from `netcheck audit`. Every
// sub-report is optional (nil/undefined when the corresponding sub-check
// didn't run for the given target shape — e.g. `subs` skips for IP
// targets). Per-section errors live in `errors`; top-level failures
// (bad target etc.) live in `error`.
export type AuditReport = {
  netcheck_version: string;
  kind: "audit";
  target: string;
  host?: string;
  started_at: string;
  took_ms: number;
  active: boolean;
  ip?: IPInfoReport;
  reverse?: ReverseReport;
  subs?: SubsReport;
  arch?: ArchReport;
  headers?: HeadersReport;
  tech?: TechReport;
  tls?: TLSAuditReport;
  takeover?: TakeoverReport;
  ports?: PortScanReport;
  enum?: PathEnumReport;
  errors?: Record<string, string>;
  error?: string;
};

// AuditGrade rolls a sub-section status up to a single colour-bucket.
// Mirrors the four `[OK]` / `[WK]` / `[HI]` / `[ER]` tags the CLI emits.
export type AuditGrade = "ok" | "weak" | "high" | "err";

// ─── Union of all report kinds ────────────────────────────────────────────

export type AnyReport =
  | FullCheckReport
  | DNSCompareReport
  | RouteReport
  | IPInfoReport
  | HeadersReport
  | TechReport
  | SubsReport
  | ReverseReport
  | ArchReport
  | TLSAuditReport
  | TakeoverReport
  | PortScanReport
  | PathEnumReport
  | AuditReport;

// CheckMode is the UI's mode identifier. Note: it diverges from
// AnyReport["kind"] for TLS — UI uses "tls", payload uses "tls-audit".
export type CheckMode =
  | "full"
  | "dns"
  | "route"
  | "ip"
  | "headers"
  | "tech"
  | "subs"
  | "reverse"
  | "arch"
  | "tls"
  | "takeover"
  | "ports"
  | "enum"
  | "audit";

// ACTIVE_MODES are the ones gated behind the in-UI authorization checkbox.
// Keep this in sync with the backend's auth-gated handlers.
export const ACTIVE_MODES: readonly CheckMode[] = ["tls", "takeover", "ports", "enum"] as const;

export function isActiveMode(mode: CheckMode): boolean {
  return (ACTIVE_MODES as readonly CheckMode[]).includes(mode);
}

// MODE_GROUPS organises the 14 modes into four rows for the tab UI.
// "Aggregate" is its own row because `audit` is *composition* over the
// other tiers, not a peer of the individual checks.
export const MODE_GROUPS: Array<{ label: string; modes: CheckMode[] }> = [
  { label: "Network", modes: ["full", "dns", "route", "ip"] },
  { label: "Passive recon", modes: ["headers", "tech", "subs", "reverse", "arch"] },
  { label: "Active scanning", modes: ["tls", "takeover", "ports", "enum"] },
  { label: "Aggregate", modes: ["audit"] },
];

// ─── Recent checks (localStorage) ─────────────────────────────────────────

export type RecentCheck = {
  ok: boolean;
  ranAt: string;
  target: string;
  mode: CheckMode;
};

// ─── Saved reports (server-side) ──────────────────────────────────────────
//
// `kind` on the wire is whatever the report payload says (see AnyReport
// union — most match CheckMode, but TLS is "tls-audit"). Treat as a string
// rather than a strict CheckMode.
export type SavedReportMeta = {
  id: string;
  saved_at: string;
  kind: string;
  target: string;
  label?: string;
  ok?: boolean;
};
