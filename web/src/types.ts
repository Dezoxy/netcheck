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

export type RecentCheck = {
  ok: boolean;
  ranAt: string;
  target: string;
};

type TCPResult = {
  addr: string;
  took_ms: number;
  error?: string;
};
