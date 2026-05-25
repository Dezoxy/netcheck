// Package pkg is the parent of netcheck's public Go API. Each subdirectory
// is a stable library package that can be imported from outside the netcheck
// module.
//
// # Layout
//
// Check engines (each produces a typed result):
//
//   - [github.com/Dezoxy/netcheck/pkg/check]      — full DNS+TCP+TLS+HTTP probe behind `netcheck <target>`
//   - [github.com/Dezoxy/netcheck/pkg/dnscompare] — multi-resolver DNS comparison
//   - [github.com/Dezoxy/netcheck/pkg/route]      — traceroute with per-hop ASN annotation
//   - [github.com/Dezoxy/netcheck/pkg/ipinfo]     — RDAP, reverse DNS, CDN classification
//   - [github.com/Dezoxy/netcheck/pkg/secheaders] — security-header report card
//   - [github.com/Dezoxy/netcheck/pkg/techdetect] — passive CMS/framework/server fingerprinting
//   - [github.com/Dezoxy/netcheck/pkg/subenum]    — Certificate-Transparency subdomain enumeration
//   - [github.com/Dezoxy/netcheck/pkg/reverseip]  — other hostnames on the same IP
//   - [github.com/Dezoxy/netcheck/pkg/wayback]    — Wayback Machine historical snapshots
//   - [github.com/Dezoxy/netcheck/pkg/tlsaudit]   — TLS protocol+cipher matrix and cert audit
//   - [github.com/Dezoxy/netcheck/pkg/takeover]   — subdomain-takeover heuristic check
//   - [github.com/Dezoxy/netcheck/pkg/portscan]   — parallel TCP connect scan
//   - [github.com/Dezoxy/netcheck/pkg/pathenum]   — HTTP path/wordlist enumeration
//
// Schemas and tooling:
//
//   - [github.com/Dezoxy/netcheck/pkg/report]     — versioned JSON schemas + text/markdown/HTML
//     renderers for every check kind. The exported `SchemaVersion` and the
//     `*JSON` types are the v2.x stability contract for JSON consumers.
//   - [github.com/Dezoxy/netcheck/pkg/diff]       — structured diff between two report JSONs
//     (per-kind: ports opened/closed, subdomains added/removed, headers
//     regressed, …). Powers `netcheck diff` and `netcheck watch`.
//   - [github.com/Dezoxy/netcheck/pkg/target]     — URL/host normalization helpers used by
//     every check.
//
// # Stability
//
// Exported names in `pkg/` are stable across the v2.x series. Active-scanning
// packages (tlsaudit, takeover, portscan, pathenum) require the same
// "i_have_authorization" boundary as the CLI — see docs/ETHICS.md.
//
// Catalogue-style packages (techdetect, secheaders) gain new detections over
// time. Their *result shapes* are stable; the set of detections they emit
// grows. Don't pin tests to "exactly these matches."
//
// The `internal/` directory (config file format, embedded web-app bundle) is
// intentionally not part of the public API.
package pkg
