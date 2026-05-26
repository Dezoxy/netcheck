package report

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/Dezoxy/netcheck/pkg/check"
	"github.com/Dezoxy/netcheck/pkg/dnscompare"
	"github.com/Dezoxy/netcheck/pkg/ipinfo"
	"github.com/Dezoxy/netcheck/pkg/pathenum"
	"github.com/Dezoxy/netcheck/pkg/portscan"
	"github.com/Dezoxy/netcheck/pkg/reverseip"
	"github.com/Dezoxy/netcheck/pkg/route"
	"github.com/Dezoxy/netcheck/pkg/secheaders"
	"github.com/Dezoxy/netcheck/pkg/subenum"
	"github.com/Dezoxy/netcheck/pkg/takeover"
	"github.com/Dezoxy/netcheck/pkg/target"
	"github.com/Dezoxy/netcheck/pkg/techdetect"
	"github.com/Dezoxy/netcheck/pkg/tlsaudit"
	"github.com/Dezoxy/netcheck/pkg/wayback"
)

// SchemaVersion is the netcheck JSON schema version. Bump on any breaking
// change to field names, types, or removal of fields. Additive changes (new
// optional fields) do not require a bump.
//
// 1.0.0 — v2.0 normalisation pass. Two field renames against the v0.5.0
// baseline that shipped during v1.x: TLSAuditCertJSON.chain_len → chain_count
// (alignment with full-check's HTTPS.chain_count), and IPInfoJSON
// resolve_took_ms → resolve_ms (alignment with the rest of the *_ms
// timing-suffix convention). Both are breaking for v1.x JSON consumers.
// The major bump signals the discontinuity; STABILITY.md describes the
// v2.x freeze contract.
const SchemaVersion = "1.0.0"

// FullJSON is the JSON representation of a full-check Report.
type FullJSON struct {
	NetcheckVersion string     `json:"netcheck_version"`
	Kind            string     `json:"kind"` // "full"
	StartedAt       time.Time  `json:"started_at"`
	Target          TargetJSON `json:"target"`
	DNS             DNSJSON    `json:"dns"`
	TCPv4           *TCPJSON   `json:"tcp_v4,omitempty"`
	TCPv6           *TCPJSON   `json:"tcp_v6,omitempty"`
	TLS             *TLSJSON   `json:"tls,omitempty"`
	HTTP            HTTPJSON   `json:"http"`
	OK              bool       `json:"ok"`
}

// TargetJSON describes the input target as parsed.
type TargetJSON struct {
	Raw    string `json:"raw"`
	Host   string `json:"host"`
	Port   string `json:"port"`
	Scheme string `json:"scheme"`
}

// DNSJSON is a single DNS lookup result.
type DNSJSON struct {
	TookMS int64                    `json:"took_ms"`
	A      []string                 `json:"a"`
	AAAA   []string                 `json:"aaaa"`
	IPInfo map[string]DNSIPInfoJSON `json:"ip_info,omitempty"`
	Error  string                   `json:"error,omitempty"`
}

// DNSIPInfoJSON is the per-IP enrichment surfaced on the full check.
type DNSIPInfoJSON struct {
	ASN     *ASNJSON `json:"asn,omitempty"`
	Reverse []string `json:"reverse,omitempty"`
	CDN     *CDNJSON `json:"cdn,omitempty"`
}

// ASNJSON is the Team Cymru lookup result for an IP or hop.
type ASNJSON struct {
	ASN      string `json:"asn"` // "15169" (no AS prefix)
	Org      string `json:"org,omitempty"`
	Country  string `json:"country,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
	Registry string `json:"registry,omitempty"`
}

// CDNJSON is a CDN classification with confidence.
type CDNJSON struct {
	Provider   string `json:"provider"`
	Confidence string `json:"confidence,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// TCPJSON is the outcome of a TCP connect.
type TCPJSON struct {
	Addr   string `json:"addr"`
	TookMS int64  `json:"took_ms"`
	Error  string `json:"error,omitempty"`
}

// TLSJSON is the outcome of a TLS handshake.
type TLSJSON struct {
	Version       string    `json:"version"` // "TLS 1.3"
	CipherSuite   string    `json:"cipher_suite"`
	Issuer        string    `json:"issuer"`
	Subject       string    `json:"subject"`
	DNSNames      []string  `json:"dns_names,omitempty"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
	ChainCount    int       `json:"chain_count"`
	TookMS        int64     `json:"took_ms"`
	Error         string    `json:"error,omitempty"`
}

// HTTPJSON captures status, redirects, and httptrace timing.
type HTTPJSON struct {
	Status   int        `json:"status"`
	FinalURL string     `json:"final_url"`
	Hops     []HTTPHop  `json:"hops"`
	Server   string     `json:"server,omitempty"`
	Proto    string     `json:"proto,omitempty"`
	Timing   HTTPTiming `json:"timing"`
	Error    string     `json:"error,omitempty"`
}

// HTTPHop is one redirect step.
type HTTPHop struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
}

// HTTPTiming is the httptrace breakdown.
type HTTPTiming struct {
	DNSMS     int64 `json:"dns_ms"`
	ConnectMS int64 `json:"connect_ms"`
	TLSMS     int64 `json:"tls_ms,omitempty"`
	TTFBMS    int64 `json:"ttfb_ms"`
	TotalMS   int64 `json:"total_ms"`
}

// DNSCompareJSON is the JSON representation of a multi-resolver DNS compare run.
type DNSCompareJSON struct {
	NetcheckVersion string      `json:"netcheck_version"`
	Kind            string      `json:"kind"` // "dns"
	Host            string      `json:"host"`
	StartedAt       time.Time   `json:"started_at"`
	Queries         []QueryJSON `json:"queries"`
}

// QueryJSON is one record-type query across all resolvers.
type QueryJSON struct {
	QType   string         `json:"qtype"`
	Results []ResolverJSON `json:"results"`
	Verdict VerdictJSON    `json:"verdict"`
}

// ResolverJSON is one resolver's answer.
type ResolverJSON struct {
	Name    string   `json:"name"`
	Address string   `json:"address"`
	Records []string `json:"records,omitempty"`
	TookMS  int64    `json:"took_ms"`
	Error   string   `json:"error,omitempty"`
}

// VerdictJSON is the agree/disagree breakdown for a query.
type VerdictJSON struct {
	Agree  bool               `json:"agree"`
	Groups []VerdictGroupJSON `json:"groups"`
}

// VerdictGroupJSON is one distinct answer set and the resolvers that returned it.
type VerdictGroupJSON struct {
	Records   []string `json:"records"`
	Resolvers []string `json:"resolvers"`
}

// RouteJSON is the JSON representation of a traceroute run.
type RouteJSON struct {
	NetcheckVersion string    `json:"netcheck_version"`
	Kind            string    `json:"kind"` // "route"
	Host            string    `json:"host"`
	DestIP          string    `json:"dest_ip,omitempty"`
	Tool            string    `json:"tool"`
	ToolArgs        []string  `json:"tool_args"`
	StartedAt       time.Time `json:"started_at"`
	Hops            []HopJSON `json:"hops"`
	Reached         bool      `json:"reached"`
	Timeouts        int       `json:"timeouts"`
}

// HopJSON is one row of traceroute output.
type HopJSON struct {
	N       int         `json:"n"`
	Timeout bool        `json:"timeout"`
	Probes  []ProbeJSON `json:"probes,omitempty"`
	IPs     []string    `json:"ips,omitempty"`
	ASN     *ASNJSON    `json:"asn,omitempty"`
}

// ProbeJSON is one probe within a hop.
type ProbeJSON struct {
	Host  string  `json:"host,omitempty"`
	IP    string  `json:"ip,omitempty"`
	RTTMS float64 `json:"rtt_ms"`
}

// IPInfoJSON is the JSON representation of a `netcheck ip` run.
type IPInfoJSON struct {
	NetcheckVersion string          `json:"netcheck_version"`
	Kind            string          `json:"kind"` // "ip"
	Target          string          `json:"target"`
	StartedAt       time.Time       `json:"started_at"`
	FromHost        bool            `json:"from_host"`
	ResolveMS       int64           `json:"resolve_ms,omitempty"`
	Details         []IPDetailsJSON `json:"details"`
}

// IPDetailsJSON is the full enrichment for one IP.
type IPDetailsJSON struct {
	IP      string    `json:"ip"`
	Reverse []string  `json:"reverse,omitempty"`
	ASN     *ASNJSON  `json:"asn,omitempty"`
	RDAP    *RDAPJSON `json:"rdap,omitempty"`
	CDN     *CDNJSON  `json:"cdn,omitempty"`
}

// RDAPJSON is the subset of RDAP we surface.
type RDAPJSON struct {
	Name       string `json:"name,omitempty"`
	Registry   string `json:"registry,omitempty"`
	Country    string `json:"country,omitempty"`
	AbuseEmail string `json:"abuse_email,omitempty"`
}

// HeadersJSON is the JSON representation of a `netcheck headers` audit.
type HeadersJSON struct {
	NetcheckVersion string             `json:"netcheck_version"`
	Kind            string             `json:"kind"` // "headers"
	URL             string             `json:"url"`
	FinalURL        string             `json:"final_url,omitempty"`
	Status          int                `json:"status,omitempty"`
	StartedAt       time.Time          `json:"started_at"`
	TookMS          int64              `json:"took_ms"`
	Findings        []FindingJSON      `json:"findings,omitempty"`
	Summary         HeadersSummaryJSON `json:"summary"`
	Error           string             `json:"error,omitempty"`
}

// FindingJSON is the per-header verdict.
type FindingJSON struct {
	Name    string `json:"name"`
	Value   string `json:"value,omitempty"`
	Grade   string `json:"grade"` // "pass" | "weak" | "missing" | "info"
	Comment string `json:"comment,omitempty"`
}

// HeadersSummaryJSON is a quick count of findings by grade.
type HeadersSummaryJSON struct {
	Pass    int `json:"pass"`
	Weak    int `json:"weak"`
	Missing int `json:"missing"`
	Info    int `json:"info"`
}

// TechJSON is the JSON representation of a `netcheck tech` fingerprint run.
type TechJSON struct {
	NetcheckVersion string      `json:"netcheck_version"`
	Kind            string      `json:"kind"` // "tech"
	URL             string      `json:"url"`
	FinalURL        string      `json:"final_url,omitempty"`
	Status          int         `json:"status,omitempty"`
	StartedAt       time.Time   `json:"started_at"`
	TookMS          int64       `json:"took_ms"`
	Matches         []TechMatch `json:"matches,omitempty"`
	Error           string      `json:"error,omitempty"`
}

// TechMatch is one detected technology.
type TechMatch struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Version    string `json:"version,omitempty"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence,omitempty"`
}

// SubsJSON is the JSON representation of a `netcheck subs` enumeration.
type SubsJSON struct {
	NetcheckVersion string            `json:"netcheck_version"`
	Kind            string            `json:"kind"` // "subs"
	Domain          string            `json:"domain"`
	StartedAt       time.Time         `json:"started_at"`
	TookMS          int64             `json:"took_ms"`
	Subdomains      []SubdomainJSON   `json:"subdomains,omitempty"`
	SourceErrors    map[string]string `json:"source_errors,omitempty"`
	Error           string            `json:"error,omitempty"`
}

// SubdomainJSON is one finding plus which sources reported it.
type SubdomainJSON struct {
	Name     string   `json:"name"`
	Wildcard bool     `json:"wildcard,omitempty"`
	Sources  []string `json:"sources"`
}

// ReverseJSON is the JSON representation of a `netcheck reverse` lookup.
type ReverseJSON struct {
	NetcheckVersion string            `json:"netcheck_version"`
	Kind            string            `json:"kind"` // "reverse"
	IP              string            `json:"ip"`
	StartedAt       time.Time         `json:"started_at"`
	TookMS          int64             `json:"took_ms"`
	Hostnames       []HostnameJSON    `json:"hostnames,omitempty"`
	SourceErrors    map[string]string `json:"source_errors,omitempty"`
	SourceDisabled  []string          `json:"source_disabled,omitempty"`
	Error           string            `json:"error,omitempty"`
}

// HostnameJSON is one reverse-IP hit plus the sources that reported it.
type HostnameJSON struct {
	Name    string   `json:"name"`
	Sources []string `json:"sources"`
}

// ArchJSON is the JSON representation of a `netcheck arch` Wayback lookup.
type ArchJSON struct {
	NetcheckVersion string         `json:"netcheck_version"`
	Kind            string         `json:"kind"` // "arch"
	Domain          string         `json:"domain"`
	StartedAt       time.Time      `json:"started_at"`
	TookMS          int64          `json:"took_ms"`
	Total           int            `json:"total"`
	UniqueURLs      int            `json:"unique_urls"`
	First           *time.Time     `json:"first,omitempty"`
	Last            *time.Time     `json:"last,omitempty"`
	RecentSamples   []SnapshotJSON `json:"recent_samples,omitempty"`
	Error           string         `json:"error,omitempty"`
}

// SnapshotJSON is one indexed capture from the Wayback CDX.
type SnapshotJSON struct {
	Timestamp time.Time `json:"timestamp"`
	URL       string    `json:"url"`
	Status    int       `json:"status,omitempty"`
}

// TLSAuditJSON is the JSON representation of a `netcheck tls` audit.
type TLSAuditJSON struct {
	NetcheckVersion string                `json:"netcheck_version"`
	Kind            string                `json:"kind"` // "tls-audit"
	Host            string                `json:"host"`
	Port            string                `json:"port"`
	StartedAt       time.Time             `json:"started_at"`
	TookMS          int64                 `json:"took_ms"`
	Protocols       []TLSProtocolJSON     `json:"protocols,omitempty"`
	Ciphers         []TLSCipherJSON       `json:"ciphers,omitempty"`
	Cert            *TLSCertJSON          `json:"cert,omitempty"`
	Findings        []TLSAuditFindingJSON `json:"findings,omitempty"`
	Error           string                `json:"error,omitempty"`
}

// TLSProtocolJSON is one TLS version probe result.
type TLSProtocolJSON struct {
	Name       string `json:"name"`
	Supported  bool   `json:"supported"`
	Deprecated bool   `json:"deprecated,omitempty"`
	Cipher     string `json:"cipher,omitempty"`
	Error      string `json:"error,omitempty"`
}

// TLSCipherJSON is one cipher-suite probe result. Only supported=true rows
// are included in the JSON output to keep the file small.
type TLSCipherJSON struct {
	Name      string `json:"name"`
	Insecure  bool   `json:"insecure,omitempty"`
	Version   string `json:"version,omitempty"`
	Supported bool   `json:"supported"`
}

// TLSCertJSON describes the leaf certificate.
type TLSCertJSON struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	DNSNames      []string  `json:"dns_names,omitempty"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
	ChainCount    int       `json:"chain_count"`
	SelfSigned    bool      `json:"self_signed,omitempty"`
	Expired       bool      `json:"expired,omitempty"`
}

// TLSAuditFindingJSON is one high-level audit verdict.
type TLSAuditFindingJSON struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
}

// TakeoverJSON is the JSON representation of a `netcheck takeover` check.
type TakeoverJSON struct {
	NetcheckVersion string                `json:"netcheck_version"`
	Kind            string                `json:"kind"` // "takeover"
	Domain          string                `json:"domain"`
	HasCNAME        bool                  `json:"has_cname"`
	StartedAt       time.Time             `json:"started_at"`
	TookMS          int64                 `json:"took_ms"`
	Findings        []TakeoverFindingJSON `json:"findings,omitempty"`
	Error           string                `json:"error,omitempty"`
}

// TakeoverFindingJSON is one verdict on one CNAME chain.
type TakeoverFindingJSON struct {
	CNAME    string `json:"cname"`
	Provider string `json:"provider,omitempty"`
	Verdict  string `json:"verdict"` // vulnerable | unverifiable | safe | unknown
	Status   int    `json:"status,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Notes    string `json:"notes,omitempty"`
}

// PortScanJSON is the JSON representation of a `netcheck ports` scan.
type PortScanJSON struct {
	NetcheckVersion string        `json:"netcheck_version"`
	Kind            string        `json:"kind"` // "ports"
	Host            string        `json:"host"`
	IP              string        `json:"ip,omitempty"`
	StartedAt       time.Time     `json:"started_at"`
	TookMS          int64         `json:"took_ms"`
	Ports           []PortJSON    `json:"ports,omitempty"` // open ports only
	Stats           PortStatsJSON `json:"stats"`
	Error           string        `json:"error,omitempty"`
}

// PortJSON is one open port.
type PortJSON struct {
	Port    int    `json:"port"`
	Service string `json:"service,omitempty"`
	// Proto is "tcp" or "udp". Added in 2.1 (R-13) as additive optional —
	// omitted on TCP-only scans for back-compat with pre-2.1 consumers.
	Proto string `json:"proto,omitempty"`
	// State is the open-state classification. "open" for TCP and definite
	// UDP responses, "open|filtered" for UDP ports where we couldn't tell
	// without raw-socket ICMP access. Omitted (defaults to "open") on
	// pure-TCP scans for back-compat.
	State string `json:"state,omitempty"`
	// Banner is the best-effort fingerprint string from a short read on
	// connect (or a minimal GET probe on known HTTP ports). May be empty.
	// Stable field — added in 1.8.0 as an additive optional.
	Banner string `json:"banner,omitempty"`
}

// PortStatsJSON summarises the scan.
type PortStatsJSON struct {
	Total    int `json:"total"`
	Open     int `json:"open"`
	Closed   int `json:"closed"`
	Filtered int `json:"filtered"`
	// OpenFiltered counts UDP ports with no response — open or filtered,
	// ambiguous without raw-socket access. Added in 2.1 (R-13) as
	// additive optional. Always 0 on TCP-only scans.
	OpenFiltered int `json:"open_filtered,omitempty"`
}

// PathEnumJSON is the JSON representation of a `netcheck enum` run.
type PathEnumJSON struct {
	NetcheckVersion string            `json:"netcheck_version"`
	Kind            string            `json:"kind"` // "enum"
	BaseURL         string            `json:"base_url"`
	StartedAt       time.Time         `json:"started_at"`
	TookMS          int64             `json:"took_ms"`
	Findings        []PathFindingJSON `json:"findings,omitempty"`
	Stats           PathStatsJSON     `json:"stats"`
	Error           string            `json:"error,omitempty"`
}

// PathFindingJSON is one interesting HTTP response.
type PathFindingJSON struct {
	Path     string `json:"path"`
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Length   int64  `json:"length,omitempty"`
	Redirect string `json:"redirect,omitempty"`
	Category string `json:"category"` // found | redirect | blocked | auth-required | server-error
}

// PathStatsJSON summarises the run.
type PathStatsJSON struct {
	Total       int `json:"total"`
	Interesting int `json:"interesting"`
	NotFound    int `json:"not_found"`
	Errors      int `json:"errors"`
}

// AuditJSON is the JSON representation of a `netcheck audit` run — one
// envelope embedding every sub-report that ran. Missing sub-reports stay
// nil. Per-sub-command failures are captured in Errors so the audit doesn't
// fail wholesale because one source was down.
type AuditJSON struct {
	NetcheckVersion string            `json:"netcheck_version"`
	Kind            string            `json:"kind"` // "audit"
	Target          string            `json:"target"`
	Host            string            `json:"host,omitempty"`
	StartedAt       time.Time         `json:"started_at"`
	TookMS          int64             `json:"took_ms"`
	Active          bool              `json:"active"`
	IP              *IPInfoJSON       `json:"ip,omitempty"`
	Reverse         *ReverseJSON      `json:"reverse,omitempty"`
	Subs            *SubsJSON         `json:"subs,omitempty"`
	Arch            *ArchJSON         `json:"arch,omitempty"`
	Headers         *HeadersJSON      `json:"headers,omitempty"`
	Tech            *TechJSON         `json:"tech,omitempty"`
	TLS             *TLSAuditJSON     `json:"tls,omitempty"`
	Takeover        *TakeoverJSON     `json:"takeover,omitempty"`
	Ports           *PortScanJSON     `json:"ports,omitempty"`
	Enum            *PathEnumJSON     `json:"enum,omitempty"`
	Errors          map[string]string `json:"errors,omitempty"` // per-sub-command failures
	Error           string            `json:"error,omitempty"`  // top-level error (bad target etc.)
}

// ---------------------------------------------------------------------------
// Conversion: internal types → JSON schema types
// ---------------------------------------------------------------------------

// ToFullJSON projects a Report into the wire-stable FullJSON schema.
func ToFullJSON(r *Report) FullJSON {
	out := FullJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "full",
		StartedAt:       r.StartedAt,
		Target:          targetToJSON(r.Target),
		DNS:             dnsToJSON(r.DNS),
		HTTP:            httpToJSON(r.HTTP),
		OK:              r.OK(),
	}
	if r.TCPv4 != nil {
		j := tcpToJSON(*r.TCPv4)
		out.TCPv4 = &j
	}
	if r.TCPv6 != nil {
		j := tcpToJSON(*r.TCPv6)
		out.TCPv6 = &j
	}
	if r.TLS != nil {
		j := tlsToJSON(*r.TLS)
		out.TLS = &j
	}
	return out
}

// ToDNSCompareJSON projects one or more dnscompare.Result rows for the same
// host into a single DNSCompareJSON envelope.
func ToDNSCompareJSON(host string, startedAt time.Time, results []dnscompare.Result) DNSCompareJSON {
	out := DNSCompareJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "dns",
		Host:            host,
		StartedAt:       startedAt,
	}
	for _, q := range results {
		out.Queries = append(out.Queries, queryToJSON(q))
	}
	return out
}

// ToRouteJSON projects a list of collected hops + run metadata into RouteJSON.
func ToRouteJSON(host, destIP, tool string, toolArgs []string, startedAt time.Time, hops []*route.Hop, asnC *ipinfo.ASNCache) RouteJSON {
	out := RouteJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "route",
		Host:            host,
		DestIP:          destIP,
		Tool:            tool,
		ToolArgs:        toolArgs,
		StartedAt:       startedAt,
	}
	for _, h := range hops {
		out.Hops = append(out.Hops, hopToJSON(h, asnC))
		if h.Timeout {
			out.Timeouts++
		}
		if !h.Timeout && destIP != "" {
			for _, ip := range h.IPs() {
				if ip == destIP {
					out.Reached = true
				}
			}
		}
	}
	return out
}

// ToIPInfoJSON projects an IP info run into IPInfoJSON.
func ToIPInfoJSON(target string, startedAt time.Time, fromHost bool, resolveTook time.Duration, details []ipinfo.IPDetails) IPInfoJSON {
	out := IPInfoJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "ip",
		Target:          target,
		StartedAt:       startedAt,
		FromHost:        fromHost,
	}
	if fromHost {
		out.ResolveMS = resolveTook.Milliseconds()
	}
	for _, d := range details {
		out.Details = append(out.Details, ipDetailsToJSON(d))
	}
	return out
}

// ToHeadersJSON projects a secheaders.Result into HeadersJSON.
func ToHeadersJSON(r secheaders.Result) HeadersJSON {
	out := HeadersJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "headers",
		URL:             r.URL,
		FinalURL:        r.FinalURL,
		Status:          r.Status,
		StartedAt:       r.StartedAt,
		TookMS:          r.Took.Milliseconds(),
	}
	if r.Err != nil {
		out.Error = r.Err.Error()
		return out
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, FindingJSON{
			Name:    f.Name,
			Value:   f.Value,
			Grade:   string(f.Grade),
			Comment: f.Comment,
		})
	}
	p, w, m, i := r.Summary()
	out.Summary = HeadersSummaryJSON{Pass: p, Weak: w, Missing: m, Info: i}
	return out
}

// ToTechJSON projects a techdetect.Result into TechJSON.
func ToTechJSON(r techdetect.Result) TechJSON {
	out := TechJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "tech",
		URL:             r.URL,
		FinalURL:        r.FinalURL,
		Status:          r.Status,
		StartedAt:       r.StartedAt,
		TookMS:          r.Took.Milliseconds(),
	}
	if r.Err != nil {
		out.Error = r.Err.Error()
		return out
	}
	for _, m := range r.Matches {
		out.Matches = append(out.Matches, TechMatch{
			Name:       m.Name,
			Category:   string(m.Category),
			Version:    m.Version,
			Confidence: m.Confidence,
			Evidence:   m.Evidence,
		})
	}
	return out
}

// ToSubsJSON projects a subenum.Result into SubsJSON.
func ToSubsJSON(r subenum.Result) SubsJSON {
	out := SubsJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "subs",
		Domain:          r.Domain,
		StartedAt:       r.StartedAt,
		TookMS:          r.Took.Milliseconds(),
	}
	if r.Err != nil {
		out.Error = r.Err.Error()
		return out
	}
	for _, s := range r.Subdomains {
		out.Subdomains = append(out.Subdomains, SubdomainJSON{
			Name:     s.Name,
			Wildcard: s.Wildcard,
			Sources:  s.Sources,
		})
	}
	if len(r.SourceErrors) > 0 {
		out.SourceErrors = r.SourceErrors
	}
	return out
}

// ToReverseJSON projects a reverseip.Result into ReverseJSON.
func ToReverseJSON(r reverseip.Result) ReverseJSON {
	out := ReverseJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "reverse",
		IP:              r.IP,
		StartedAt:       r.StartedAt,
		TookMS:          r.Took.Milliseconds(),
	}
	if r.Err != nil {
		out.Error = r.Err.Error()
		return out
	}
	for _, h := range r.Hostnames {
		out.Hostnames = append(out.Hostnames, HostnameJSON{
			Name:    h.Name,
			Sources: h.Sources,
		})
	}
	if len(r.SourceErrors) > 0 {
		out.SourceErrors = r.SourceErrors
	}
	if len(r.SourceDisabled) > 0 {
		out.SourceDisabled = r.SourceDisabled
	}
	return out
}

// ToArchJSON projects a wayback.Result into ArchJSON.
func ToArchJSON(r wayback.Result) ArchJSON {
	out := ArchJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "arch",
		Domain:          r.Domain,
		StartedAt:       r.StartedAt,
		TookMS:          r.Took.Milliseconds(),
		Total:           r.Total,
		UniqueURLs:      r.UniqueURLs,
	}
	if r.Err != nil {
		out.Error = r.Err.Error()
		return out
	}
	if !r.First.IsZero() {
		f := r.First
		out.First = &f
	}
	if !r.Last.IsZero() {
		l := r.Last
		out.Last = &l
	}
	for _, s := range r.RecentSamples {
		out.RecentSamples = append(out.RecentSamples, SnapshotJSON{
			Timestamp: s.Timestamp,
			URL:       s.URL,
			Status:    s.Status,
		})
	}
	return out
}

// ToTLSAuditJSON projects a tlsaudit.Result into TLSAuditJSON. Only supported
// cipher suites are included in the JSON output — the not-supported list is
// large and noisy.
func ToTLSAuditJSON(r tlsaudit.Result) TLSAuditJSON {
	out := TLSAuditJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "tls-audit",
		Host:            r.Host,
		Port:            r.Port,
		StartedAt:       r.StartedAt,
		TookMS:          r.Took.Milliseconds(),
	}
	if r.Err != nil {
		out.Error = r.Err.Error()
		return out
	}
	for _, p := range r.Protocols {
		out.Protocols = append(out.Protocols, TLSProtocolJSON{
			Name:       p.Name,
			Supported:  p.Supported,
			Deprecated: p.Deprecated,
			Cipher:     p.Cipher,
			Error:      p.Error,
		})
	}
	for _, c := range r.Ciphers {
		if !c.Supported {
			continue
		}
		out.Ciphers = append(out.Ciphers, TLSCipherJSON{
			Name:      c.Name,
			Insecure:  c.Insecure,
			Version:   c.Version,
			Supported: c.Supported,
		})
	}
	if r.Cert != nil {
		out.Cert = &TLSCertJSON{
			Subject:       r.Cert.Subject,
			Issuer:        r.Cert.Issuer,
			DNSNames:      r.Cert.DNSNames,
			NotBefore:     r.Cert.NotBefore,
			NotAfter:      r.Cert.NotAfter,
			DaysRemaining: r.Cert.DaysRemaining,
			ChainCount:    r.Cert.ChainLen,
			SelfSigned:    r.Cert.SelfSigned,
			Expired:       r.Cert.Expired,
		}
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, TLSAuditFindingJSON{
			Severity: f.Severity,
			Title:    f.Title,
			Detail:   f.Detail,
		})
	}
	return out
}

// ToTakeoverJSON projects a takeover.Result into TakeoverJSON.
func ToTakeoverJSON(r takeover.Result) TakeoverJSON {
	out := TakeoverJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "takeover",
		Domain:          r.Domain,
		HasCNAME:        r.HasCNAME,
		StartedAt:       r.StartedAt,
		TookMS:          r.Took.Milliseconds(),
	}
	if r.Err != nil {
		out.Error = r.Err.Error()
		return out
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, TakeoverFindingJSON{
			CNAME:    f.CNAME,
			Provider: f.Provider,
			Verdict:  string(f.Verdict),
			Status:   f.Status,
			Detail:   f.Detail,
			Notes:    f.Notes,
		})
	}
	return out
}

// ToPortScanJSON projects a portscan.Result into PortScanJSON.
func ToPortScanJSON(r portscan.Result) PortScanJSON {
	out := PortScanJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "ports",
		Host:            r.Host,
		IP:              r.IP,
		StartedAt:       r.StartedAt,
		TookMS:          r.Took.Milliseconds(),
		Stats: PortStatsJSON{
			Total:        r.Stats.Total,
			Open:         r.Stats.Open,
			Closed:       r.Stats.Closed,
			Filtered:     r.Stats.Filtered,
			OpenFiltered: r.Stats.OpenFiltered,
		},
	}
	if r.Err != nil {
		out.Error = r.Err.Error()
		return out
	}
	// Detect whether any UDP results are present. If the scan was TCP-only
	// (the pre-R-13 case), omit Proto/State so the JSON output is byte-
	// identical to old consumers.
	hasUDP := false
	for _, p := range r.Ports {
		if p.Proto == "udp" {
			hasUDP = true
			break
		}
	}
	for _, p := range r.Ports {
		pj := PortJSON{Port: p.Port, Service: p.Service, Banner: p.Banner}
		if hasUDP {
			pj.Proto = p.Proto
			if pj.Proto == "" {
				pj.Proto = "tcp"
			}
			pj.State = p.State
			if pj.State == "" {
				pj.State = "open"
			}
		}
		out.Ports = append(out.Ports, pj)
	}
	return out
}

// ToPathEnumJSON projects a pathenum.Result into PathEnumJSON.
func ToPathEnumJSON(r pathenum.Result) PathEnumJSON {
	out := PathEnumJSON{
		NetcheckVersion: SchemaVersion,
		Kind:            "enum",
		BaseURL:         r.BaseURL,
		StartedAt:       r.StartedAt,
		TookMS:          r.Took.Milliseconds(),
		Stats: PathStatsJSON{
			Total:       r.Stats.Total,
			Interesting: r.Stats.Interesting,
			NotFound:    r.Stats.NotFound,
			Errors:      r.Stats.Errors,
		},
	}
	if r.Err != nil {
		out.Error = r.Err.Error()
		return out
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, PathFindingJSON{
			Path:     f.Path,
			URL:      f.URL,
			Status:   f.Status,
			Length:   f.Length,
			Redirect: f.Redirect,
			Category: f.Category,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Internal projections
// ---------------------------------------------------------------------------

func targetToJSON(t *target.Target) TargetJSON {
	if t == nil {
		return TargetJSON{}
	}
	return TargetJSON{
		Raw:    t.Raw,
		Host:   t.Host,
		Port:   t.Port,
		Scheme: t.Scheme,
	}
}

func dnsToJSON(d check.DNSResult) DNSJSON {
	out := DNSJSON{
		TookMS: d.Took.Milliseconds(),
		A:      ipsToStrings(d.A),
		AAAA:   ipsToStrings(d.AAAA),
	}
	if d.Err != nil {
		out.Error = d.Err.Error()
	}
	if len(d.IPInfo) > 0 {
		out.IPInfo = make(map[string]DNSIPInfoJSON, len(d.IPInfo))
		for k, v := range d.IPInfo {
			out.IPInfo[k] = dnsIPInfoToJSON(v)
		}
	}
	return out
}

func dnsIPInfoToJSON(v ipinfo.DNSIPInfo) DNSIPInfoJSON {
	return DNSIPInfoJSON{
		ASN:     asnToJSON(v.ASN),
		Reverse: v.Reverse,
		CDN:     cdnToJSON(v.CDN),
	}
}

func asnToJSON(a *ipinfo.ASNInfo) *ASNJSON {
	if a == nil || a.ASN == "" {
		return nil
	}
	return &ASNJSON{
		ASN:      ipinfo.NormalizeASN(a.ASN),
		Org:      ipinfo.CleanASNOrg(a.Org),
		Country:  a.Country,
		Prefix:   a.Prefix,
		Registry: a.Registry,
	}
}

func cdnToJSON(c ipinfo.CDNMatch) *CDNJSON {
	if c.Provider == "" {
		return nil
	}
	return &CDNJSON{
		Provider:   c.Provider,
		Confidence: c.Confidence,
		Reason:     c.Reason,
	}
}

func rdapToJSON(r *ipinfo.RDAPInfo) *RDAPJSON {
	if r == nil {
		return nil
	}
	return &RDAPJSON{
		Name:       r.Name,
		Registry:   r.Registry,
		Country:    r.Country,
		AbuseEmail: r.AbuseEmail,
	}
}

func tcpToJSON(r check.TCPResult) TCPJSON {
	out := TCPJSON{Addr: r.Addr, TookMS: r.Took.Milliseconds()}
	if r.Err != nil {
		out.Error = r.Err.Error()
	}
	return out
}

func tlsToJSON(r check.TLSResult) TLSJSON {
	out := TLSJSON{TookMS: r.Took.Milliseconds()}
	if r.Err != nil {
		out.Error = r.Err.Error()
		return out
	}
	out.Version = tlsVersionName(r.Version)
	out.CipherSuite = tls.CipherSuiteName(r.CipherSuite)
	out.Issuer = r.Issuer
	out.Subject = r.Subject
	out.DNSNames = r.DNSNames
	out.NotBefore = r.NotBefore
	out.NotAfter = r.NotAfter
	out.DaysRemaining = daysRemaining(r.NotAfter)
	out.ChainCount = len(r.Chain)
	return out
}

func httpToJSON(r check.HTTPResult) HTTPJSON {
	out := HTTPJSON{
		Status:   r.Status,
		FinalURL: r.FinalURL,
		Server:   r.Server,
		Proto:    r.Proto,
		Timing: HTTPTiming{
			DNSMS:     r.DNSTime.Milliseconds(),
			ConnectMS: r.ConnectTime.Milliseconds(),
			TLSMS:     r.TLSTime.Milliseconds(),
			TTFBMS:    r.TTFB.Milliseconds(),
			TotalMS:   r.Total.Milliseconds(),
		},
	}
	if r.Err != nil {
		out.Error = r.Err.Error()
	}
	for _, h := range r.Hops {
		out.Hops = append(out.Hops, HTTPHop{URL: h.URL, Status: h.Status})
	}
	return out
}

func queryToJSON(q dnscompare.Result) QueryJSON {
	out := QueryJSON{QType: q.QType}
	for _, r := range q.Results {
		rj := ResolverJSON{
			Name:    r.Resolver.Name,
			Address: r.Resolver.Address,
			Records: r.Records,
			TookMS:  r.Took.Milliseconds(),
		}
		if r.Err != nil {
			rj.Error = r.Err.Error()
		}
		out.Results = append(out.Results, rj)
	}
	v := q.Verdict()
	out.Verdict.Agree = v.Agree
	for _, g := range v.Groups {
		out.Verdict.Groups = append(out.Verdict.Groups, VerdictGroupJSON{
			Records:   g.Records,
			Resolvers: g.Resolvers,
		})
	}
	return out
}

func hopToJSON(h *route.Hop, asnC *ipinfo.ASNCache) HopJSON {
	out := HopJSON{N: h.N, Timeout: h.Timeout}
	for _, p := range h.Probes {
		out.Probes = append(out.Probes, ProbeJSON{
			Host:  p.Host,
			IP:    p.IP,
			RTTMS: float64(p.RTT) / float64(time.Millisecond),
		})
	}
	out.IPs = h.IPs()
	if asnC != nil && len(out.IPs) > 0 {
		if info := asnC.Lookup(context.Background(), out.IPs[0]); info != nil {
			out.ASN = asnToJSON(info)
		}
	}
	return out
}

func ipDetailsToJSON(d ipinfo.IPDetails) IPDetailsJSON {
	return IPDetailsJSON{
		IP:      d.IP.String(),
		Reverse: d.Reverse,
		ASN:     asnToJSON(d.ASN),
		RDAP:    rdapToJSON(d.RDAP),
		CDN:     cdnToJSON(d.CDN),
	}
}

func ipsToStrings(ips []net.IP) []string {
	if len(ips) == 0 {
		return nil
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
