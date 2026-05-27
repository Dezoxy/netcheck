package dnscompare

import (
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// ─── ParseTypes ───────────────────────────────────────────────────────────

func TestParseTypes(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"A", []string{"A"}},
		{"A,AAAA", []string{"A", "AAAA"}},
		{"a,aaaa,mx", []string{"A", "AAAA", "MX"}},
		{" A , AAAA ", []string{"A", "AAAA"}}, // trimming + spaces
		{"A,A,AAAA", []string{"A", "AAAA"}},   // dedup, preserves order
		{"AAAA,A", []string{"AAAA", "A"}},     // order preserved
		// Tier 1 (default) — every entry must parse.
		{"CAA", []string{"CAA"}},
		{"A,AAAA,CNAME,NS,MX,TXT,SOA,CAA", []string{"A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "CAA"}},
		// Tier 2 (extended) sample.
		{"SRV,HTTPS,SVCB,PTR", []string{"SRV", "HTTPS", "SVCB", "PTR"}},
		// Tier 3 (DNSSEC) sample.
		{"DNSKEY,DS,RRSIG", []string{"DNSKEY", "DS", "RRSIG"}},
	}
	for _, c := range cases {
		got, err := ParseTypes(c.in)
		if err != nil {
			t.Fatalf("ParseTypes(%q) error: %v", c.in, err)
		}
		if len(got) != len(c.want) {
			t.Errorf("ParseTypes(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("ParseTypes(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestParseTypesErrors(t *testing.T) {
	for _, in := range []string{"", " ", ",,,", "FOO", "A,BAR"} {
		if _, err := ParseTypes(in); err == nil {
			t.Errorf("ParseTypes(%q) want error, got nil", in)
		}
	}
}

// ─── EnsurePort ───────────────────────────────────────────────────────────

func TestEnsurePort(t *testing.T) {
	cases := []struct {
		in, port, want string
	}{
		{"1.1.1.1", "53", "1.1.1.1:53"},
		{"1.1.1.1:53", "53", "1.1.1.1:53"},
		{"1.1.1.1:5353", "53", "1.1.1.1:5353"},
		{"::1", "53", "[::1]:53"},
		{"[::1]:53", "53", "[::1]:53"},
		{"2001:db8::1", "853", "[2001:db8::1]:853"},
		{"dns.example.com", "53", "dns.example.com:53"},
	}
	for _, c := range cases {
		if got := EnsurePort(c.in, c.port); got != c.want {
			t.Errorf("EnsurePort(%q, %q) = %q, want %q", c.in, c.port, got, c.want)
		}
	}
}

// ─── recordValue ──────────────────────────────────────────────────────────

func TestRecordValueAllTypes(t *testing.T) {
	cases := []struct {
		name string
		rr   dns.RR
		want string
	}{
		{
			name: "A",
			rr:   &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA}, A: net.IPv4(1, 2, 3, 4)},
			want: "1.2.3.4",
		},
		{
			name: "AAAA",
			rr:   &dns.AAAA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA}, AAAA: net.ParseIP("2606:4700::1")},
			want: "2606:4700::1",
		},
		{
			name: "CNAME strips trailing dot",
			rr:   &dns.CNAME{Hdr: dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME}, Target: "example.com."},
			want: "example.com",
		},
		{
			name: "MX",
			rr:   &dns.MX{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX}, Preference: 10, Mx: "mail.example.com."},
			want: "10 mail.example.com",
		},
		{
			name: "TXT joins multiple strings",
			rr:   &dns.TXT{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeTXT}, Txt: []string{"v=spf1 ", "include:_spf.example.com ~all"}},
			want: "v=spf1 include:_spf.example.com ~all",
		},
		{
			name: "NS",
			rr:   &dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS}, Ns: "ns1.example.net."},
			want: "ns1.example.net",
		},
		{
			name: "SOA",
			rr:   &dns.SOA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeSOA}, Ns: "ns.example.com.", Mbox: "admin.example.com.", Serial: 2026052100},
			want: "ns.example.com admin.example.com 2026052100",
		},
		{
			name: "CAA quoted value",
			rr:   &dns.CAA{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCAA}, Flag: 0, Tag: "issue", Value: "letsencrypt.org"},
			want: `0 issue "letsencrypt.org"`,
		},
		{
			name: "SRV",
			rr:   &dns.SRV{Hdr: dns.RR_Header{Name: "_sip._tcp.example.com.", Rrtype: dns.TypeSRV}, Priority: 10, Weight: 20, Port: 5060, Target: "sip.example.com."},
			want: "10 20 5060 sip.example.com",
		},
		{
			name: "PTR strips trailing dot",
			rr:   &dns.PTR{Hdr: dns.RR_Header{Name: "4.3.2.1.in-addr.arpa.", Rrtype: dns.TypePTR}, Ptr: "host.example.com."},
			want: "host.example.com",
		},
		{
			name: "DS",
			rr:   &dns.DS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDS}, KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "ABCDEF"},
			want: "12345 13 2 ABCDEF",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := recordValue(c.rr); got != c.want {
				t.Errorf("recordValue = %q, want %q", got, c.want)
			}
		})
	}
}

func TestRecordValueUnknownFallsThrough(t *testing.T) {
	// HINFO is in qtypeByName (queryable) but has no custom formatter —
	// verify it falls through to the rdata-only path without crashing.
	hinfo := &dns.HINFO{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHINFO}, Cpu: "x86", Os: "linux"}
	got := recordValue(hinfo)
	if !strings.Contains(got, "x86") {
		t.Errorf("HINFO fallback = %q, expected to contain 'x86'", got)
	}
}

// TestRecordValueFallbackIgnoresTTL guards the Codex P2 finding on PR #84:
// two RRs with identical RDATA but different TTLs (typical when comparing
// the same answer across resolvers with diverged cache state) must
// compare equal via recordValue, otherwise Verdict() reports false
// disagreement. Verified against unhandled types only — formatted ones
// already never include TTL.
func TestRecordValueFallbackIgnoresTTL(t *testing.T) {
	cases := []struct {
		name string
		mk   func(ttl uint32) dns.RR
	}{
		{
			name: "HINFO",
			mk: func(ttl uint32) dns.RR {
				return &dns.HINFO{
					Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHINFO, Class: dns.ClassINET, Ttl: ttl},
					Cpu: "x86", Os: "linux",
				}
			},
		},
		{
			name: "NAPTR",
			mk: func(ttl uint32) dns.RR {
				return &dns.NAPTR{
					Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNAPTR, Class: dns.ClassINET, Ttl: ttl},
					Order:       100,
					Preference:  10,
					Flags:       "S",
					Service:     "SIP+D2T",
					Regexp:      "",
					Replacement: "_sip._tcp.example.com.",
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lo := recordValue(c.mk(60))
			hi := recordValue(c.mk(3600))
			if lo != hi {
				t.Errorf("TTL drift leaked into recordValue: ttl=60 → %q, ttl=3600 → %q", lo, hi)
			}
			if lo == "" {
				t.Errorf("recordValue is empty — header strip ate the RDATA too")
			}
		})
	}
}

// TestScanTypeSetsParse confirms every type named in the canonical scan-type
// sets round-trips through ParseTypes. Catches typos that would otherwise
// only surface at runtime as "unsupported record type".
func TestScanTypeSetsParse(t *testing.T) {
	sets := map[string][]string{
		"DefaultScanTypes":  DefaultScanTypes,
		"ExtendedScanTypes": ExtendedScanTypes,
		"DNSSECTypes":       DNSSECTypes,
	}
	for name, set := range sets {
		got, err := ParseTypes(strings.Join(set, ","))
		if err != nil {
			t.Errorf("%s: ParseTypes error: %v", name, err)
			continue
		}
		if len(got) != len(set) {
			t.Errorf("%s: ParseTypes dedup changed length (set=%v got=%v)", name, set, got)
		}
	}
}

// TestScanTypeSetsDisjoint confirms the three tiers don't share members —
// the UI relies on this to render each record type in exactly one place.
func TestScanTypeSetsDisjoint(t *testing.T) {
	seen := map[string]string{}
	for tier, set := range map[string][]string{
		"DefaultScanTypes":  DefaultScanTypes,
		"ExtendedScanTypes": ExtendedScanTypes,
		"DNSSECTypes":       DNSSECTypes,
	} {
		for _, qt := range set {
			if other, dup := seen[qt]; dup {
				t.Errorf("%q appears in both %s and %s", qt, other, tier)
			}
			seen[qt] = tier
		}
	}
}

// ─── SystemResolvers ──────────────────────────────────────────────────────

func TestSystemResolversShape(t *testing.T) {
	// We don't assert /etc/resolv.conf exists (CI may not have it). Just
	// verify that whatever SystemResolvers returns is well-formed.
	got := SystemResolvers()
	for _, r := range got {
		if r.Name == "" {
			t.Errorf("resolver Name empty: %+v", r)
		}
		if r.Address == "" {
			t.Errorf("resolver Address empty: %+v", r)
		}
	}
}
