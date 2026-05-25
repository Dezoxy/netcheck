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
	// An unknown record type falls through to the default rr.String() path —
	// just verify it doesn't crash and returns something non-empty.
	hinfo := &dns.HINFO{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeHINFO}, Cpu: "x86", Os: "linux"}
	got := recordValue(hinfo)
	if !strings.Contains(got, "x86") {
		t.Errorf("HINFO fallback = %q, expected to contain 'x86'", got)
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
