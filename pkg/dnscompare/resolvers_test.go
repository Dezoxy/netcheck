package dnscompare

import "testing"

func TestParseResolver(t *testing.T) {
	cases := []struct {
		in       string
		wantType ResolverType
		wantAddr string
		wantErr  bool
	}{
		{"1.1.1.1", TypeUDP, "1.1.1.1:53", false},
		{"1.1.1.1:53", TypeUDP, "1.1.1.1:53", false},
		{"8.8.4.4:5353", TypeUDP, "8.8.4.4:5353", false},
		{"udp://9.9.9.9", TypeUDP, "9.9.9.9:53", false},
		{"tcp://1.1.1.1", TypeTCP, "1.1.1.1:53", false},
		{"tls://1.1.1.1", TypeDoT, "1.1.1.1:853", false},
		{"dot://9.9.9.9", TypeDoT, "9.9.9.9:853", false},
		{"tls://1.1.1.1:853", TypeDoT, "1.1.1.1:853", false},
		{"https://cloudflare-dns.com/dns-query", TypeDoH, "https://cloudflare-dns.com/dns-query", false},
		{"doh://cloudflare-dns.com/dns-query", TypeDoH, "https://cloudflare-dns.com/dns-query", false},
		{"ftp://nope", "", "", true},
		{"", "", "", true},
	}
	for _, c := range cases {
		got, err := ParseResolver(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseResolver(%q) want error, got %+v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseResolver(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got.Type != c.wantType {
			t.Errorf("ParseResolver(%q).Type = %q, want %q", c.in, got.Type, c.wantType)
		}
		if got.Address != c.wantAddr {
			t.Errorf("ParseResolver(%q).Address = %q, want %q", c.in, got.Address, c.wantAddr)
		}
	}
}
