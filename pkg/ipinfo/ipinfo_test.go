package ipinfo

import (
	"net"
	"testing"
)

func TestNormalizeIP(t *testing.T) {
	v4 := net.ParseIP("1.2.3.4")
	if got := NormalizeIP(v4); got.To4() == nil {
		t.Errorf("IPv4 lost its 4-byte form: %v", got)
	}
	v6 := net.ParseIP("2001:db8::1")
	if got := NormalizeIP(v6); len(got) != 16 {
		t.Errorf("IPv6 not 16 bytes: %v", got)
	}
	if NormalizeIP(nil) != nil {
		t.Errorf("NormalizeIP(nil) should be nil")
	}
}

func TestUniqueIPsDedupes(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("1.1.1.1"),
		net.ParseIP("1.1.1.1"), // dup
		net.ParseIP("2.2.2.2"),
		net.ParseIP("2606:4700::1"),
		nil, // skipped
	}
	got := UniqueIPs(ips)
	if len(got) != 3 {
		t.Fatalf("got %d unique, want 3: %v", len(got), got)
	}
	if got[0].String() != "1.1.1.1" || got[1].String() != "2.2.2.2" || got[2].String() != "2606:4700::1" {
		t.Errorf("order/contents wrong: %v", got)
	}
}

func TestCleanASNOrg(t *testing.T) {
	cases := map[string]string{
		"GOOGLE, US":                           "GOOGLE",
		"CLOUDFLARENET - Cloudflare, Inc., US": "CLOUDFLARENET",
		"AMAZON-02 - Amazon.com, Inc., US":     "AMAZON-02",
		"FACEBOOK":                             "FACEBOOK",
		"":                                     "",
		"   ":                                  "",
		"FOO, ZZ":                              "FOO",
	}
	for in, want := range cases {
		if got := CleanASNOrg(in); got != want {
			t.Errorf("CleanASNOrg(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalizeASN(t *testing.T) {
	cases := map[string]string{
		"15169":     "15169",
		"AS15169":   "15169",
		"as13335":   "13335",
		"  AS54113": "54113",
		"":          "",
	}
	for in, want := range cases {
		if got := NormalizeASN(in); got != want {
			t.Errorf("NormalizeASN(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsPrivateOrSpecial(t *testing.T) {
	cases := map[string]bool{
		"10.0.0.1":    true,
		"192.168.1.1": true,
		"172.16.5.4":  true,
		"127.0.0.1":   true,
		"169.254.0.1": true, // link-local
		"::1":         true, // loopback v6
		"fe80::1":     true, // link-local v6
		"0.0.0.0":     true, // unspecified
		"224.0.0.1":   true, // multicast

		"1.1.1.1":      false,
		"8.8.8.8":      false,
		"2606:4700::1": false,
		"142.250.0.1":  false,
	}
	for ipStr, want := range cases {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			t.Fatalf("bad test input: %q", ipStr)
		}
		if got := IsPrivateOrSpecial(ip); got != want {
			t.Errorf("IsPrivateOrSpecial(%q) = %v, want %v", ipStr, got, want)
		}
	}
}

func TestDNSInfoSuffix(t *testing.T) {
	if got := DNSInfoSuffix(nil); got != "" {
		t.Errorf("nil input = %q, want empty", got)
	}
	empty := &DNSIPInfo{}
	if got := DNSInfoSuffix(empty); got != "" {
		t.Errorf("empty input = %q, want empty", got)
	}
	full := &DNSIPInfo{
		ASN: &ASNInfo{ASN: "15169", Org: "GOOGLE, US"},
		CDN: CDNMatch{Provider: "Google"},
	}
	want := "  AS15169 GOOGLE (CDN: Google)"
	if got := DNSInfoSuffix(full); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCymruQueryName(t *testing.T) {
	got := cymruQueryName(net.ParseIP("8.8.8.8"))
	want := "8.8.8.8.origin.asn.cymru.com"
	if got != want {
		t.Errorf("IPv4: got %q, want %q", got, want)
	}

	// IPv6 nibble form for 2001:db8::1
	gotV6 := cymruQueryName(net.ParseIP("2001:db8::1"))
	if gotV6 == "" {
		t.Fatal("IPv6 cymru query returned empty")
	}
	// We don't pin the exact nibble string, but it must end with origin6.asn.cymru.com.
	if !endsWith(gotV6, ".origin6.asn.cymru.com") {
		t.Errorf("IPv6: %q doesn't end with .origin6.asn.cymru.com", gotV6)
	}
}

func endsWith(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}
