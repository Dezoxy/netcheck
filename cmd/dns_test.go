package cmd

import (
	"testing"

	"netcheck/internal/config"
	"netcheck/internal/dnscompare"
)

func TestConfigResolverToDNS(t *testing.T) {
	cases := []struct {
		name    string
		in      config.ResolverEntry
		want    dnscompare.Resolver
		wantErr bool
	}{
		{
			name: "udp by default when type omitted",
			in:   config.ResolverEntry{Name: "cf", Address: "1.1.1.1"},
			want: dnscompare.Resolver{Name: "cf", Address: "1.1.1.1:53", Type: dnscompare.TypeUDP},
		},
		{
			name: "tcp",
			in:   config.ResolverEntry{Name: "cf-tcp", Address: "1.1.1.1", Type: "tcp"},
			want: dnscompare.Resolver{Name: "cf-tcp", Address: "1.1.1.1:53", Type: dnscompare.TypeTCP},
		},
		{
			name: "dot defaults to port 853",
			in:   config.ResolverEntry{Name: "cf-dot", Address: "1.1.1.1", Type: "dot"},
			want: dnscompare.Resolver{Name: "cf-dot", Address: "1.1.1.1:853", Type: dnscompare.TypeDoT},
		},
		{
			name: "dot keeps explicit port",
			in:   config.ResolverEntry{Address: "1.1.1.1:9999", Type: "tls"},
			want: dnscompare.Resolver{Name: "1.1.1.1:9999", Address: "1.1.1.1:9999", Type: dnscompare.TypeDoT},
		},
		{
			name: "doh with URL passes through",
			in:   config.ResolverEntry{Name: "cf-doh", Address: "https://cloudflare-dns.com/dns-query", Type: "doh"},
			want: dnscompare.Resolver{Name: "cf-doh", Address: "https://cloudflare-dns.com/dns-query", Type: dnscompare.TypeDoH},
		},
		{
			name: "doh with bare host rewrites to /dns-query",
			in:   config.ResolverEntry{Address: "dns.example.com", Type: "doh"},
			want: dnscompare.Resolver{Name: "dns.example.com", Address: "https://dns.example.com/dns-query", Type: dnscompare.TypeDoH},
		},
		{
			name:    "missing address is an error",
			in:      config.ResolverEntry{Name: "broken"},
			wantErr: true,
		},
		{
			name: "unknown type falls back to URL parser",
			in:   config.ResolverEntry{Address: "tls://1.1.1.1", Type: "??"},
			want: dnscompare.Resolver{Name: "tls://1.1.1.1", Address: "1.1.1.1:853", Type: dnscompare.TypeDoT},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := configResolverToDNS(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("got %+v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("got %+v\nwant %+v", got, c.want)
			}
		})
	}
}
