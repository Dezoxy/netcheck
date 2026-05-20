package main

import (
	"context"
	"testing"
)

func TestResolveIPInputDirectIPv4(t *testing.T) {
	target, ips, fromHost, err := resolveIPInput(context.Background(), `"8.8.8.8"`)
	if err != nil {
		t.Fatal(err)
	}
	if fromHost {
		t.Fatal("fromHost = true, want false")
	}
	if target != "8.8.8.8" || len(ips) != 1 || ips[0].String() != "8.8.8.8" {
		t.Fatalf("target=%q ips=%v", target, ips)
	}
}

func TestResolveIPInputBracketedIPv6(t *testing.T) {
	target, ips, fromHost, err := resolveIPInput(context.Background(), "[2001:4860:4860::8888]:443")
	if err != nil {
		t.Fatal(err)
	}
	if fromHost {
		t.Fatal("fromHost = true, want false")
	}
	if target != "2001:4860:4860::8888" || len(ips) != 1 || ips[0].String() != "2001:4860:4860::8888" {
		t.Fatalf("target=%q ips=%v", target, ips)
	}
}

func TestFormatASNDetailsIncludesRDAPOrg(t *testing.T) {
	got := formatASNDetails(&ASNInfo{ASN: "15169", Org: "GOOGLE, US"}, &RDAPInfo{Name: "Google LLC"})
	want := "AS15169 GOOGLE (Google LLC)"
	if got != want {
		t.Fatalf("formatASNDetails = %q, want %q", got, want)
	}
}

func TestFormatASNDetailsTrimsCymruLegalSuffix(t *testing.T) {
	got := formatASNDetails(&ASNInfo{ASN: "13335", Org: "CLOUDFLARENET - Cloudflare, Inc., US"}, &RDAPInfo{Name: "Cloudflare, Inc."})
	want := "AS13335 CLOUDFLARENET (Cloudflare, Inc.)"
	if got != want {
		t.Fatalf("formatASNDetails = %q, want %q", got, want)
	}
}
