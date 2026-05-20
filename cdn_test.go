package main

import "testing"

func TestClassifyCDNASNAndPTR(t *testing.T) {
	got := classifyCDN(&ASNInfo{ASN: "15169"}, []string{"fra16s48-in-f14.1e100.net"})
	if got.Provider != "Google" {
		t.Fatalf("Provider = %q, want Google", got.Provider)
	}
	if got.Confidence != "high" {
		t.Fatalf("Confidence = %q, want high", got.Confidence)
	}
	if got.Reason != "ASN match + 1e100.net PTR" {
		t.Fatalf("Reason = %q", got.Reason)
	}
}

func TestClassifyCDNASNOnly(t *testing.T) {
	got := classifyCDN(&ASNInfo{ASN: "AS13335"}, nil)
	if got.Provider != "Cloudflare" {
		t.Fatalf("Provider = %q, want Cloudflare", got.Provider)
	}
	if got.Confidence != "medium" {
		t.Fatalf("Confidence = %q, want medium", got.Confidence)
	}
}

func TestClassifyCDNPTROnly(t *testing.T) {
	got := classifyCDN(nil, []string{"server-1-2-3-4.cloudfront.net."})
	if got.Provider != "AWS" {
		t.Fatalf("Provider = %q, want AWS", got.Provider)
	}
	if got.Reason != "cloudfront.net PTR" {
		t.Fatalf("Reason = %q", got.Reason)
	}
}
