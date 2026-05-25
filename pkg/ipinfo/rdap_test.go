package ipinfo

import (
	"encoding/json"
	"testing"
)

func TestParseRDAPInfo(t *testing.T) {
	resp := &rdapIPResponse{
		Name:    "GOGL",
		Country: "US",
		Port43:  "whois.arin.net",
		Entities: []rdapEntity{
			{
				Roles: []string{"registrant"},
				VCardArray: json.RawMessage(`["vcard",[
					["version",{},"text","4.0"],
					["fn",{},"text","Google LLC"],
					["org",{},"text","Google LLC"]
				]]`),
			},
			{
				Roles: []string{"abuse"},
				VCardArray: json.RawMessage(`["vcard",[
					["version",{},"text","4.0"],
					["fn",{},"text","Abuse"],
					["email",{},"text","network-abuse@google.com"]
				]]`),
			},
		},
	}

	got := parseRDAPInfo(resp)
	if got == nil {
		t.Fatal("parseRDAPInfo returned nil")
	}
	if got.Name != "Google LLC" {
		t.Fatalf("Name = %q, want Google LLC", got.Name)
	}
	if got.Registry != "arin" {
		t.Fatalf("Registry = %q, want arin", got.Registry)
	}
	if got.Country != "US" {
		t.Fatalf("Country = %q, want US", got.Country)
	}
	if got.AbuseEmail != "network-abuse@google.com" {
		t.Fatalf("AbuseEmail = %q", got.AbuseEmail)
	}
}

func TestParseRDAPInfoNestedAbuse(t *testing.T) {
	resp := &rdapIPResponse{
		Links: []rdapLink{{Href: "https://rdap.db.ripe.net/ip/192.0.2.1"}},
		Entities: []rdapEntity{
			{
				Roles: []string{"technical"},
				Entities: []rdapEntity{
					{
						Roles: []string{"abuse"},
						VCardArray: json.RawMessage(`["vcard",[
							["email",{},"text","abuse@example.net"]
						]]`),
					},
				},
			},
		},
	}

	got := parseRDAPInfo(resp)
	if got == nil {
		t.Fatal("parseRDAPInfo returned nil")
	}
	if got.Registry != "ripe" {
		t.Fatalf("Registry = %q, want ripe", got.Registry)
	}
	if got.AbuseEmail != "abuse@example.net" {
		t.Fatalf("AbuseEmail = %q", got.AbuseEmail)
	}
}

func TestFormatASNDetailsIncludesRDAPOrg(t *testing.T) {
	got := FormatASNDetails(&ASNInfo{ASN: "15169", Org: "GOOGLE, US"}, &RDAPInfo{Name: "Google LLC"})
	want := "AS15169 GOOGLE (Google LLC)"
	if got != want {
		t.Fatalf("FormatASNDetails = %q, want %q", got, want)
	}
}

func TestFormatASNDetailsTrimsCymruLegalSuffix(t *testing.T) {
	got := FormatASNDetails(&ASNInfo{ASN: "13335", Org: "CLOUDFLARENET - Cloudflare, Inc., US"}, &RDAPInfo{Name: "Cloudflare, Inc."})
	want := "AS13335 CLOUDFLARENET (Cloudflare, Inc.)"
	if got != want {
		t.Fatalf("FormatASNDetails = %q, want %q", got, want)
	}
}
