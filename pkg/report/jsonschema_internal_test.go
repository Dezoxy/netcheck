package report

import (
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Dezoxy/netcheck/pkg/dnscompare"
	"github.com/Dezoxy/netcheck/pkg/reverseip"
	"github.com/Dezoxy/netcheck/pkg/subenum"
)

// ipsToStrings must always return a non-nil slice. Returning nil
// would serialize to JSON null, which breaks the web UI's `string[]` typed
// DNSJSON.A / .AAAA fields (App.tsx calls .map() unconditionally).
// Regression guard for the empty-page crash on IPv4-only targets.
func TestIpsToStringsNeverReturnsNil(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []net.IP
	}{
		{"nil input", nil},
		{"empty slice", []net.IP{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := ipsToStrings(tc.in)
			if out == nil {
				t.Fatal("ipsToStrings returned nil; web UI requires non-nil []string")
			}
			b, err := json.Marshal(out)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if string(b) != "[]" {
				t.Errorf("got JSON %s, want []", b)
			}
		})
	}
}

// Every non-omitempty []T struct field in jsonschema.go must marshal
// to [] (not null) when its populator receives empty/nil input. This
// is the contract the web UI consumes — App.tsx calls .map() on these
// fields without nullish-checks, so any null here causes a render
// crash. Regression guard generalised from the ipsToStrings fix.
//
// Each entry runs a builder with empty input and asserts the JSON
// contains `"field":[]` (not `"field":null`). Add a new entry here
// whenever a new non-omitempty slice field is added to the schema.
func TestPopulatorsNeverMarshalNonOmitemptySlicesAsNull(t *testing.T) {
	for _, tc := range []struct {
		name    string
		marshal func() ([]byte, error)
		fields  []string // field names that must appear as `"name":[]`
	}{
		{
			name: "ToDNSCompareJSON (empty results)",
			marshal: func() ([]byte, error) {
				return json.Marshal(ToDNSCompareJSON("example.com", time.Time{}, nil))
			},
			fields: []string{"queries"},
		},
		{
			name: "ToRouteJSON (nil toolArgs, nil hops)",
			marshal: func() ([]byte, error) {
				return json.Marshal(ToRouteJSON("example.com", "", "traceroute", nil, time.Time{}, nil, nil))
			},
			fields: []string{"tool_args", "hops"},
		},
		{
			name: "ToIPInfoJSON (no details)",
			marshal: func() ([]byte, error) {
				return json.Marshal(ToIPInfoJSON("1.2.3.4", time.Time{}, false, 0, nil))
			},
			fields: []string{"details"},
		},
		{
			name: "ToSubsJSON (empty Subdomain.Sources)",
			marshal: func() ([]byte, error) {
				return json.Marshal(ToSubsJSON(subenum.Result{
					Subdomains: []subenum.Subdomain{{Name: "x.example.com"}}, // Sources nil
				}))
			},
			fields: []string{`"sources":[]`}, // SubdomainJSON.Sources inside subdomains[0]
		},
		{
			name: "ToReverseJSON (empty Hostname.Sources)",
			marshal: func() ([]byte, error) {
				return json.Marshal(ToReverseJSON(reverseip.Result{
					Hostnames: []reverseip.Hostname{{Name: "x.example.com"}}, // Sources nil
				}))
			},
			fields: []string{`"sources":[]`},
		},
		{
			name: "queryToJSON (empty Verdict.Groups + empty Group records/resolvers)",
			marshal: func() ([]byte, error) {
				return json.Marshal(queryToJSON(dnscompare.Result{QType: "A"}))
			},
			fields: []string{`"results":[]`, `"groups":[]`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.marshal()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			s := string(b)
			for _, f := range tc.fields {
				want := f
				if !strings.Contains(want, ":") {
					// Bare field name → require `"f":[]`
					want = `"` + f + `":[]`
				}
				if !strings.Contains(s, want) {
					t.Errorf("missing %s in JSON; got: %s", want, s)
				}
				// Belt-and-suspenders: explicit null form must never appear.
				nullForm := strings.Replace(want, "[]", "null", 1)
				if strings.Contains(s, nullForm) {
					t.Errorf("found %s in JSON; nil slice must marshal to [] not null", nullForm)
				}
			}
		})
	}
}
