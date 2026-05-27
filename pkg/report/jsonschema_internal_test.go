package report

import (
	"encoding/json"
	"net"
	"testing"
)

// ipsToStrings must always return a non-nil slice. Returning nil
// serialises to JSON null, which breaks the web UI's `string[]` typed
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
