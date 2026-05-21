package target

import "testing"

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"bare hostname unchanged", "example.com", "example.com", false},
		{"lowercased", "Example.COM", "example.com", false},
		{"https URL", "https://example.com", "example.com", false},
		{"http URL with path", "http://example.com/path?q=1#frag", "example.com", false},
		{"hostname with path", "example.com/some/path", "example.com", false},
		{"hostname with query", "example.com?foo=bar", "example.com", false},
		{"hostname with fragment", "example.com#section", "example.com", false},
		{"hostname with port", "example.com:8080", "example.com", false},
		{"https URL with port", "https://example.com:8443/x", "example.com", false},
		{"IPv6 literal bracketed", "[2001:db8::1]:443", "2001:db8::1", false},
		{"bare IPv6 not bracketed left alone", "2001:db8::1", "2001:db8::1", false},
		{"surrounding double quotes", `"google.com"`, "google.com", false},
		{"surrounding single quotes", "'google.com'", "google.com", false},
		{"whitespace trimmed", "   google.com   ", "google.com", false},
		{"messy input", `  "HTTPS://Google.com/search?q=hi"  `, "google.com", false},

		{"empty", "", "", true},
		{"whitespace only", "   ", "", true},
		{"quotes only", `""`, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := NormalizeHost(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("NormalizeHost(%q) = %q, want error", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeHost(%q) unexpected error: %v", c.in, err)
			}
			if got != c.want {
				t.Errorf("NormalizeHost(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
