package target

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		name       string
		in         string
		wantScheme string
		wantHost   string
		wantPort   string
		wantErr    bool
	}{
		{"bare hostname defaults to https", "google.com", "https", "google.com", "443", false},
		{"http URL", "http://example.com", "http", "example.com", "80", false},
		{"https URL", "https://example.com/path", "https", "example.com", "443", false},
		{"explicit port", "https://example.com:8443", "https", "example.com", "8443", false},
		{"http explicit port", "http://example.com:8080/x", "http", "example.com", "8080", false},
		{"bare hostname with port", "example.com:8080", "https", "example.com", "8080", false},
		{"IPv4 literal", "192.0.2.1", "https", "192.0.2.1", "443", false},
		{"IPv6 literal bracketed", "https://[2001:db8::1]:8443/x", "https", "2001:db8::1", "8443", false},
		{"whitespace trimmed", "  google.com  ", "https", "google.com", "443", false},

		{"empty", "", "", "", "", true},
		{"whitespace only", "   ", "", "", "", true},
		{"unsupported scheme", "ftp://example.com", "", "", "", true},
		{"scheme only", "https://", "", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q) = %+v, want error", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q) unexpected error: %v", c.in, err)
			}
			if got.Scheme != c.wantScheme {
				t.Errorf("Scheme = %q, want %q", got.Scheme, c.wantScheme)
			}
			if got.Host != c.wantHost {
				t.Errorf("Host = %q, want %q", got.Host, c.wantHost)
			}
			if got.Port != c.wantPort {
				t.Errorf("Port = %q, want %q", got.Port, c.wantPort)
			}
		})
	}
}

func TestParseRawPreserved(t *testing.T) {
	// Parse should normalize Raw with the scheme added in.
	got, err := Parse("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.Raw != "https://example.com" {
		t.Errorf("Raw = %q, want https://example.com", got.Raw)
	}
}
