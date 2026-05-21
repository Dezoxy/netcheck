package cmd

import "testing"

func TestParseFormat(t *testing.T) {
	cases := []struct {
		in      string
		want    Format
		wantErr bool
	}{
		{"", FormatText, false}, // empty defaults to text
		{"text", FormatText, false},
		{"TEXT", FormatText, false},
		{"txt", FormatText, false},
		{"  text  ", FormatText, false},
		{"json", FormatJSON, false},
		{"JSON", FormatJSON, false},
		{"markdown", FormatMarkdown, false},
		{"md", FormatMarkdown, false},
		{"html", FormatHTML, false},
		{"htm", FormatHTML, false},

		{"yaml", FormatText, true},
		{"xml", FormatText, true},
		{"prom", FormatText, true},
	}
	for _, c := range cases {
		got, err := ParseFormat(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseFormat(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseFormat(%q) unexpected error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("ParseFormat(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
