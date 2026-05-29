package ipinfo

import "testing"

func TestCutWhoisField(t *testing.T) {
	tests := []struct {
		line, label, want string
		ok                bool
	}{
		{"Registrar: MarkMonitor Inc.", "registrar", "MarkMonitor Inc.", true},
		{"registrar:    Example Kft.", "registrar", "Example Kft.", true},
		{"REGISTRAR: Foo", "registrar", "Foo", true},
		{"Registrar URL: https://example.com", "registrar", "", false}, // exact key only
		{"Registrar IANA ID: 292", "registrar", "", false},
		{"whois: whois.nic.hu", "whois", "whois.nic.hu", true},
		{"no colon here", "registrar", "", false},
	}
	for _, tt := range tests {
		got, ok := cutWhoisField(tt.line, tt.label)
		if ok != tt.ok || got != tt.want {
			t.Errorf("cutWhoisField(%q, %q) = (%q, %v), want (%q, %v)",
				tt.line, tt.label, got, ok, tt.want, tt.ok)
		}
	}
}

func TestParseRegistrar(t *testing.T) {
	// gTLD-style response: must pick "Registrar:", not "Registrar URL:".
	gtld := "Domain Name: EXAMPLE.COM\nRegistrar URL: https://www.markmonitor.com\nRegistrar: MarkMonitor Inc.\nRegistrar IANA ID: 292\n"
	if got := parseRegistrar(gtld); got != "MarkMonitor Inc." {
		t.Errorf("gTLD: got %q, want %q", got, "MarkMonitor Inc.")
	}

	// ccTLD-style response: lowercase label.
	cctld := "domain:       vipcomm.hu\nregistrar:    Example Registrar Kft.\n"
	if got := parseRegistrar(cctld); got != "Example Registrar Kft." {
		t.Errorf("ccTLD: got %q, want %q", got, "Example Registrar Kft.")
	}

	if got := parseRegistrar("domain: foo.example\nstatus: active\n"); got != "" {
		t.Errorf("no registrar line: got %q, want empty", got)
	}
	if got := parseRegistrar(""); got != "" {
		t.Errorf("empty input: got %q, want empty", got)
	}
}
