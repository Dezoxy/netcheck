package webui

import (
	"io/fs"
	"strings"
	"testing"
)

func TestDistContainsWorkbenchAssets(t *testing.T) {
	cases := map[string]string{
		"index.html":           `<div id="root"></div>`,
		"manifest.webmanifest": `"short_name": "netcheck"`,
		"sw.js":                "CACHE_NAME",
	}

	for name, want := range cases {
		got, err := fs.ReadFile(Dist(), name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !strings.Contains(string(got), want) {
			t.Fatalf("%s missing %q", name, want)
		}
	}
}
