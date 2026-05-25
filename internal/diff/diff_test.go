package diff

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func mustJSON(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDiffNoChangesPorts(t *testing.T) {
	same := map[string]any{
		"kind":       "ports",
		"host":       "example.com",
		"started_at": "2026-05-25T10:00:00Z",
		"ports": []any{
			map[string]any{"port": 80, "service": "http"},
		},
		"stats": map[string]any{"total": 1, "open": 1},
	}
	rep, err := Diff(mustJSON(t, same), mustJSON(t, same))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Changed {
		t.Errorf("expected no changes, got %+v", rep)
	}
}

func TestDiffPortsOpenedClosed(t *testing.T) {
	older := map[string]any{
		"kind": "ports", "host": "example.com",
		"started_at": "2026-05-25T10:00:00Z",
		"ports": []any{
			map[string]any{"port": 22, "service": "ssh"},
			map[string]any{"port": 80, "service": "http"},
		},
	}
	newer := map[string]any{
		"kind": "ports", "host": "example.com",
		"started_at": "2026-05-25T11:00:00Z",
		"ports": []any{
			map[string]any{"port": 80, "service": "http"},
			map[string]any{"port": 443, "service": "https"},
		},
	}
	rep, err := Diff(mustJSON(t, older), mustJSON(t, newer))
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Changed {
		t.Fatal("expected changes")
	}
	var sb strings.Builder
	RenderText(&sb, rep)
	out := sb.String()
	// Should report 443 opened, 22 closed.
	if !strings.Contains(out, "Port 443 opened") {
		t.Errorf("missing 'Port 443 opened':\n%s", out)
	}
	if !strings.Contains(out, "Port 22 closed") {
		t.Errorf("missing 'Port 22 closed':\n%s", out)
	}
}

func TestDiffPortsBannerChange(t *testing.T) {
	older := map[string]any{
		"kind": "ports", "host": "example.com",
		"ports": []any{
			map[string]any{"port": 80, "service": "http", "banner": "nginx/1.24.0"},
		},
	}
	newer := map[string]any{
		"kind": "ports", "host": "example.com",
		"ports": []any{
			map[string]any{"port": 80, "service": "http", "banner": "nginx/1.27.0"},
		},
	}
	rep, _ := Diff(mustJSON(t, older), mustJSON(t, newer))
	if !rep.Changed {
		t.Fatal("expected banner change to register")
	}
	var sb strings.Builder
	RenderText(&sb, rep)
	if !strings.Contains(sb.String(), "1.24.0") || !strings.Contains(sb.String(), "1.27.0") {
		t.Errorf("expected old and new banner in output:\n%s", sb.String())
	}
}

func TestDiffSubsAddedRemoved(t *testing.T) {
	older := map[string]any{
		"kind": "subs", "domain": "example.com",
		"subdomains": []any{
			map[string]any{"name": "a.example.com"},
			map[string]any{"name": "b.example.com"},
		},
	}
	newer := map[string]any{
		"kind": "subs", "domain": "example.com",
		"subdomains": []any{
			map[string]any{"name": "b.example.com"},
			map[string]any{"name": "c.example.com"},
		},
	}
	rep, _ := Diff(mustJSON(t, older), mustJSON(t, newer))
	if !rep.Changed {
		t.Fatal("expected subdomain changes")
	}
	var sb strings.Builder
	RenderText(&sb, rep)
	out := sb.String()
	if !strings.Contains(out, "c.example.com") {
		t.Errorf("expected added subdomain in output:\n%s", out)
	}
	if !strings.Contains(out, "a.example.com") {
		t.Errorf("expected removed subdomain in output:\n%s", out)
	}
}

func TestDiffHeadersGradeChange(t *testing.T) {
	older := map[string]any{
		"kind": "headers", "url": "https://example.com",
		"findings": []any{
			map[string]any{"name": "HSTS", "grade": "pass"},
		},
	}
	newer := map[string]any{
		"kind": "headers", "url": "https://example.com",
		"findings": []any{
			map[string]any{"name": "HSTS", "grade": "missing"},
		},
	}
	rep, _ := Diff(mustJSON(t, older), mustJSON(t, newer))
	if !rep.Changed {
		t.Fatal("expected grade regression")
	}
	// A pass→missing change is a regression — severity should be err.
	var seenErr bool
	for _, s := range rep.Sections {
		for _, c := range s.Changes {
			if c.Severity == SevErr {
				seenErr = true
			}
		}
	}
	if !seenErr {
		t.Errorf("pass→missing should produce SevErr, got %+v", rep)
	}
}

func TestDiffKindMismatchReportsAndContinues(t *testing.T) {
	older := map[string]any{"kind": "ports", "host": "example.com"}
	newer := map[string]any{"kind": "subs", "domain": "example.com"}
	rep, err := Diff(mustJSON(t, older), mustJSON(t, newer))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Kind != "mixed" {
		t.Errorf("expected Kind=mixed, got %q", rep.Kind)
	}
	if !rep.Changed {
		t.Fatal("expected kind change to register as change")
	}
}

func TestDiffMalformedInputErrors(t *testing.T) {
	if _, err := Diff([]byte("not json"), []byte("{}")); err == nil {
		t.Error("expected parse error on bad old json")
	}
	if _, err := Diff([]byte("{}"), []byte("not json")); err == nil {
		t.Error("expected parse error on bad new json")
	}
}

func TestRenderJSONRoundtrip(t *testing.T) {
	// Encoding the report to JSON and decoding back should preserve the
	// public fields exactly. Cheap guard against a future struct-tag drift.
	in := Report{
		Kind:    "ports",
		Target:  "example.com",
		Changed: true,
		Sections: []Section{
			{Title: "Ports opened", Changes: []Change{{Severity: SevErr, Message: "Port 8080 opened"}}},
		},
	}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, in); err != nil {
		t.Fatal(err)
	}
	var out Report
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Kind != in.Kind || out.Target != in.Target || len(out.Sections) != 1 {
		t.Errorf("roundtrip mismatch: %+v", out)
	}
}

func TestDiffNoChangesRendersExplicit(t *testing.T) {
	same := map[string]any{"kind": "ports", "host": "example.com",
		"ports": []any{map[string]any{"port": 80}}}
	rep, _ := Diff(mustJSON(t, same), mustJSON(t, same))
	var sb strings.Builder
	RenderText(&sb, rep)
	if !strings.Contains(sb.String(), "no changes") {
		t.Errorf("expected explicit no-changes message:\n%s", sb.String())
	}
}

func TestDiffTechVersionChange(t *testing.T) {
	older := map[string]any{"kind": "tech", "url": "https://example.com",
		"matches": []any{
			map[string]any{"name": "nginx", "version": "1.24.0"},
			map[string]any{"name": "jquery", "version": "3.5.0"},
		}}
	newer := map[string]any{"kind": "tech", "url": "https://example.com",
		"matches": []any{
			map[string]any{"name": "nginx", "version": "1.27.0"},
			map[string]any{"name": "react", "version": "18.0.0"},
		}}
	rep, _ := Diff(mustJSON(t, older), mustJSON(t, newer))
	if !rep.Changed {
		t.Fatal("expected changes")
	}
	var sb strings.Builder
	RenderText(&sb, rep)
	out := sb.String()
	// Expect: nginx version changed, jquery removed, react added.
	for _, want := range []string{"nginx", "1.24.0", "1.27.0", "jquery", "react"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestExtractTargetCoversCommonKinds(t *testing.T) {
	cases := []struct {
		in   map[string]any
		want string
	}{
		{map[string]any{"host": "h"}, "h"},
		{map[string]any{"domain": "d"}, "d"},
		{map[string]any{"url": "u"}, "u"},
		{map[string]any{"base_url": "b"}, "b"},
		{map[string]any{"ip": "1.2.3.4"}, "1.2.3.4"},
		{map[string]any{"target": map[string]any{"raw": "https://x"}}, "https://x"},
		{map[string]any{}, ""},
	}
	for i, c := range cases {
		if got := extractTarget(c.in); got != c.want {
			t.Errorf("case %d: extractTarget = %q, want %q", i, got, c.want)
		}
	}
}
