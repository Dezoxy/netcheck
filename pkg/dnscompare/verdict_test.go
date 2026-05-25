package dnscompare

import (
	"errors"
	"testing"
)

func TestVerdictAllAgree(t *testing.T) {
	r := Result{
		Host:  "example.com",
		QType: "A",
		Results: []ResolverResult{
			{Resolver: Resolver{Name: "A"}, Records: []string{"1.1.1.1"}},
			{Resolver: Resolver{Name: "B"}, Records: []string{"1.1.1.1"}},
			{Resolver: Resolver{Name: "C"}, Records: []string{"1.1.1.1"}},
		},
	}
	v := r.Verdict()
	if !v.Agree {
		t.Errorf("Agree = false, want true")
	}
	if len(v.Groups) != 1 {
		t.Fatalf("Groups len = %d, want 1", len(v.Groups))
	}
	if len(v.Groups[0].Resolvers) != 3 {
		t.Errorf("Group resolvers = %v, want 3", v.Groups[0].Resolvers)
	}
}

func TestVerdictDisagree(t *testing.T) {
	r := Result{
		Results: []ResolverResult{
			{Resolver: Resolver{Name: "A"}, Records: []string{"1.1.1.1"}},
			{Resolver: Resolver{Name: "B"}, Records: []string{"2.2.2.2"}},
			{Resolver: Resolver{Name: "C"}, Records: []string{"1.1.1.1"}},
		},
	}
	v := r.Verdict()
	if v.Agree {
		t.Errorf("Agree = true, want false")
	}
	if len(v.Groups) != 2 {
		t.Fatalf("Groups len = %d, want 2", len(v.Groups))
	}
	// Group 0 should be the first-seen answer set (1.1.1.1) with A and C.
	if len(v.Groups[0].Resolvers) != 2 {
		t.Errorf("Group[0] resolvers = %v, want 2 (A and C)", v.Groups[0].Resolvers)
	}
}

func TestVerdictFailedResolversIgnored(t *testing.T) {
	r := Result{
		Results: []ResolverResult{
			{Resolver: Resolver{Name: "A"}, Records: []string{"1.1.1.1"}},
			{Resolver: Resolver{Name: "B"}, Err: errors.New("timeout")},
			{Resolver: Resolver{Name: "C"}, Records: []string{"1.1.1.1"}},
		},
	}
	v := r.Verdict()
	if !v.Agree {
		t.Errorf("Agree = false, want true (B failed and is ignored)")
	}
	if len(v.Groups) != 1 {
		t.Fatalf("Groups len = %d", len(v.Groups))
	}
	if len(v.Groups[0].Resolvers) != 2 {
		t.Errorf("Group resolvers = %v, want 2 (A and C)", v.Groups[0].Resolvers)
	}
}

func TestVerdictAllFailed(t *testing.T) {
	r := Result{
		Results: []ResolverResult{
			{Resolver: Resolver{Name: "A"}, Err: errors.New("timeout")},
			{Resolver: Resolver{Name: "B"}, Err: errors.New("refused")},
		},
	}
	v := r.Verdict()
	if len(v.Groups) != 0 {
		t.Errorf("Groups len = %d, want 0", len(v.Groups))
	}
	// Agree is technically true when there are zero groups — the renderer
	// special-cases "all failed" off this, but make sure no panic.
	_ = v.Agree
}
