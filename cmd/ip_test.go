package cmd

import (
	"context"
	"testing"
)

func TestResolveIPInputDirectIPv4(t *testing.T) {
	label, ips, fromHost, err := ResolveIPInput(context.Background(), `"8.8.8.8"`)
	if err != nil {
		t.Fatal(err)
	}
	if fromHost {
		t.Fatal("fromHost = true, want false")
	}
	if label != "8.8.8.8" || len(ips) != 1 || ips[0].String() != "8.8.8.8" {
		t.Fatalf("label=%q ips=%v", label, ips)
	}
}

func TestResolveIPInputBracketedIPv6(t *testing.T) {
	label, ips, fromHost, err := ResolveIPInput(context.Background(), "[2001:4860:4860::8888]:443")
	if err != nil {
		t.Fatal(err)
	}
	if fromHost {
		t.Fatal("fromHost = true, want false")
	}
	if label != "2001:4860:4860::8888" || len(ips) != 1 || ips[0].String() != "2001:4860:4860::8888" {
		t.Fatalf("label=%q ips=%v", label, ips)
	}
}
