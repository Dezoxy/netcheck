package portscan

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"
)

func TestScanOnProgressFiresOncePerPort(t *testing.T) {
	port, stop := startListener(t)
	defer stop()

	var mu sync.Mutex
	got := []Progress{}
	opts := Options{
		Ports:          []int{port, port + 1, port + 2}, // 1 open + 2 (very likely) closed
		Concurrency:    3,
		PerPortTimeout: 200 * time.Millisecond,
		OnProgress: func(p Progress) {
			mu.Lock()
			got = append(got, p)
			mu.Unlock()
		},
	}
	res := Scan(context.Background(), "127.0.0.1", opts, 5*time.Second)
	if res.Err != nil {
		t.Fatalf("unexpected err: %v", res.Err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 {
		t.Fatalf("expected 3 progress events, got %d: %+v", len(got), got)
	}
	// Indexes 1..3, each unique.
	seenIdx := map[int]bool{}
	for _, p := range got {
		if p.TotalPorts != 3 {
			t.Errorf("TotalPorts = %d, want 3", p.TotalPorts)
		}
		if p.Index < 1 || p.Index > 3 {
			t.Errorf("Index out of range: %d", p.Index)
		}
		if seenIdx[p.Index] {
			t.Errorf("duplicate Index %d", p.Index)
		}
		seenIdx[p.Index] = true
	}
	// Exactly one open, two filtered/closed.
	openCount := 0
	for _, p := range got {
		if p.State == "open" {
			openCount++
			if p.Port != port {
				t.Errorf("open progress for wrong port: %d (want %d)", p.Port, port)
			}
		}
	}
	if openCount != 1 {
		t.Errorf("expected 1 open progress event, got %d", openCount)
	}
}

func TestScanOnProgressNilDoesNotCrash(t *testing.T) {
	// Sanity: when OnProgress is nil, scan should run without panicking.
	port, stop := startListener(t)
	defer stop()
	res := Scan(context.Background(), "127.0.0.1", Options{
		Ports:          []int{port},
		Concurrency:    1,
		PerPortTimeout: 200 * time.Millisecond,
		OnProgress:     nil,
	}, 5*time.Second)
	if res.Err != nil {
		t.Fatalf("unexpected err: %v", res.Err)
	}
}

func TestScanProgressOrderMatchesCompletion(t *testing.T) {
	// We can't promise a specific port-completion order under concurrency,
	// but Index should be 1-N with no gaps. This validates the atomic
	// counter logic.
	port, stop := startListener(t)
	defer stop()

	var mu sync.Mutex
	got := []int{}
	res := Scan(context.Background(), "127.0.0.1", Options{
		Ports:          []int{port, port + 1, port + 2, port + 3, port + 4},
		Concurrency:    5,
		PerPortTimeout: 200 * time.Millisecond,
		OnProgress: func(p Progress) {
			mu.Lock()
			got = append(got, p.Index)
			mu.Unlock()
		},
	}, 5*time.Second)
	if res.Err != nil {
		t.Fatalf("unexpected err: %v", res.Err)
	}

	mu.Lock()
	defer mu.Unlock()
	sort.Ints(got)
	want := []int{1, 2, 3, 4, 5}
	for i, v := range want {
		if got[i] != v {
			t.Errorf("Index sequence broken at i=%d: got %v, want %v", i, got, want)
		}
	}
}
