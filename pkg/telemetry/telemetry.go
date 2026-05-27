// Package telemetry derives the metrics rendered in the HUD's
// Telemetry Strip from the eventbus stream. Two derived values:
//
//   - PacketsPerSec — events/sec averaged over the last 60s window.
//     Not actual network packets — we're not a sniffer. The name
//     matches the Stitch mock; the API response and this file
//     document the real meaning.
//
//   - AvgLatencyMS — mean of Event.LatencyMS values seen in the
//     window. Events with LatencyMS==0 are skipped (most are).
//
// The Sparkline array carries the last 60 per-second event-count
// samples, oldest first. The /api/telemetry handler returns the
// snapshot as JSON; the React Telemetry Strip polls every 1s.
package telemetry

import (
	"sync"
	"time"

	"github.com/Dezoxy/netcheck/pkg/eventbus"
)

const windowSeconds = 60

// Snapshot is the JSON shape returned by /api/telemetry. Field names
// are wire-format; don't rename without bumping the API contract.
type Snapshot struct {
	// PacketsPerSec is the count of bus events / second averaged over
	// the last `windowSeconds`. Despite the name (which mirrors the
	// Stitch HUD mock), these are check events, not packets.
	PacketsPerSec float64 `json:"packets_per_sec"`
	// AvgLatencyMS is the mean latency across events with a non-zero
	// LatencyMS in the window. 0 when no timed events have arrived.
	AvgLatencyMS float64 `json:"avg_latency_ms"`
	// Sparkline is the last `windowSeconds` per-second event counts,
	// oldest first. Drives the small SVG sparkline in the UI.
	Sparkline []float64 `json:"sparkline"`
	// Subscribers is the number of /api/events/stream consumers
	// currently connected. Surfaced for the System Health pill.
	Subscribers int `json:"subscribers"`
}

// Collector subscribes to the bus and maintains a rolling 60s window
// of per-second event counts + latency sums. Start() blocks until
// ctx is done; call in a goroutine.
type Collector struct {
	bus *eventbus.Bus

	mu        sync.Mutex
	counts    [windowSeconds]int     // events per second, ring
	latencies [windowSeconds]float64 // latency sum per second, ring
	samples   [windowSeconds]int     // # samples with latency per second
	head      int                    // index of the current second
	headStart time.Time              // wall time of head bucket start
}

// NewCollector returns a Collector wired to the given bus. The
// returned Collector is not running — call Run(ctx) in a goroutine.
func NewCollector(bus *eventbus.Bus) *Collector {
	return &Collector{bus: bus, headStart: time.Now()}
}

// Run subscribes and updates the ring buffer until ctx is done.
// Safe to call once per Collector; safe to call concurrently with
// Snapshot().
func (c *Collector) Run(done <-chan struct{}) {
	ch, cancel := c.bus.Subscribe()
	defer cancel()
	// A 1s ticker rolls the ring forward even when no events arrive
	// (so the sparkline still scrolls during idle periods).
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			c.record(ev)
		case <-tick.C:
			c.rollForward(time.Now())
		}
	}
}

// record bumps the current-second counters for an event.
func (c *Collector) record(ev eventbus.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rollForwardLocked(time.Now())
	c.counts[c.head]++
	if ev.LatencyMS > 0 {
		c.latencies[c.head] += float64(ev.LatencyMS)
		c.samples[c.head]++
	}
}

// rollForward advances the head pointer to match `now`. Any
// intervening buckets are zeroed (they had no events). Public
// caller-side variant used by the ticker.
func (c *Collector) rollForward(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rollForwardLocked(now)
}

func (c *Collector) rollForwardLocked(now time.Time) {
	elapsed := int(now.Sub(c.headStart).Seconds())
	if elapsed <= 0 {
		return
	}
	if elapsed >= windowSeconds {
		// We've been idle for the whole window — zero everything.
		for i := range c.counts {
			c.counts[i] = 0
			c.latencies[i] = 0
			c.samples[i] = 0
		}
		c.head = 0
		c.headStart = now
		return
	}
	for i := 0; i < elapsed; i++ {
		c.head = (c.head + 1) % windowSeconds
		c.counts[c.head] = 0
		c.latencies[c.head] = 0
		c.samples[c.head] = 0
	}
	c.headStart = c.headStart.Add(time.Duration(elapsed) * time.Second)
}

// Snapshot returns the current rolled-forward state. Safe to call
// concurrently with Run.
func (c *Collector) Snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rollForwardLocked(time.Now())

	var totalEvents int
	var totalLatencySum float64
	var totalSamples int
	for i := 0; i < windowSeconds; i++ {
		totalEvents += c.counts[i]
		totalLatencySum += c.latencies[i]
		totalSamples += c.samples[i]
	}

	// Sparkline: emit the ring oldest-first by walking head+1 → head.
	sparkline := make([]float64, windowSeconds)
	for i := 0; i < windowSeconds; i++ {
		idx := (c.head + 1 + i) % windowSeconds
		sparkline[i] = float64(c.counts[idx])
	}

	avgLat := 0.0
	if totalSamples > 0 {
		avgLat = totalLatencySum / float64(totalSamples)
	}

	return Snapshot{
		PacketsPerSec: float64(totalEvents) / float64(windowSeconds),
		AvgLatencyMS:  avgLat,
		Sparkline:     sparkline,
		Subscribers:   c.bus.SubscriberCount(),
	}
}
