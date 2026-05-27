package eventbus

import (
	"testing"
	"time"
)

// Publish never blocks even when a subscriber's buffer is full —
// the bus drops the oldest event for that subscriber instead. With
// `defaultBuffer` events published and a fully-stalled subscriber,
// the queue should be capped at the buffer size.
//
// This is the core contract the HUD's Live Event Stream depends on:
// no consumer (slow renderer, paused tab, broken network) can ever
// block check handlers via the bus.
func TestPublishDropsOldestWhenBufferFull(t *testing.T) {
	b := New()
	stalled, cancel := b.Subscribe()
	defer cancel()

	// Push twice the buffer's worth. None are drained. Should not
	// deadlock and should not exceed the buffer.
	target := defaultBuffer * 2
	doneCh := make(chan struct{})
	go func() {
		for i := 0; i < target; i++ {
			b.Publish(NewInfo("test", "msg"))
		}
		close(doneCh)
	}()
	select {
	case <-doneCh:
		// Good — publishes returned without blocking.
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a stalled subscriber")
	}

	queued := len(stalled)
	if queued > defaultBuffer {
		t.Errorf("stalled subscriber queue=%d exceeds buffer cap %d", queued, defaultBuffer)
	}
	if queued == 0 {
		t.Errorf("stalled subscriber queue=0, want some events to have landed")
	}
}

// A subscriber that drains synchronously between publishes sees
// every event. This avoids goroutine scheduling races entirely:
// pub → drain → pub → drain. Demonstrates fanout works and the
// channel isn't accidentally lossy on the happy path.
//
// (The "drain on a separate goroutine and assert N of M survive"
// shape is flaky by design — under heavy CI load the publisher
// can complete the whole loop before the drainer is scheduled,
// and drop-oldest correctly kicks in. That race was a bad test;
// this is a better one.)
func TestSubscriberReceivesEachPublishedEvent(t *testing.T) {
	b := New()
	ch, cancel := b.Subscribe()
	defer cancel()

	const n = 50
	for i := 0; i < n; i++ {
		b.Publish(NewInfo("test", "msg"))
		// Drain the channel before publishing again, so the buffer
		// never fills and drop-oldest never triggers.
		select {
		case ev := <-ch:
			if ev.Source != "test" {
				t.Fatalf("event %d: got source=%q, want %q", i, ev.Source, "test")
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("event %d: publish did not reach subscriber within 100ms", i)
		}
	}
}

// Subscribe registers, cancel deregisters. SubscriberCount tracks both.
func TestSubscribeCancel(t *testing.T) {
	b := New()
	if got := b.SubscriberCount(); got != 0 {
		t.Fatalf("fresh bus: count=%d, want 0", got)
	}
	_, cancelA := b.Subscribe()
	_, cancelB := b.Subscribe()
	if got := b.SubscriberCount(); got != 2 {
		t.Fatalf("two subs: count=%d, want 2", got)
	}
	cancelA()
	if got := b.SubscriberCount(); got != 1 {
		t.Fatalf("after cancelA: count=%d, want 1", got)
	}
	// Cancel is idempotent.
	cancelA()
	if got := b.SubscriberCount(); got != 1 {
		t.Fatalf("double cancelA: count=%d, want 1", got)
	}
	cancelB()
	if got := b.SubscriberCount(); got != 0 {
		t.Fatalf("after cancelB: count=%d, want 0", got)
	}
}

// Publish with zero subscribers is a no-op (and must not panic).
func TestPublishWithNoSubscribers(t *testing.T) {
	b := New()
	b.Publish(NewInfo("test", "into the void"))
	// No panic, no deadlock — pass.
}
