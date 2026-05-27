package eventbus

import "sync"

// defaultBuffer is the per-subscriber channel capacity. When a slow
// consumer fills its buffer, the bus drops the OLDEST event for that
// subscriber rather than blocking the publisher. 64 is enough to
// absorb a brief stall (≈64 events / scan) without hiding a real
// slow-consumer bug from observers.
const defaultBuffer = 64

// Bus is netcheck's in-process pub/sub. Zero value is NOT ready —
// call New() to construct one. Safe for concurrent Publish from
// multiple goroutines; Subscribe is also concurrent-safe.
type Bus struct {
	mu   sync.RWMutex
	subs map[*subscriber]struct{}
}

type subscriber struct {
	ch  chan Event
	bus *Bus
}

// New returns a ready Bus.
func New() *Bus {
	return &Bus{subs: make(map[*subscriber]struct{})}
}

// Publish fans an event out to every current subscriber. Never
// blocks: if a subscriber's buffer is full, the bus drops the
// OLDEST event for that subscriber (drain-one then send). This
// prefers freshness over completeness — the HUD's Live Event Stream
// is more useful with the latest 100 events than the first 100.
//
// Hot path: a single RLock around the subs map. Adding/removing
// subscribers uses the write lock and is rare (one per WebSocket /
// SSE connection lifetime).
func (b *Bus) Publish(ev Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for s := range b.subs {
		select {
		case s.ch <- ev:
			// Sent fine.
		default:
			// Buffer full. Drop the oldest, then send. The
			// double-select handles the race where someone
			// reads in between (rare, but possible).
			select {
			case <-s.ch:
			default:
			}
			select {
			case s.ch <- ev:
			default:
				// Truly stuck — receiver hasn't read at all.
				// Skip rather than block the bus.
			}
		}
	}
}

// Subscribe returns a buffered channel that will receive every event
// published from now on, plus a cancel function that closes the
// channel and removes the subscription.
//
// Cancel is idempotent. Always defer it.
//
//	ch, cancel := bus.Subscribe()
//	defer cancel()
//	for ev := range ch { ... }
func (b *Bus) Subscribe() (<-chan Event, func()) {
	s := &subscriber{
		ch:  make(chan Event, defaultBuffer),
		bus: b,
	}
	b.mu.Lock()
	b.subs[s] = struct{}{}
	b.mu.Unlock()

	var once sync.Once
	cancel := func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, s)
			b.mu.Unlock()
			close(s.ch)
		})
	}
	return s.ch, cancel
}

// SubscriberCount reports the number of active subscribers. Useful
// for tests and the /api/healthz response. O(1).
func (b *Bus) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs)
}
