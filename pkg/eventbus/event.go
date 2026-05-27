// Package eventbus is netcheck's in-process pub/sub for structured
// check events. The HUD redesign's Live Event Stream panel renders
// these as INFO/WARN/CRIT log rows; the Telemetry panel derives
// packets-per-second and avg latency from the same stream.
//
// The bus is intentionally minimal — no persistence, no replay, no
// priority queues. Publishers drop into Bus.Publish; subscribers
// receive a channel + a cancel func. Slow subscribers don't block
// publishers; the per-subscriber buffer drops the oldest event when
// full. See bus.go for the buffer policy.
//
// Event payloads are deliberately small and serializable. The SSE
// handler in cmd/app.go marshals each event to JSON as it arrives.
package eventbus

import "time"

// Level is the severity of a logged event. The three values mirror
// the HUD's status-pill chips (status-info / status-warn / status-crit).
// Use Info for the routine "check started / finished" flow, Warn for
// recoverable errors (high latency, retries), and Crit for hard
// failures the user should notice.
type Level string

const (
	LevelInfo Level = "INFO"
	LevelWarn Level = "WARN"
	LevelCrit Level = "CRIT"
)

// Event is one observation on the bus. Source is a short noun like
// "dns", "http", "ports" that the UI can use for filtering. Message
// is freeform text suitable for a single log row. Fields carries any
// structured context — keep it small (sub-1KB) since every subscriber
// gets a copy.
type Event struct {
	Timestamp time.Time      `json:"ts"`
	Level     Level          `json:"level"`
	Source    string         `json:"source"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"fields,omitempty"`
	// LatencyMS, when non-zero, lets the Telemetry derivation pick
	// the sample up without parsing Fields. Omit (leave zero) when
	// the event doesn't represent a timed operation.
	LatencyMS int64 `json:"latency_ms,omitempty"`
}

// NewInfo / NewWarn / NewCrit are small convenience constructors so
// the publish call sites stay one-liners.
//
//	bus.Publish(eventbus.NewInfo("dns", "resolved %s in %dms", host, ms))
func NewInfo(source, msg string) Event {
	return Event{Timestamp: time.Now(), Level: LevelInfo, Source: source, Message: msg}
}

func NewWarn(source, msg string) Event {
	return Event{Timestamp: time.Now(), Level: LevelWarn, Source: source, Message: msg}
}

func NewCrit(source, msg string) Event {
	return Event{Timestamp: time.Now(), Level: LevelCrit, Source: source, Message: msg}
}
