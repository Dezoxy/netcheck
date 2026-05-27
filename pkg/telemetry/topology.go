package telemetry

import (
	"sync"
	"time"
)

// TopologyNode is one rendered point in the HUD's Target Topography
// SVG. (x, y) is a 0..1 normalized position the React component
// turns into viewport coordinates. Status drives the per-node color
// (target / hop / timeout).
type TopologyNode struct {
	ID     string   `json:"id"`
	Label  string   `json:"label,omitempty"`
	X      float64  `json:"x"`
	Y      float64  `json:"y"`
	Status string   `json:"status"` // "target", "hop", "timeout"
	IPs    []string `json:"ips,omitempty"`
}

// TopologyEdge connects two nodes by ID. Direction matters for the
// SVG (line drawn from From to To); the renderer adds an arrowhead.
type TopologyEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// TopologyGraph is the full payload returned by /api/topology. Empty
// nodes + edges means "no scan has run yet" — the UI shows the
// ambient placeholder.
type TopologyGraph struct {
	Nodes     []TopologyNode `json:"nodes"`
	Edges     []TopologyEdge `json:"edges"`
	UpdatedAt time.Time      `json:"updated_at,omitempty"`
}

// TopologyCache stores the latest traceroute-derived graph. The
// route handler in cmd/app.go writes here when a route check
// completes; the /api/topology handler reads. Single-slot: a new
// traceroute clobbers the previous graph.
type TopologyCache struct {
	mu    sync.RWMutex
	graph TopologyGraph
}

// NewTopologyCache returns an empty cache. The zero TopologyGraph
// inside is fine — /api/topology returns it as-is on a cold start.
func NewTopologyCache() *TopologyCache {
	return &TopologyCache{graph: TopologyGraph{Nodes: []TopologyNode{}, Edges: []TopologyEdge{}}}
}

// Set replaces the cached graph. Nodes/Edges are kept as-is; the
// caller owns layout. UpdatedAt is stamped to Now() to give the UI
// a freshness signal.
func (c *TopologyCache) Set(nodes []TopologyNode, edges []TopologyEdge) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Honor the "non-omitempty slice never nil" contract from #108.
	if nodes == nil {
		nodes = []TopologyNode{}
	}
	if edges == nil {
		edges = []TopologyEdge{}
	}
	c.graph = TopologyGraph{Nodes: nodes, Edges: edges, UpdatedAt: time.Now()}
}

// Snapshot returns a copy of the current graph. Safe to mutate the
// returned slices (they're freshly allocated).
func (c *TopologyCache) Snapshot() TopologyGraph {
	c.mu.RLock()
	defer c.mu.RUnlock()
	nodes := make([]TopologyNode, len(c.graph.Nodes))
	copy(nodes, c.graph.Nodes)
	edges := make([]TopologyEdge, len(c.graph.Edges))
	copy(edges, c.graph.Edges)
	return TopologyGraph{Nodes: nodes, Edges: edges, UpdatedAt: c.graph.UpdatedAt}
}
