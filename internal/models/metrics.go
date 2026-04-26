// Traffic metrics reported by agents to the server via NATS.
package models

import "time"

// MetricsReport is the payload an agent publishes to the "metrics.report"
// NATS topic on every reporting interval.
type MetricsReport struct {
	AgentID   string        `json:"agent_id"`
	Timestamp time.Time     `json:"timestamp"`
	Clients   []ClientStats `json:"clients"`
}

// ClientStats holds per-IP traffic counters for a single reporting window.
type ClientStats struct {
	IP           string  `json:"ip"`
	ReqPerSec    int     `json:"req_per_sec"`
	Blocked      int     `json:"blocked"` // 1 if currently blocked, 0 otherwise
	Passed       int     `json:"passed"`  // total packets allowed through
	AvgLatencyUs float64 `json:"avg_latency_us,omitempty"` 
	MinLatencyUs float64 `json:"min_latency_us,omitempty"` 
	MaxLatencyUs float64 `json:"max_latency_us,omitempty"`
}