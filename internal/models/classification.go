package models

import "time"

// Classification labels assigned by the autonomous Z-score classifier.
const (
	ClassUnknown    = "unknown"    // insufficient history to decide
	ClassNormal     = "normal"     // behaving within baseline — no action
	ClassTrusted    = "trusted"    // consistently predictable — whitelisted in eBPF
	ClassSuspicious = "suspicious" // sudden deviation — rate-limited or blocked
)

// IPClassification holds the latest classification state for a single IP.
type IPClassification struct {
	IP             string    `json:"ip"`
	Classification string    `json:"classification"`
	ZScore         float64   `json:"z_score"`
	SampleCount    int       `json:"sample_count"`
	MeanRate       float64   `json:"mean_rate"`
	StddevRate     float64   `json:"stddev_rate"`
	CurrentRate    float64   `json:"current_rate"`
	MeanLatency    float64   `json:"mean_latency"`
	StddevLatency  float64   `json:"stddev_latency"`
	Whitelisted    bool      `json:"whitelisted"`
	LastUpdated    time.Time `json:"last_updated"`
	Reason         string    `json:"reason"`
}

// ClassificationLog is a single entry in the classification audit trail.
type ClassificationLog struct {
	Time           time.Time `json:"time"`
	IP             string    `json:"ip"`
	Classification string    `json:"classification"`
	ZScore         float64   `json:"z_score"`
	SampleCount    int       `json:"sample_count"`
	MeanRate       float64   `json:"mean_rate"`
	CurrentRate    float64   `json:"current_rate"`
	Action         string    `json:"action"` // "whitelist_add", "whitelist_remove", "rate_limit", "block", "no_change"
	RateLimit      int       `json:"rate_limit,omitempty"`
	Reason         string    `json:"reason"`
}

// WhitelistUpdate is the NATS payload published on "whitelist.update" whenever
// the classifier adds or removes an IP from the eBPF bypass list.
type WhitelistUpdate struct {
	IP     string `json:"ip"`
	Action string `json:"action"` // "add" or "remove"
	Reason string `json:"reason"`
}

// WhitelistFetchResponse is the NATS reply payload for "whitelist.fetch"
// requests sent by agents at startup to seed their bypass list.
type WhitelistFetchResponse struct {
	IPs []string `json:"ips"`
}
