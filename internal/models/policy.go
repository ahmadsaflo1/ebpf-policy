// Package models defines the shared data structures used by the policy server
// and enforcement agents.
package models

import "time"

// PolicyRule describes a single traffic-enforcement rule, for example
// "block any IP sending more than 500 req/s for 60 seconds".
type PolicyRule struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Threshold int       `json:"threshold"` // req/s above which the rule triggers
	Action    string    `json:"action"`    // "block" or "rate_limit"
	Duration  int       `json:"duration"`  // how long the action is applied, in seconds
	Tag       string    `json:"tag"`       // environment tag, e.g. "production"; empty means global
	CreatedAt time.Time `json:"created_at"`
}

// ClientStatus represents the current enforcement state of a single client IP.
type ClientStatus struct {
	IP        string    `json:"ip"`
	ReqPerSec int       `json:"req_per_sec"`
	Blocked   bool      `json:"blocked"`
	BlockedAt time.Time `json:"blocked_at,omitempty"`
}