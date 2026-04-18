package models

import "time"

// A policy rule — e.g. "block IP if over 500 req/s"
type PolicyRule struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Threshold int       `json:"threshold"`// req/s
	Action    string    `json:"action"`   // e.g. "block" or "rate_limit"
	Duration  int       `json:"duration"` // seconds
	Tag       string    `json:"tag"`
	CreatedAt time.Time `json:"created_at"`
}

// Status of a client IP — e.g. "
type ClientStatus struct {
	IP        string    `json:"ip"`
	ReqPerSec int  	    `json:"req_per_sec"`
	Blocked   bool      `json:"blocked"`
	BlockedAt time.Time `json:"blocked_at,omitempty"`
}