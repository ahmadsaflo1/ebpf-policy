package models

import "time"

// Metrics report sent by agents to the central server
type MetricsReport struct {
	AgentID   string         `json:"agent_id"`
	Timestamp time.Time      `json:"timestamp"`
	Clients	  []ClientStats `json:"clients"`
}

type ClientStats struct {
	IP        string   `json:"ip"`
	ReqPerSec int  	   `json:"req_per_sec"`
	Blocked   int      `json:"blocked"`
	Passed    int	   `json:"passed"`
}