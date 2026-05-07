// System performance metrics reported by agents to the server via NATS.
package models

import "time"

// SystemMetrics represents system performance data collected by the agent
type SystemMetrics struct {
	CPUPercent    int64 `json:"cpu_percent"`
	MemoryPercent int64 `json:"memory_percent"`
	MemoryUsedMB  uint64  `json:"memory_used_mb"`
	MemoryTotalMB uint64  `json:"memory_total_mb"`
	DiskUsedGB    uint64  `json:"disk_used_gb"`
	DiskTotalGB   uint64  `json:"disk_total_gb"`
	DiskPercent   int64 `json:"disk_percent"`
	NetBytesSent  uint64  `json:"net_bytes_sent"`
	NetBytesRecv  uint64  `json:"net_bytes_recv"`
}

// SystemMetricsReport is published by agents to the server
type SystemMetricsReport struct {
	AgentID   string        `json:"agent_id"`
	Timestamp time.Time     `json:"timestamp"`
	Metrics   SystemMetrics `json:"metrics"`
}