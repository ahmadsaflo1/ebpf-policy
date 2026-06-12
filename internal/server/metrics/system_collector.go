package metrics

import (
	"encoding/json"
	"log"
	"sync"

	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
)

// autoScaleRuleID is the sentinel rule ID used for automatically generated
// load-scaling rules. Negative to avoid conflicts with database-allocated IDs.
const autoScaleRuleID = -1

// ScaleConfig holds the CPU and rate-limit thresholds for reactive load handling.
type ScaleConfig struct {
	CPUHigh         int
	CPUNormal       int
	RateLimitHigh   int
	RateLimitNormal int
}

var (
	autoScaleMu     sync.Mutex
	autoScaleAgents = make(map[string]bool) // agents with an active auto-scale rule
)

// StartSystemCollector subscribes to "system.metrics" on NATS, persists each
// incoming SystemMetricsReport, and reacts to CPU load by publishing temporary
// rate-limit rules when an agent is under pressure.
func StartSystemCollector(cfg ScaleConfig) {
	err := messaging.Subscribe("system.metrics", func(data []byte) {
		var report models.SystemMetricsReport
		if err := json.Unmarshal(data, &report); err != nil {
			log.Printf("Error unmarshaling system metrics report: %v", err)
			return
		}

		cpuPct := float64(report.Metrics.CPUPercent) / 1000

		log.Printf("Received system metrics from agent %s: CPU=%.1f%%, Mem=%.1f%%, Disk=%.1f%%\n",
			report.AgentID,
			cpuPct,
			float64(report.Metrics.MemoryPercent)/1000,
			float64(report.Metrics.DiskPercent)/1000)

		saveSystemMetrics(report.AgentID, report.Metrics)
		checkAutoScale(report.AgentID, cpuPct, cfg)
	})

	if err != nil {
		log.Fatalf("Failed to subscribe to system metrics: %v", err)
	}

	log.Println("System metrics collector started and subscribed to system.metrics")
}

// checkAutoScale publishes or retracts a temporary rate-limit rule for agentID
// based on current CPU load vs the configured thresholds. The in-memory
// autoScaleAgents map prevents redundant publishes for the same state.
func checkAutoScale(agentID string, cpuPct float64, cfg ScaleConfig) {
	if cfg.CPUHigh <= 0 {
		return
	}

	autoScaleMu.Lock()
	active := autoScaleAgents[agentID]
	autoScaleMu.Unlock()

	switch {
	case !active && cpuPct > float64(cfg.CPUHigh):
		publishAutoScaleRule(agentID, cfg.RateLimitHigh)
		autoScaleMu.Lock()
		autoScaleAgents[agentID] = true
		autoScaleMu.Unlock()
		log.Printf("Auto-scale: agent %s CPU=%.1f%% > %d%% — activating rate-limit %d req/s\n",
			agentID, cpuPct, cfg.CPUHigh, cfg.RateLimitHigh)

	case active && cpuPct < float64(cfg.CPUNormal):
		retractAutoScaleRule(agentID)
		autoScaleMu.Lock()
		delete(autoScaleAgents, agentID)
		autoScaleMu.Unlock()
		log.Printf("Auto-scale: agent %s CPU=%.1f%% < %d%% — removing rate-limit, restoring %d req/s\n",
			agentID, cpuPct, cfg.CPUNormal, cfg.RateLimitNormal)
	}
}

// publishAutoScaleRule sends a temporary rate-limit rule exclusively to agentID
// via policy.update.<agentID>. The rule uses autoScaleRuleID so it can be
// cleanly retracted later without affecting database-managed rules.
func publishAutoScaleRule(agentID string, threshold int) {
	rule := models.PolicyRule{
		ID:        autoScaleRuleID,
		Name:      "auto-scale-" + agentID,
		Threshold: threshold,
		Action:    "rate_limit",
		Duration:  0,
		Topic:     agentID,
	}
	data, err := json.Marshal(rule)
	if err != nil {
		log.Printf("Auto-scale: failed to marshal rule for agent %s: %v", agentID, err)
		return
	}
	if err := messaging.Publish("policy.update."+agentID, data); err != nil {
		log.Printf("Auto-scale: failed to publish rule for agent %s: %v", agentID, err)
	}
}

// retractAutoScaleRule removes the temporary rule from agentID by publishing
// a delete event for autoScaleRuleID to policy.delete.<agentID>.
func retractAutoScaleRule(agentID string) {
	data, err := json.Marshal(map[string]int{"id": autoScaleRuleID})
	if err != nil {
		log.Printf("Auto-scale: failed to marshal delete for agent %s: %v", agentID, err)
		return
	}
	if err := messaging.Publish("policy.delete."+agentID, data); err != nil {
		log.Printf("Auto-scale: failed to publish delete for agent %s: %v", agentID, err)
	}
}

// saveSystemMetrics inserts system performance data into the database
func saveSystemMetrics(agentID string, metrics models.SystemMetrics) {
	_, err := db.DB.Exec(`
		INSERT INTO system_metrics (
			time, agent_id, cpu_percent, memory_percent, memory_used_mb, memory_total_mb,
			disk_used_gb, disk_total_gb, disk_percent, net_bytes_sent, net_bytes_recv
		) VALUES (NOW(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		agentID,
		metrics.CPUPercent,
		metrics.MemoryPercent,
		metrics.MemoryUsedMB,
		metrics.MemoryTotalMB,
		metrics.DiskUsedGB,
		metrics.DiskTotalGB,
		metrics.DiskPercent,
		metrics.NetBytesSent,
		metrics.NetBytesRecv,
	)
	if err != nil {
		log.Printf("Failed to save system metrics for agent %s: %v", agentID, err)
	}
}
