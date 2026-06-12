package metrics

import (
	"encoding/json"
	"log"

	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
)

// autoScaleRuleID is the sentinel rule ID for adaptive load-scaling rules.
// Negative to avoid conflicts with database-allocated IDs.
const autoScaleRuleID = -1

// StartSystemCollector subscribes to "system.metrics" on NATS, persists each
// incoming SystemMetricsReport, and triggers adaptive scaling analysis.
func StartSystemCollector() {
	err := messaging.Subscribe("system.metrics", func(data []byte) {
		var report models.SystemMetricsReport
		if err := json.Unmarshal(data, &report); err != nil {
			log.Printf("Error unmarshaling system metrics report: %v", err)
			return
		}

		log.Printf("Received system metrics from agent %s: CPU=%.1f%%, Mem=%.1f%%, Disk=%.1f%%\n",
			report.AgentID,
			float64(report.Metrics.CPUPercent)/1000,
			float64(report.Metrics.MemoryPercent)/1000,
			float64(report.Metrics.DiskPercent)/1000)

		saveSystemMetrics(report.AgentID, report.Metrics)
		ProcessAdaptive(report)
	})

	if err != nil {
		log.Fatalf("Failed to subscribe to system metrics: %v", err)
	}

	log.Println("System metrics collector started and subscribed to system.metrics")
}

// saveSystemMetrics inserts system performance data into the database.
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
