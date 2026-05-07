// Package metrics subscribes to agent telemetry reports and persists them in
// the database for later inspection.
package metrics

import (
	"encoding/json"
	"log"

	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
)

// StartCollector subscribes to "metrics.report" on NATS and persists each
// incoming MetricsReport's per-IP stats to the client_stats table.
func StartCollector() {
	err := messaging.Subscribe("metrics.report", func(data []byte) {
		var report models.MetricsReport
		if err := json.Unmarshal(data, &report); err != nil {
			log.Printf("Error unmarshaling metric report: %v", err)
			return
		}

		log.Printf("Received metric report from agent %s with %d Clients\n",
			report.AgentID, len(report.Clients))

		for _, client := range report.Clients {
			saveClientStats(report.AgentID, client)
		}
	})

	if err != nil {
		log.Fatalf("Failed to subscribe to metrics reports: %v", err)
		return
	}

	log.Println("Metrics collector started and subscribed to metrics.reports")
}

// saveClientStats inserts a single per-IP stat row into the client_stats table.
func saveClientStats(agentID string, stat models.ClientStats) {
	_, err := db.DB.Exec(`
		INSERT INTO client_stats (
			time, agent_id, ip, req_per_sec, blocked, rate_limited, passed,
			avg_latency_us, min_latency_us, max_latency_us
		) VALUES (NOW(), $1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		agentID,
		stat.IP,
		stat.ReqPerSec,
		stat.Blocked,
		stat.RateLimited,
		stat.Passed,
		stat.AvgLatencyUs,
		stat.MinLatencyUs,
		stat.MaxLatencyUs,
	)
	if err != nil {
		log.Printf("Failed to save client stats for agent %s: %v", agentID, err)
	}
}
