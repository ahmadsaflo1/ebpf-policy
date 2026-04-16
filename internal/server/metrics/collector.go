package metrics

import (
	"encoding/json"
	"log"
	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
)

// StartCollector initializes the metrics collector to listen for incoming metrics reports from agents and saves them to the database.
func StartCollector(){
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

func saveClientStats(agentID string, stat models.ClientStats) {
	_, err := db.DB.Exec(`
		INSERT INTO client_stats (agent_id, ip, req_per_sec, blocked, passed, recorded_at)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
		agentID, stat.IP, stat.ReqPerSec, stat.Blocked, stat.Passed,
	)

	if err != nil {
		log.Printf("Failed to save client stats for agent %s: %v", agentID, err)
	}
}