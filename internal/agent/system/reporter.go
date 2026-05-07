package system

import (
	"encoding/json"
	"log"
	"time"

	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
)

// Reporter sends system metrics to the server via NATS
type Reporter struct {
	agentID         string
	serverAvailable *bool
}

// NewReporter creates a new system metrics reporter
func NewReporter(agentID string, serverAvailable *bool) *Reporter {
	return &Reporter{
		agentID:         agentID,
		serverAvailable: serverAvailable,
	}
}

// Report sends system metrics to the server
func (r *Reporter) Report(metrics models.SystemMetrics) {
	if messaging.NC == nil || !messaging.NC.IsConnected() {
		log.Println("System Reporter: NATS not connected — skipping report")
		return
	}

	if !*r.serverAvailable {
		log.Println("System Reporter: server not available — skipping report")
		return
	}

	report := models.SystemMetricsReport{
		AgentID:   r.agentID,
		Timestamp: time.Now(),
		Metrics:   metrics,
	}

	data, err := json.Marshal(report)
	if err != nil {
		log.Println("Failed to marshal system metrics report:", err)
		return
	}

	err = messaging.Publish("system.metrics", data)
	if err != nil {
		log.Println("Failed to publish system metrics:", err)
		return
	}

	log.Printf("System metrics sent: CPU=%.1f%%, Mem=%.1f%%, Disk=%.1f%%\n",
		float64(metrics.CPUPercent)/1000, float64(metrics.MemoryPercent)/1000, float64(metrics.DiskPercent)/1000)
}