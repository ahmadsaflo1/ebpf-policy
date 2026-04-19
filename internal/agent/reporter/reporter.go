package reporter

import (
	"encoding/json"
	"log"
	"time"
	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
)

type Reporter struct {
	agentID	string
	interval time.Duration
	stats  []models.ClientStats
	serverAvailable *bool
}

// New creates a new Reporter instance with the given agent ID.
func New(agentID string, serverAvailable *bool) *Reporter {
	return &Reporter{
		agentID:  agentID,
		interval: 10 * time.Second, // default reporting interval
		stats:    make([]models.ClientStats, 0),
		serverAvailable: serverAvailable,
	}
}

// AddStats adds client stats to the report.
func (r *Reporter) AddStat(stats models.ClientStats) {
	r.stats = append(r.stats, stats)
}

// Start begins the periodic reporting of metrics to the central server.
func (r *Reporter) Start() {
	ticker := time.NewTicker(r.interval)
	go func() {
		for range ticker.C {
			r.send()
		}
	}()
	log.Printf("Reporter started with interval: %s\n", r.interval)
}

// send compiles the current stats into a report and sends it to the central server via NATS.
func (r *Reporter) send() {
	if len(r.stats) == 0 {
		return // nothing to report
	}


    if messaging.NC == nil || !messaging.NC.IsConnected() {
        log.Println("Reporter: NATS not connected — skipping report")
        r.stats = make([]models.ClientStats, 0)
        return
    }

	if !*r.serverAvailable {
        log.Println("Reporter: server not available — skipping report")
        r.stats = make([]models.ClientStats, 0)
        return
    }

	report := models.MetricsReport{
		AgentID: r.agentID,
		Timestamp: time.Now(),
		Clients:   r.stats,
	}

	data, err := json.Marshal(report)
	if err != nil {
		log.Println("Failed to marshal report:", err)
		return
	}

	err = messaging.Publish("metrics.report", data)
	if err != nil {
		log.Println("Failed to publish report:", err)
		return
	}

	log.Printf("Report sent: %d clients\n", len(r.stats))
	r.stats = r.stats[:0] // clear stats after sending
}
