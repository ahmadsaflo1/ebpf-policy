package api

import (
	"net/http"
	"time"

	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
)

// GetScalingDecisions handles GET /api/scaling/decisions.
// Returns adaptive scaling decisions logged to the scaling_decisions table.
// Query params:
//   - agent    — filter by agent_id (optional)
//   - timerange — e.g. "1h", "6h", "24h", "7d" (default: "24h")
//   - limit    — max rows to return (default: 100)
func GetScalingDecisions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	agent := q.Get("agent")
	timerange := q.Get("timerange")
	if timerange == "" {
		timerange = "24h"
	}
	limit := q.Get("limit")
	if limit == "" {
		limit = "100"
	}

	interval := parseTimerangeToInterval(timerange)

	rows, err := db.DB.Query(`
		SELECT time, agent_id, load_index, z_cpu, z_memory, z_disk, z_network, rate_limit, reason
		FROM scaling_decisions
		WHERE ($1 = '' OR agent_id = $2)
		  AND time > NOW() - $3::interval
		ORDER BY time DESC
		LIMIT $4`,
		agent, agent, interval, limit,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	results := []map[string]interface{}{}
	for rows.Next() {
		var (
			t         time.Time
			agentID   string
			loadIndex float64
			zCpu      float64
			zMem      float64
			zDisk     float64
			zNet      float64
			rateLimit int
			reason    string
		)
		if err := rows.Scan(&t, &agentID, &loadIndex, &zCpu, &zMem, &zDisk, &zNet, &rateLimit, &reason); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"time":       t,
			"agent_id":   agentID,
			"load_index": loadIndex,
			"z_cpu":      zCpu,
			"z_memory":   zMem,
			"z_disk":     zDisk,
			"z_network":  zNet,
			"rate_limit": rateLimit,
			"reason":     reason,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"count":   len(results),
		"results": results,
	})
}
