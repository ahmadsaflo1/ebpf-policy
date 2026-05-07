package api

import (
	"net/http"
	"time"

	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
)

// GetSystemMetrics handles GET /api/system/metrics
// Query params: agent (optional), timerange (optional, default 1h), limit (default 100)
func GetSystemMetrics(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	agent := q.Get("agent")
	timerange := q.Get("timerange")
	if timerange == "" {
		timerange = "1h"
	}
	limit := q.Get("limit")
	if limit == "" {
		limit = "100"
	}

	interval := parseTimerangeToInterval(timerange)

	rows, err := db.DB.Query(`
		SELECT
			agent_id,
			cpu_percent,
			memory_percent,
			memory_used_mb,
			memory_total_mb,
			disk_used_gb,
			disk_total_gb,
			disk_percent,
			net_bytes_sent,
			net_bytes_recv,
			time
		FROM system_metrics
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

	var results []map[string]interface{}
	for rows.Next() {
		var agentID string
		var cpuPercent, memPercent, diskPercent int64
		var memUsedMB, memTotalMB, diskUsedGB, diskTotalGB, netBytesSent, netBytesRecv uint64
		var recordedAt time.Time

		if err := rows.Scan(
			&agentID, &cpuPercent, &memPercent, &memUsedMB, &memTotalMB,
			&diskUsedGB, &diskTotalGB, &diskPercent, &netBytesSent, &netBytesRecv,
			&recordedAt,
		); err != nil {
			continue
		}

		results = append(results, map[string]interface{}{
			"agent_id":         agentID,
			"cpu_percent":      cpuPercent,
			"memory_percent":   memPercent,
			"memory_used_mb":   memUsedMB,
			"memory_total_mb":  memTotalMB,
			"disk_used_gb":     diskUsedGB,
			"disk_total_gb":    diskTotalGB,
			"disk_percent":     diskPercent,
			"net_bytes_sent":   netBytesSent,
			"net_bytes_recv":   netBytesRecv,
			"recorded_at":      recordedAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"count":   len(results),
		"results": results,
	})
}

// GetSystemMetricsAggregated handles GET /api/system/metrics/aggregated
// Returns aggregated system metrics per agent
func GetSystemMetricsAggregated(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	agent := q.Get("agent")
	if agent == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent parameter is required"})
		return
	}

	timerange := q.Get("timerange")
	if timerange == "" {
		timerange = "1h"
	}

	interval := parseTimerangeToInterval(timerange)

	var agentID string
	var avgCPU, maxCPU, avgMem, maxMem, avgDisk, maxDisk int64
	var totalBytesSent, totalBytesRecv uint64
	var totalRecords int

	err := db.DB.QueryRow(`
		SELECT
			agent_id,
			CAST(ROUND(AVG(cpu_percent)) AS INTEGER) as avg_cpu,
			MAX(cpu_percent) as max_cpu,
			CAST(ROUND(AVG(memory_percent)) AS INTEGER) as avg_mem,
			MAX(memory_percent) as max_mem,
			CAST(ROUND(AVG(disk_percent)) AS INTEGER) as avg_disk,
			MAX(disk_percent) as max_disk,
			SUM(net_bytes_sent) as total_bytes_sent,
			SUM(net_bytes_recv) as total_bytes_recv,
			COUNT(*) as total_records
		FROM system_metrics
		WHERE agent_id = $1
		  AND time > NOW() - $2::interval
		GROUP BY agent_id`,
		agent, interval,
	).Scan(
		&agentID, &avgCPU, &maxCPU, &avgMem, &maxMem,
		&avgDisk, &maxDisk, &totalBytesSent, &totalBytesRecv, &totalRecords,
	)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "no system metrics found for this agent in the specified timerange",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent_id":          agentID,
		"timerange":         timerange,
		"total_records":     totalRecords,
		"avg_cpu_percent":   avgCPU,
		"max_cpu_percent":   maxCPU,
		"avg_memory_percent": avgMem,
		"max_memory_percent": maxMem,
		"avg_disk_percent":  avgDisk,
		"max_disk_percent":  maxDisk,
		"total_bytes_sent":  totalBytesSent,
		"total_bytes_recv":  totalBytesRecv,
	})
}