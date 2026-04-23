package api

import (
	"net/http"
	"time"

	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
	"github.com/gin-gonic/gin"
)

// GetSystemMetrics handles GET /api/system/metrics
// Query params: agent (optional), timerange (optional, default 1h), limit (default 100)
func GetSystemMetrics(c *gin.Context) {
	agent := c.Query("agent")
	timerange := c.DefaultQuery("timerange", "1h")
	limit := c.DefaultQuery("limit", "100")

	duration, err := parseDuration(timerange)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid timerange format"})
		return
	}

	query := `
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
			recorded_at
		FROM system_metrics
		WHERE (? = '' OR agent_id = ?)
		  AND recorded_at > datetime('now', ?)
		ORDER BY recorded_at DESC
		LIMIT ?`

	rows, err := db.DB.Query(query, agent, agent, duration, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var agentID, recordedAtStr string
		var cpuPercent, memPercent, diskPercent float64
		var memUsedMB, memTotalMB, diskUsedGB, diskTotalGB, netBytesSent, netBytesRecv uint64

		if err := rows.Scan(
			&agentID, &cpuPercent, &memPercent, &memUsedMB, &memTotalMB,
			&diskUsedGB, &diskTotalGB, &diskPercent, &netBytesSent, &netBytesRecv,
			&recordedAtStr,
		); err != nil {
			continue
		}

		recordedAt, _ := time.Parse("2006-01-02 15:04:05", recordedAtStr)

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

	c.JSON(http.StatusOK, gin.H{
		"count":   len(results),
		"results": results,
	})
}

// GetSystemMetricsAggregated handles GET /api/system/metrics/aggregated
// Returns aggregated system metrics per agent
func GetSystemMetricsAggregated(c *gin.Context) {
	agent := c.Query("agent")
	if agent == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent parameter is required"})
		return
	}

	timerange := c.DefaultQuery("timerange", "1h")
	duration, err := parseDuration(timerange)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid timerange format"})
		return
	}

	query := `
		SELECT 
			agent_id,
			AVG(cpu_percent) as avg_cpu,
			MAX(cpu_percent) as max_cpu,
			AVG(memory_percent) as avg_mem,
			MAX(memory_percent) as max_mem,
			AVG(disk_percent) as avg_disk,
			MAX(disk_percent) as max_disk,
			SUM(net_bytes_sent) as total_bytes_sent,
			SUM(net_bytes_recv) as total_bytes_recv,
			COUNT(*) as total_records
		FROM system_metrics
		WHERE agent_id = ?
		  AND recorded_at > datetime('now', ?)
		GROUP BY agent_id`

	var agentID string
	var avgCPU, maxCPU, avgMem, maxMem, avgDisk, maxDisk float64
	var totalBytesSent, totalBytesRecv uint64
	var totalRecords int

	err = db.DB.QueryRow(query, agent, duration).Scan(
		&agentID, &avgCPU, &maxCPU, &avgMem, &maxMem,
		&avgDisk, &maxDisk, &totalBytesSent, &totalBytesRecv, &totalRecords,
	)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "no system metrics found for this agent in the specified timerange",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
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