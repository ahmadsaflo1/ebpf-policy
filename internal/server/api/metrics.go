package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
	"github.com/gin-gonic/gin"
)

// ClientMetric represents aggregated metrics for a client IP
type ClientMetric struct {
	IP            string    `json:"ip"`
	AgentID       string    `json:"agent_id"`
	AvgReqPerSec  float64   `json:"avg_req_per_sec"`
	MaxReqPerSec  int       `json:"max_req_per_sec"`
	TotalBlocked  int       `json:"total_blocked"`
	TotalPassed   int       `json:"total_passed"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

// SearchClients handles GET /api/metrics/search
// Query params: ip, agent, limit, offset
func SearchClients(c *gin.Context) {
	ip := c.Query("ip")
	agent := c.Query("agent")
	limit := c.DefaultQuery("limit", "100")
	offset := c.DefaultQuery("offset", "0")

	query := `
		SELECT agent_id, ip, req_per_sec, blocked, passed, recorded_at
		FROM client_stats
		WHERE (? = '' OR ip LIKE ?)
		  AND (? = '' OR agent_id = ?)
		ORDER BY recorded_at DESC
		LIMIT ? OFFSET ?`

	rows, err := db.DB.Query(query, 
		ip, "%"+ip+"%", 
		agent, agent, 
		limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var agentID, ipAddr string
		var reqPerSec, blocked, passed int
		var recordedAt time.Time

		if err := rows.Scan(&agentID, &ipAddr, &reqPerSec, &blocked, &passed, &recordedAt); err != nil {
			continue
		}

		results = append(results, map[string]interface{}{
			"agent_id":    agentID,
			"ip":          ipAddr,
			"req_per_sec": reqPerSec,
			"blocked":     blocked,
			"passed":      passed,
			"recorded_at": recordedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"count":   len(results),
		"results": results,
	})
}

// GetAggregatedMetrics handles GET /api/metrics/aggregated
// Query params: ip (required), timerange (optional, default 1h)
func GetAggregatedMetrics(c *gin.Context) {
	ip := c.Query("ip")
	if ip == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ip parameter is required"})
		return
	}

	timerange := c.DefaultQuery("timerange", "1h")
	
	// Parse timerange to SQL interval
	duration, err := parseDuration(timerange)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid timerange format"})
		return
	}

	query := `
		SELECT 
			ip,
			COUNT(*) as total_records,
			AVG(req_per_sec) as avg_req_per_sec,
			MAX(req_per_sec) as max_req_per_sec,
			MIN(req_per_sec) as min_req_per_sec,
			SUM(blocked) as total_blocked,
			SUM(passed) as total_passed,
			MIN(recorded_at) as first_seen,
			MAX(recorded_at) as last_seen
		FROM client_stats
		WHERE ip = ? 
		  AND recorded_at > datetime('now', ?)
		GROUP BY ip`

	var resultIP string
	var totalRecords int
	var avgReqPerSec float64
	var maxReqPerSec, minReqPerSec int
	var totalBlocked, totalPassed int
	var firstSeenStr, lastSeenStr string  // ✅ Ändrat till string

	err = db.DB.QueryRow(query, ip, duration).Scan(
		&resultIP,
		&totalRecords,
		&avgReqPerSec,
		&maxReqPerSec,
		&minReqPerSec,
		&totalBlocked,
		&totalPassed,
		&firstSeenStr, 
		&lastSeenStr,   
	)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "no data found for this IP in the specified timerange",
		})
		return
	}

	// ✅ Parse timestamps från strings
	firstSeen, _ := time.Parse("2006-01-02 15:04:05", firstSeenStr)
	lastSeen, _ := time.Parse("2006-01-02 15:04:05", lastSeenStr)

	c.JSON(http.StatusOK, gin.H{
		"ip":              resultIP,
		"timerange":       timerange,
		"total_records":   totalRecords,
		"avg_req_per_sec": avgReqPerSec,
		"max_req_per_sec": maxReqPerSec,
		"min_req_per_sec": minReqPerSec,
		"total_blocked":   totalBlocked,
		"total_passed":    totalPassed,
		"first_seen":      firstSeen,
		"last_seen":       lastSeen,
	})
}

// GetTopClients handles GET /api/metrics/top
// Returns top N clients by request rate
// Query params: limit (default 10), timerange (default 1h), order_by (req_per_sec or blocked)
func GetTopClients(c *gin.Context) {
	limit := c.DefaultQuery("limit", "10")
	timerange := c.DefaultQuery("timerange", "1h")
	orderBy := c.DefaultQuery("order_by", "req_per_sec")

	duration, err := parseDuration(timerange)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid timerange format"})
		return
	}

	// Validate order_by
	validOrderBy := map[string]string{
		"req_per_sec": "avg_req_per_sec",
		"blocked":     "total_blocked",
	}
	
	orderColumn, ok := validOrderBy[orderBy]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "order_by must be 'req_per_sec' or 'blocked'"})
		return
	}

	query := `
		SELECT 
			ip,
			AVG(req_per_sec) as avg_req_per_sec,
			MAX(req_per_sec) as max_req_per_sec,
			SUM(blocked) as total_blocked,
			SUM(passed) as total_passed,
			COUNT(*) as total_records
		FROM client_stats
		WHERE recorded_at > datetime('now', ?)
		GROUP BY ip
		ORDER BY ` + orderColumn + ` DESC
		LIMIT ?`

	rows, err := db.DB.Query(query, duration, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var ip string
		var avgReq, maxReq float64
		var totalBlocked, totalPassed, totalRecords int

		if err := rows.Scan(&ip, &avgReq, &maxReq, &totalBlocked, &totalPassed, &totalRecords); err != nil {
			continue
		}

		results = append(results, map[string]interface{}{
			"ip":              ip,
			"avg_req_per_sec": avgReq,
			"max_req_per_sec": maxReq,
			"total_blocked":   totalBlocked,
			"total_passed":    totalPassed,
			"total_records":   totalRecords,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"timerange": timerange,
		"order_by":  orderBy,
		"count":     len(results),
		"results":   results,
	})
}

// parseDuration converts human-readable duration to SQLite interval format
// Examples: "1h" -> "-1 hour", "30m" -> "-30 minutes", "7d" -> "-7 days"
func parseDuration(timerange string) (string, error) {
	if len(timerange) < 2 {
		return "", gin.Error{Err: nil}
	}

	value := timerange[:len(timerange)-1]
	unit := timerange[len(timerange)-1:]

	num, err := strconv.Atoi(value)
	if err != nil {
		return "", err
	}

	sqlUnit := ""
	switch unit {
	case "m":
		sqlUnit = "minutes"
	case "h":
		sqlUnit = "hours"
	case "d":
		sqlUnit = "days"
	default:
		return "", gin.Error{Err: nil}
	}

	return "-" + strconv.Itoa(num) + " " + sqlUnit, nil
}