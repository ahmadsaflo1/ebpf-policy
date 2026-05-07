package api

import (
	"net/http"
	"time"

	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
)

// SearchClients handles GET /api/metrics/search
// Query params: ip, agent, limit, offset
func SearchClients(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ip := q.Get("ip")
	agent := q.Get("agent")
	limit := q.Get("limit")
	if limit == "" {
		limit = "100"
	}
	offset := q.Get("offset")
	if offset == "" {
		offset = "0"
	}

	query := `
		SELECT
			agent_id,
			ip::text,
			req_per_sec,
			blocked,
			rate_limited,
			passed,
			avg_latency_us,
			min_latency_us,
			max_latency_us,
			time
		FROM client_stats
		WHERE ($1 = '' OR ip::text LIKE $2)
		  AND ($3 = '' OR agent_id = $4)
		ORDER BY time DESC
		LIMIT $5 OFFSET $6`
	args := []interface{}{ip, "%" + ip + "%", agent, agent, limit, offset}

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	results := []map[string]interface{}{}
	for rows.Next() {
		var agentID, ipAddr string
		var reqPerSec, blocked, rateLimited, passed int
		var avgLatency, minLatency, maxLatency int64
		var recordedAt time.Time

		if err := rows.Scan(&agentID, &ipAddr, &reqPerSec, &blocked, &rateLimited, &passed,
			&avgLatency, &minLatency, &maxLatency, &recordedAt); err != nil {
			continue
		}

		results = append(results, map[string]interface{}{
			"agent_id":       agentID,
			"ip":             ipAddr,
			"req_per_sec":    reqPerSec,
			"blocked":        blocked,
			"rate_limited":   rateLimited,
			"passed":         passed,
			"avg_latency_us": avgLatency,
			"min_latency_us": minLatency,
			"max_latency_us": maxLatency,
			"recorded_at":    recordedAt,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"count":   len(results),
		"results": results,
	})
}

// GetAggregatedMetrics handles GET /api/metrics/aggregated
// Query params: ip (required), timerange (optional, default 1h)
func GetAggregatedMetrics(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ip := q.Get("ip")
	if ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "ip parameter is required"})
		return
	}

	timerange := q.Get("timerange")
	if timerange == "" {
		timerange = "1h"
	}

	interval := parseTimerangeToInterval(timerange)

	var resultIP string
	var totalRecords int
	var avgReqPerSec float64
	var maxReqPerSec, minReqPerSec int
	var totalBlocked, totalRateLimited, totalPassed int
	var avgLatency, minLatency, maxLatency int64
	var firstSeen, lastSeen time.Time

	err := db.DB.QueryRow(`
		SELECT
			ip::text,
			COUNT(*) as total_records,
			AVG(req_per_sec) as avg_req_per_sec,
			MAX(req_per_sec) as max_req_per_sec,
			MIN(req_per_sec) as min_req_per_sec,
			SUM(blocked) as total_blocked,
			SUM(rate_limited) as total_rate_limited,
			SUM(passed) as total_passed,
			CAST(ROUND(AVG(avg_latency_us)) AS BIGINT) as avg_latency,
			MIN(min_latency_us) as min_latency,
			MAX(max_latency_us) as max_latency,
			MIN(time) as first_seen,
			MAX(time) as last_seen
		FROM client_stats
		WHERE ip = $1::inet
		  AND time > NOW() - $2::interval
		GROUP BY ip`,
		ip, interval,
	).Scan(
		&resultIP, &totalRecords, &avgReqPerSec, &maxReqPerSec, &minReqPerSec,
		&totalBlocked, &totalRateLimited, &totalPassed, &avgLatency, &minLatency, &maxLatency,
		&firstSeen, &lastSeen,
	)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "no data found for this IP in the specified timerange",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ip":                  resultIP,
		"timerange":           timerange,
		"total_records":       totalRecords,
		"avg_req_per_sec":     avgReqPerSec,
		"max_req_per_sec":     maxReqPerSec,
		"min_req_per_sec":     minReqPerSec,
		"total_blocked":       totalBlocked,
		"total_rate_limited":  totalRateLimited,
		"total_passed":        totalPassed,
		"avg_latency_us":      avgLatency,
		"min_latency_us":      minLatency,
		"max_latency_us":      maxLatency,
		"first_seen":          firstSeen,
		"last_seen":           lastSeen,
	})
}

// GetTopClients handles GET /api/metrics/top
// Returns top N clients by request rate
// Query params: limit (default 10), timerange (default 1h), order_by (req_per_sec or blocked)
func GetTopClients(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := q.Get("limit")
	if limit == "" {
		limit = "10"
	}
	timerange := q.Get("timerange")
	if timerange == "" {
		timerange = "1h"
	}
	orderBy := q.Get("order_by")
	if orderBy == "" {
		orderBy = "req_per_sec"
	}

	validOrderBy := map[string]string{
		"req_per_sec":  "avg_req_per_sec",
		"blocked":      "total_blocked",
		"rate_limited": "total_rate_limited",
	}

	orderColumn, ok := validOrderBy[orderBy]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "order_by must be 'req_per_sec' or 'blocked'"})
		return
	}

	interval := parseTimerangeToInterval(timerange)

	rows, err := db.DB.Query(`
		SELECT
			ip::text,
			AVG(req_per_sec) as avg_req_per_sec,
			MAX(req_per_sec) as max_req_per_sec,
			SUM(blocked) as total_blocked,
			SUM(rate_limited) as total_rate_limited,
			SUM(passed) as total_passed,
			COUNT(*) as total_records
		FROM client_stats
		WHERE time > NOW() - $1::interval
		GROUP BY ip
		ORDER BY `+orderColumn+` DESC
		LIMIT $2`,
		interval, limit,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	results := []map[string]interface{}{}
	for rows.Next() {
		var ip string
		var avgReq, maxReq float64
		var totalBlocked, totalRateLimited, totalPassed, totalRecords int

		if err := rows.Scan(&ip, &avgReq, &maxReq, &totalBlocked, &totalRateLimited, &totalPassed, &totalRecords); err != nil {
			continue
		}

		results = append(results, map[string]interface{}{
			"ip":                 ip,
			"avg_req_per_sec":    avgReq,
			"max_req_per_sec":    maxReq,
			"total_blocked":      totalBlocked,
			"total_rate_limited": totalRateLimited,
			"total_passed":       totalPassed,
			"total_records":      totalRecords,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"timerange": timerange,
		"order_by":  orderBy,
		"count":     len(results),
		"results":   results,
	})
}

// parseTimerangeToInterval converts "1h" to PostgreSQL interval "1 hour"
func parseTimerangeToInterval(timerange string) string {
	if len(timerange) < 2 {
		return "1 hour"
	}

	value := timerange[:len(timerange)-1]
	unit := timerange[len(timerange)-1:]

	switch unit {
	case "m":
		return value + " minutes"
	case "h":
		return value + " hours"
	case "d":
		return value + " days"
	default:
		return "1 hour"
	}
}
