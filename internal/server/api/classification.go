package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
)

// GetClassifications returns the latest autonomous classification state for all
// IPs, optionally filtered by ?classification=trusted|suspicious|normal|unknown.
func GetClassifications(w http.ResponseWriter, r *http.Request) {
	filter := r.URL.Query().Get("classification")
	limitStr := r.URL.Query().Get("limit")
	limit := 200
	if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
		limit = n
	}

	query := `
		SELECT ip::text, classification, z_score, sample_count,
		       mean_rate, stddev_rate, current_rate,
		       mean_latency, stddev_latency, whitelisted, last_updated, reason
		FROM ip_classifications`
	args := []any{}
	if filter != "" {
		query += ` WHERE classification = $1`
		args = append(args, filter)
	}
	query += ` ORDER BY last_updated DESC LIMIT $` + strconv.Itoa(len(args)+1)
	args = append(args, limit)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		http.Error(w, "query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var out []models.IPClassification
	for rows.Next() {
		var c models.IPClassification
		if err := rows.Scan(
			&c.IP, &c.Classification, &c.ZScore, &c.SampleCount,
			&c.MeanRate, &c.StddevRate, &c.CurrentRate,
			&c.MeanLatency, &c.StddevLatency, &c.Whitelisted,
			&c.LastUpdated, &c.Reason,
		); err != nil {
			continue
		}
		out = append(out, c)
	}
	if out == nil {
		out = []models.IPClassification{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// GetClassification returns the latest classification for a single IP passed
// as a query parameter: ?ip=1.2.3.4
func GetClassification(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "ip parameter required", http.StatusBadRequest)
		return
	}

	var c models.IPClassification
	row := db.DB.QueryRow(`
		SELECT ip::text, classification, z_score, sample_count,
		       mean_rate, stddev_rate, current_rate,
		       mean_latency, stddev_latency, whitelisted, last_updated, reason
		FROM ip_classifications
		WHERE ip = $1`, ip)

	if err := row.Scan(
		&c.IP, &c.Classification, &c.ZScore, &c.SampleCount,
		&c.MeanRate, &c.StddevRate, &c.CurrentRate,
		&c.MeanLatency, &c.StddevLatency, &c.Whitelisted,
		&c.LastUpdated, &c.Reason,
	); err != nil {
		http.Error(w, "IP not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(c)
}

// GetClassificationLog returns the classification audit log, optionally filtered
// by ?ip=1.2.3.4 and paginated via ?limit=N&offset=M.
func GetClassificationLog(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 100
	if n, err := strconv.Atoi(limitStr); err == nil && n > 0 {
		limit = n
	}
	offset := 0
	if n, err := strconv.Atoi(offsetStr); err == nil && n >= 0 {
		offset = n
	}

	query := `
		SELECT time, ip::text, classification, z_score, sample_count,
		       mean_rate, current_rate, action, rate_limit, reason
		FROM ip_classification_log`
	args := []any{}
	if ip != "" {
		query += ` WHERE ip = $1`
		args = append(args, ip)
	}
	query += ` ORDER BY time DESC LIMIT $` + strconv.Itoa(len(args)+1) +
		` OFFSET $` + strconv.Itoa(len(args)+2)
	args = append(args, limit, offset)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		http.Error(w, "query error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var out []models.ClassificationLog
	for rows.Next() {
		var e models.ClassificationLog
		if err := rows.Scan(
			&e.Time, &e.IP, &e.Classification, &e.ZScore, &e.SampleCount,
			&e.MeanRate, &e.CurrentRate, &e.Action, &e.RateLimit, &e.Reason,
		); err != nil {
			continue
		}
		out = append(out, e)
	}
	if out == nil {
		out = []models.ClassificationLog{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}
