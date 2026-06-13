// Package classifier implements an autonomous IP classification engine based on
// Z-score anomaly detection. It continuously evaluates per-IP traffic behaviour
// against a rolling 24-hour baseline and reclassifies IPs as TRUSTED, NORMAL,
// or SUSPICIOUS without any manual administration.
//
// Classification rules:
//
//   - TRUSTED  — at least MinTrustedSamples data points with a coefficient of
//     variation ≤ MaxCV and a current Z-score ≤ ZTrust. Whitelisted in the
//     eBPF bypass_list so all traffic passes without enforcement.
//
//   - SUSPICIOUS — at least MinBaseSamples data points with a current Z-score
//     ≥ ZSuspicious. Rate-limited or blocked proportional to the Z-score:
//     3 ≤ z < 4 → lenient cap (1.5 × mean), 4 ≤ z < 5 → tight cap (0.5 × mean),
//     z ≥ 5 → block 60 s.
//
//   - NORMAL — everything else (sufficient history, Z-score between thresholds).
//
//   - UNKNOWN — insufficient history to decide.
//
// Every decision is logged to ip_classification_log and the latest state is
// upserted into ip_classifications. Whitelist changes are published via NATS
// on "whitelist.update" so agents apply them directly in their eBPF maps.
package classifier

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
)

// Classification thresholds — tuned so the system is conservative about
// granting trust and fast to revoke it on anomaly.
const (
	// MinBaseSamples is the minimum number of 10-second data points required
	// before the classifier will produce any verdict other than UNKNOWN.
	// 18 points ≈ 3 minutes of traffic.
	MinBaseSamples = 18

	// MinTrustedSamples is the minimum data points required before an IP can
	// be promoted to TRUSTED. 360 points ≈ 1 hour of consistent traffic.
	MinTrustedSamples = 360

	// MaxCV is the maximum coefficient of variation (stddev/mean) allowed for
	// a TRUSTED IP. A CV > 0.5 means the traffic rate is too bursty to trust.
	MaxCV = 0.5

	// ZTrust is the Z-score ceiling for the TRUSTED classification.
	// Current behaviour must be within 1.5 standard deviations of the baseline.
	ZTrust = 1.5

	// ZSuspicious is the Z-score floor that triggers SUSPICIOUS classification.
	ZSuspicious = 3.0

	// ZBlock is the Z-score above which a SUSPICIOUS IP is immediately blocked.
	ZBlock = 5.0

	// classifierInterval is how often the full classification cycle runs.
	classifierInterval = 60 * time.Second

	// recentWindow controls how many recent data points define "current behaviour".
	recentWindow = 3
)

// ipBaseline holds the statistical properties of an IP's historical traffic.
type ipBaseline struct {
	SampleCount   int
	MeanRate      float64
	StddevRate    float64
	MeanLatency   float64
	StddevLatency float64
	// CurrentRate is the average req/s across the most recent recentWindow rows.
	CurrentRate float64
}

// Start launches the background classification loop. It returns immediately;
// use ctx cancellation to stop it.
func Start() {
	if err := messaging.RespondToRequests("whitelist.fetch", handleFetchRequest); err != nil {
		log.Printf("Classifier: could not register whitelist.fetch handler: %v", err)
	}

	go func() {
		// Wait one interval before the first classification cycle so the DB
		// has enough data to compute meaningful baselines.
		time.Sleep(classifierInterval)

		ticker := time.NewTicker(classifierInterval)
		defer ticker.Stop()

		for range ticker.C {
			runCycle()
		}
	}()
	log.Println("Classifier: autonomous IP classification engine started (interval 60s)")
}

// handleFetchRequest responds to an agent's whitelist.fetch request with the
// trusted IPs that the requesting agent has actually seen in the last 24 h.
// The request body must contain {"agent_id": "<id>"}.
func handleFetchRequest(req []byte) []byte {
	var body struct {
		AgentID string `json:"agent_id"`
	}
	json.Unmarshal(req, &body)

	// Return only IPs that are whitelisted AND have been seen by this agent.
	// Agents that have never seen an IP should not get it in their bypass list.
	rows, err := db.DB.Query(`
		SELECT DISTINCT ic.ip::text
		FROM ip_classifications ic
		JOIN client_stats cs ON cs.ip = ic.ip
		WHERE ic.whitelisted = TRUE
		  AND cs.agent_id   = $1
		  AND cs.time       > NOW() - INTERVAL '24 hours'`,
		body.AgentID)
	if err != nil {
		log.Printf("Classifier: whitelist.fetch query error: %v", err)
		data, _ := json.Marshal(models.WhitelistFetchResponse{IPs: []string{}})
		return data
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err == nil {
			ips = append(ips, ip)
		}
	}
	if ips == nil {
		ips = []string{}
	}
	data, _ := json.Marshal(models.WhitelistFetchResponse{IPs: ips})
	return data
}

// runCycle queries all active IPs and reclassifies each one.
func runCycle() {
	rows, err := db.DB.Query(
		`SELECT DISTINCT ip::text
		 FROM client_stats
		 WHERE time > NOW() - INTERVAL '24 hours'`)
	if err != nil {
		log.Printf("Classifier: active-IP query error: %v", err)
		return
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err == nil {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return
	}

	log.Printf("Classifier: evaluating %d active IPs", len(ips))
	for _, ip := range ips {
		classifyIP(ip)
	}
}

// classifyIP fetches the baseline for ip, computes the Z-score, decides the
// classification, takes the appropriate enforcement action, and logs the result.
func classifyIP(ip string) {
	bl, err := fetchBaseline(ip)
	if err != nil {
		log.Printf("Classifier: baseline error for %s: %v", ip, err)
		return
	}

	// Previous classification (for detecting state transitions).
	var prevClass string
	var wasWhitelisted bool
	row := db.DB.QueryRow(
		`SELECT classification, whitelisted FROM ip_classifications WHERE ip = $1`, ip)
	_ = row.Scan(&prevClass, &wasWhitelisted)

	// Classify.
	class, action, z, rateLimit, reason := decide(bl, wasWhitelisted)

	// Persist latest state.
	upsertClassification(ip, class, z, bl, wasWhitelisted, reason)

	// Log every cycle (not just on change) for a full audit trail.
	logEntry(ip, class, z, bl, action, rateLimit, reason)

	// Only publish NATS messages and log state-change events on transitions
	// to keep NATS traffic low.
	if class == prevClass {
		return
	}

	log.Printf("Classifier: %s  %s→%s  z=%.2f  %s", ip, prevClass, class, z, reason)

	switch action {
	case "whitelist_add":
		publishWhitelistUpdate(ip, "add", reason)
		updateWhitelistedFlag(ip, true)

	case "whitelist_remove":
		if wasWhitelisted {
			publishWhitelistUpdate(ip, "remove", reason)
			updateWhitelistedFlag(ip, false)
		}

	case "rate_limit":
		publishEnforcementRule(ip, rateLimit, reason)

	case "block":
		publishBlockRule(ip, reason)
	}
}

// decide runs the classification logic and returns the classification label,
// Z-score, enforcement action, rate limit (if any), and a human-readable reason.
func decide(bl *ipBaseline, wasWhitelisted bool) (class, action string, z float64, rateLimit int, reason string) {
	z = zScore(bl.CurrentRate, bl.MeanRate, bl.StddevRate)

	if bl.SampleCount < MinBaseSamples {
		return models.ClassUnknown, "no_change", z, 0,
			fmt.Sprintf("insufficient history (%d/%d samples)", bl.SampleCount, MinBaseSamples)
	}

	switch {
	case z >= ZBlock:
		action = "block"
		class = models.ClassSuspicious
		reason = fmt.Sprintf("z=%.2f ≥ %.1f (severe anomaly); blocking 60s", z, ZBlock)

	case z >= ZSuspicious:
		class = models.ClassSuspicious
		// Proportional rate limit: steeper the z-score, tighter the cap.
		if z < 4.0 {
			rateLimit = max1(int(math.Ceil(bl.MeanRate*1.5)), 1)
			reason = fmt.Sprintf("z=%.2f ≥ %.1f; lenient cap at %d req/s (1.5× mean)", z, ZSuspicious, rateLimit)
		} else {
			rateLimit = max1(int(math.Ceil(bl.MeanRate*0.8)), 1)
			reason = fmt.Sprintf("z=%.2f ≥ 4.0; tight cap at %d req/s (0.8× mean)", z, rateLimit)
		}
		action = "rate_limit"
		if wasWhitelisted {
			action = "whitelist_remove"
			reason = "removed from whitelist: " + reason
		}

	case bl.SampleCount >= MinTrustedSamples && z <= ZTrust && cv(bl) <= MaxCV:
		class = models.ClassTrusted
		if wasWhitelisted {
			action = "no_change"
			reason = fmt.Sprintf("z=%.2f ≤ %.1f, cv=%.2f ≤ %.1f — stable; remains trusted",
				z, ZTrust, cv(bl), MaxCV)
		} else {
			action = "whitelist_add"
			reason = fmt.Sprintf("z=%.2f ≤ %.1f, cv=%.2f ≤ %.1f, %d samples — promoting to trusted",
				z, ZTrust, cv(bl), MaxCV, bl.SampleCount)
		}

	default:
		class = models.ClassNormal
		action = "no_change"
		reason = fmt.Sprintf("z=%.2f within normal range (samples=%d)", z, bl.SampleCount)
		if wasWhitelisted {
			// Was trusted but no longer meets criteria — demote quietly.
			action = "whitelist_remove"
			reason = fmt.Sprintf("z=%.2f or cv=%.2f exceeds trust thresholds — demoting from trusted",
				z, cv(bl))
		}
	}
	return class, action, z, rateLimit, reason
}

// fetchBaseline queries TimescaleDB for the 24-hour rolling statistics and
// the most recent recentWindow req/s values for ip.
func fetchBaseline(ip string) (*ipBaseline, error) {
	bl := &ipBaseline{}

	row := db.DB.QueryRow(`
		SELECT
			COUNT(*)                               AS sample_count,
			COALESCE(AVG(req_per_sec),    0)       AS mean_rate,
			COALESCE(STDDEV(req_per_sec), 0)       AS stddev_rate,
			COALESCE(AVG(avg_latency_us), 0)       AS mean_latency,
			COALESCE(STDDEV(avg_latency_us), 0)    AS stddev_latency
		FROM client_stats
		WHERE ip = $1
		  AND time > NOW() - INTERVAL '24 hours'`, ip)

	if err := row.Scan(
		&bl.SampleCount,
		&bl.MeanRate,
		&bl.StddevRate,
		&bl.MeanLatency,
		&bl.StddevLatency,
	); err != nil {
		return nil, fmt.Errorf("baseline scan: %w", err)
	}

	// Recent behaviour: average over the last recentWindow rows.
	row2 := db.DB.QueryRow(`
		SELECT COALESCE(AVG(req_per_sec), 0)
		FROM (
			SELECT req_per_sec
			FROM client_stats
			WHERE ip = $1
			  AND time > NOW() - INTERVAL '2 minutes'
			ORDER BY time DESC
			LIMIT $2
		) sub`, ip, recentWindow)

	if err := row2.Scan(&bl.CurrentRate); err != nil {
		return nil, fmt.Errorf("current-rate scan: %w", err)
	}

	return bl, nil
}

// upsertClassification writes the current classification to ip_classifications.
func upsertClassification(ip, class string, z float64, bl *ipBaseline, whitelisted bool, reason string) {
	newWhitelisted := whitelisted
	if class == models.ClassTrusted {
		newWhitelisted = true
	} else if class == models.ClassSuspicious || class == models.ClassNormal {
		newWhitelisted = false
	}

	_, err := db.DB.Exec(`
		INSERT INTO ip_classifications
			(ip, classification, z_score, sample_count, mean_rate, stddev_rate,
			 current_rate, mean_latency, stddev_latency, whitelisted, last_updated, reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), $11)
		ON CONFLICT (ip) DO UPDATE SET
			classification  = EXCLUDED.classification,
			z_score         = EXCLUDED.z_score,
			sample_count    = EXCLUDED.sample_count,
			mean_rate       = EXCLUDED.mean_rate,
			stddev_rate     = EXCLUDED.stddev_rate,
			current_rate    = EXCLUDED.current_rate,
			mean_latency    = EXCLUDED.mean_latency,
			stddev_latency  = EXCLUDED.stddev_latency,
			whitelisted     = EXCLUDED.whitelisted,
			last_updated    = EXCLUDED.last_updated,
			reason          = EXCLUDED.reason`,
		ip, class, z, bl.SampleCount,
		bl.MeanRate, bl.StddevRate, bl.CurrentRate,
		bl.MeanLatency, bl.StddevLatency,
		newWhitelisted, reason,
	)
	if err != nil {
		log.Printf("Classifier: upsert error for %s: %v", ip, err)
	}
}

// updateWhitelistedFlag flips only the whitelisted column without touching the
// rest of the row (used after NATS publish to keep the DB in sync).
func updateWhitelistedFlag(ip string, whitelisted bool) {
	_, err := db.DB.Exec(
		`UPDATE ip_classifications SET whitelisted = $2 WHERE ip = $1`, ip, whitelisted)
	if err != nil {
		log.Printf("Classifier: whitelist flag update error for %s: %v", ip, err)
	}
}

// logEntry appends a row to ip_classification_log.
func logEntry(ip, class string, z float64, bl *ipBaseline, action string, rateLimit int, reason string) {
	_, err := db.DB.Exec(`
		INSERT INTO ip_classification_log
			(time, ip, classification, z_score, sample_count, mean_rate, current_rate, action, rate_limit, reason)
		VALUES (NOW(), $1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		ip, class, z, bl.SampleCount, bl.MeanRate, bl.CurrentRate, action, rateLimit, reason,
	)
	if err != nil {
		log.Printf("Classifier: log error for %s: %v", ip, err)
	}
}

// publishWhitelistUpdate sends a whitelist add/remove event only to agents
// that have actually observed this IP in the last 24 h. Publishing per-agent
// (whitelist.update.<agentID>) avoids whitelisting IPs on agents that have no
// traffic history for them.
func publishWhitelistUpdate(ip, action, reason string) {
	agents, err := agentsForIP(ip)
	if err != nil {
		log.Printf("Classifier: could not look up agents for %s: %v", ip, err)
		return
	}
	payload := models.WhitelistUpdate{IP: ip, Action: action, Reason: reason}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Classifier: marshal whitelist update for %s: %v", ip, err)
		return
	}
	for _, agentID := range agents {
		topic := "whitelist.update." + agentID
		if err := messaging.Publish(topic, data); err != nil {
			log.Printf("Classifier: publish %s for %s: %v", topic, ip, err)
		}
	}
}

// agentsForIP returns the IDs of all agents that have seen ip in the last 24 h.
func agentsForIP(ip string) ([]string, error) {
	rows, err := db.DB.Query(`
		SELECT DISTINCT agent_id
		FROM client_stats
		WHERE ip   = $1
		  AND time > NOW() - INTERVAL '24 hours'`, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var agents []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			agents = append(agents, id)
		}
	}
	return agents, rows.Err()
}

// publishEnforcementRule sends an agent-targeted rate-limit policy for ip.
// Uses the sentinel ID -2 so it can be cleanly replaced on the next cycle.
func publishEnforcementRule(ip string, rateLimit int, reason string) {
	rule := models.PolicyRule{
		ID:        -2,
		Name:      fmt.Sprintf("classifier-ratelimit-%s", ip),
		Threshold: rateLimit,
		Action:    "rate_limit",
		Duration:  0,
		Topic:     ip,
	}
	data, _ := json.Marshal(rule)
	if err := messaging.Publish("policy.update."+ip, data); err != nil {
		log.Printf("Classifier: publish rate-limit rule for %s: %v", ip, err)
	}
}

// publishBlockRule sends a 60-second block rule for ip.
func publishBlockRule(ip, reason string) {
	rule := models.PolicyRule{
		ID:        -2,
		Name:      fmt.Sprintf("classifier-block-%s", ip),
		Threshold: 0,
		Action:    "block",
		Duration:  60,
		Topic:     ip,
	}
	data, _ := json.Marshal(rule)
	if err := messaging.Publish("policy.update."+ip, data); err != nil {
		log.Printf("Classifier: publish block rule for %s: %v", ip, err)
	}
}

// minCVFloor mirrors the adaptive scaler's floor: stddev is never allowed to
// fall below 10 % of mean so that very stable IPs don't get huge z-scores from
// tiny absolute fluctuations in request rate.
const minCVFloor = 0.10

// zScore computes |value − mean| / stddev with a stddev floor of 10 % of mean.
// Returns 0 when mean is 0.
func zScore(value, mean, stddev float64) float64 {
	if mean == 0 {
		return 0
	}
	floor := mean * minCVFloor
	if stddev < floor {
		stddev = floor
	}
	return math.Abs(value-mean) / stddev
}

// cv returns the coefficient of variation (stddev / mean). Returns 0 when mean
// is 0 to avoid division by zero on IPs with no measurable traffic.
func cv(bl *ipBaseline) float64 {
	if bl.MeanRate == 0 {
		return 0
	}
	return bl.StddevRate / bl.MeanRate
}

// max1 returns x when x >= 1, otherwise 1. Prevents rate limits from being set to 0.
func max1(x, _ int) int {
	if x < 1 {
		return 1
	}
	return x
}
