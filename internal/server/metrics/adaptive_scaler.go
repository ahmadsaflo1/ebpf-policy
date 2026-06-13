package metrics

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"sync"
	"time"

	"github.com/ahmadsaflo1/ebpf-policy/internal/messaging"
	"github.com/ahmadsaflo1/ebpf-policy/internal/models"
	"github.com/ahmadsaflo1/ebpf-policy/internal/server/db"
)

// AgentState tracks adaptive scaling state per agent in memory.
type AgentState struct {
	AgentID            string
	LoadIndex          float64
	ActiveRuleLevel    int
	StableCount        int
	LastPublished      time.Time
	LastPublishedIndex float64
	Baseline           map[string]BaselineStat
}

// BaselineStat holds the rolling 24 h mean and standard deviation for one resource.
type BaselineStat struct {
	Mean   float64
	StdDev float64
}

// ScalingDecision is the record persisted to the DB and returned by the API.
type ScalingDecision struct {
	Time      time.Time `json:"time"`
	AgentID   string    `json:"agent_id"`
	LoadIndex float64   `json:"load_index"`
	ZCpu      float64   `json:"z_cpu"`
	ZMemory   float64   `json:"z_memory"`
	ZDisk     float64   `json:"z_disk"`
	ZNetwork  float64   `json:"z_network"`
	RateLimit int       `json:"rate_limit"`
	Reason    string    `json:"reason"`
}

var (
	agentStateMu sync.Mutex
	agentStates  = make(map[string]*AgentState)
)

// levelRateLimit maps rule level (1–4) to its req/s rate limit.
var levelRateLimit = map[int]int{
	1: 400,
	2: 200,
	3: 100,
	4: 50,
}

// indexToLevel maps a combined load index to a rule level (0 = normal, 4 = max).
func indexToLevel(idx float64) int {
	switch {
	case idx <= 30:
		return 0
	case idx <= 50:
		return 1
	case idx <= 70:
		return 2
	case idx <= 90:
		return 3
	default:
		return 4
	}
}

// minCVFloor is the minimum coefficient of variation enforced on stddev before
// computing z-scores. When a resource is very stable (small stddev relative to
// mean), even a tiny absolute change produces an enormous z-score and a
// spurious load_index of 100. A floor of 10 % of mean prevents this: a CPU
// stable at 15 % needs to move by at least 1.5 percentage points before the
// z-score rises above 1.0.
const minCVFloor = 0.10

// zScore computes (value − mean) / stddev with a minimum-stddev floor to
// prevent hypersensitivity on very stable resources. Returns 0 when mean is 0.
func zScore(value, mean, stddev float64) float64 {
	if mean == 0 {
		return 0
	}
	floor := mean * minCVFloor
	if stddev < floor {
		stddev = floor
	}
	return (value - mean) / stddev
}

// computeLoadIndex combines four z-scores into a single 0–100 index.
// Negative z-scores (below-baseline usage) contribute zero.
func computeLoadIndex(zCpu, zMem, zDisk, zNet float64) float64 {
	pos := func(z float64) float64 {
		if z < 0 {
			return 0
		}
		return z
	}
	idx := pos(zCpu)*25 + pos(zMem)*25 + pos(zDisk)*25 + pos(zNet)*25
	if idx > 100 {
		return 100
	}
	return idx
}

// getOrCreateState returns the in-memory AgentState for agentID, creating it on
// first access. Only the map access is guarded; struct mutations are safe because
// the NATS subscriber delivers messages sequentially.
func getOrCreateState(agentID string) *AgentState {
	agentStateMu.Lock()
	defer agentStateMu.Unlock()
	if s, ok := agentStates[agentID]; ok {
		return s
	}
	s := &AgentState{
		AgentID:  agentID,
		Baseline: make(map[string]BaselineStat),
	}
	agentStates[agentID] = s
	return s
}

// fetchBaseline queries a 24 h rolling window of system_metrics for agentID and
// returns per-resource mean/stddev. Returns nil on query error.
func fetchBaseline(agentID string) map[string]BaselineStat {
	row := db.DB.QueryRow(`
		SELECT
			COALESCE(AVG(cpu_percent),                        0) AS avg_cpu,
			COALESCE(STDDEV(cpu_percent),                     0) AS std_cpu,
			COALESCE(AVG(memory_percent),                     0) AS avg_mem,
			COALESCE(STDDEV(memory_percent),                  0) AS std_mem,
			COALESCE(AVG(disk_percent),                       0) AS avg_disk,
			COALESCE(STDDEV(disk_percent),                    0) AS std_disk,
			COALESCE(AVG(net_bytes_sent + net_bytes_recv),    0) AS avg_net,
			COALESCE(STDDEV(net_bytes_sent + net_bytes_recv), 0) AS std_net
		FROM system_metrics
		WHERE agent_id = $1
		  AND time > NOW() - INTERVAL '24 hours'`,
		agentID,
	)
	var (
		avgCpu, stdCpu   float64
		avgMem, stdMem   float64
		avgDisk, stdDisk float64
		avgNet, stdNet   float64
	)
	if err := row.Scan(&avgCpu, &stdCpu, &avgMem, &stdMem, &avgDisk, &stdDisk, &avgNet, &stdNet); err != nil {
		log.Printf("Adaptive: baseline query error for %s: %v", agentID, err)
		return nil
	}
	return map[string]BaselineStat{
		"cpu":     {Mean: avgCpu, StdDev: stdCpu},
		"memory":  {Mean: avgMem, StdDev: stdMem},
		"disk":    {Mean: avgDisk, StdDev: stdDisk},
		"network": {Mean: avgNet, StdDev: stdNet},
	}
}

// ProcessAdaptive evaluates Z-score–based adaptive scaling for one incoming
// system report. Must be called after saveSystemMetrics so the DB already
// contains the new row (it is included in the 24 h baseline window).
func ProcessAdaptive(report models.SystemMetricsReport) {
	agentID := report.AgentID
	state := getOrCreateState(agentID)

	baseline := fetchBaseline(agentID)
	if baseline == nil {
		return
	}

	m := report.Metrics
	zCpu := zScore(float64(m.CPUPercent), baseline["cpu"].Mean, baseline["cpu"].StdDev)
	zMem := zScore(float64(m.MemoryPercent), baseline["memory"].Mean, baseline["memory"].StdDev)
	zDisk := zScore(float64(m.DiskPercent), baseline["disk"].Mean, baseline["disk"].StdDev)
	zNet := zScore(float64(m.NetBytesSent+m.NetBytesRecv), baseline["network"].Mean, baseline["network"].StdDev)

	idx := computeLoadIndex(zCpu, zMem, zDisk, zNet)
	targetLevel := indexToLevel(idx)

	state.Baseline = baseline
	state.LoadIndex = idx

	// Determine candidateLevel using escalation / gradual-recovery rules.
	candidateLevel := state.ActiveRuleLevel
	reason := ""

	switch {
	case targetLevel > state.ActiveRuleLevel:
		// Immediate escalation to the required level.
		candidateLevel = targetLevel
		state.StableCount = 0
		reason = fmt.Sprintf("load index %.1f exceeded level-%d threshold; escalating to level %d (%d req/s)",
			idx, state.ActiveRuleLevel, candidateLevel, levelRateLimit[candidateLevel])

	case targetLevel < state.ActiveRuleLevel:
		// Gradual recovery: require 2 consecutive stable reports before stepping down.
		if state.StableCount < 2 {
			state.StableCount++
		}
		if state.StableCount >= 2 {
			candidateLevel = state.ActiveRuleLevel - 1
			if candidateLevel == 0 {
				reason = fmt.Sprintf("load index %.1f stable for 2 reports below level-1 threshold; restoring manual rules", idx)
			} else {
				reason = fmt.Sprintf("load index %.1f stable for 2 reports; stepping down from level %d to %d (%d req/s)",
					idx, state.ActiveRuleLevel, candidateLevel, levelRateLimit[candidateLevel])
			}
		}

	default:
		// Same level; reset the recovery counter.
		state.StableCount = 0
	}

	if candidateLevel == state.ActiveRuleLevel {
		return
	}

	// Oscillation protection: suppress publish when index changed < 10 units
	// since the last publish. This prevents rapid toggling near level boundaries.
	// Level-0 (rule removal) is exempt — it must always be logged so operators
	// can see when the adaptive rule was cleared.
	if candidateLevel > 0 && math.Abs(idx-state.LastPublishedIndex) < 10 {
		return
	}

	prevLevel := state.ActiveRuleLevel
	rateLimit := 0

	if candidateLevel > 0 {
		rateLimit = levelRateLimit[candidateLevel]
		publishAdaptiveScaleRule(agentID, rateLimit, candidateLevel)
	} else {
		// Always delete the adaptive sentinel rule when returning to level 0,
		// regardless of whether manual rules exist to replace it.
		if delData, err := json.Marshal(map[string]int{"id": autoScaleRuleID}); err == nil {
			_ = messaging.Publish("policy.delete."+agentID, delData)
		}
		if hasManual := restoreManualRules(agentID); !hasManual {
			reason += " — no manual rules configured; adaptive rule cleared"
		}
	}

	logScalingDecision(ScalingDecision{
		Time:      time.Now(),
		AgentID:   agentID,
		LoadIndex: idx,
		ZCpu:      zCpu,
		ZMemory:   zMem,
		ZDisk:     zDisk,
		ZNetwork:  zNet,
		RateLimit: rateLimit,
		Reason:    reason,
	})

	log.Printf("Adaptive: agent=%s idx=%.1f z=[cpu:%.2f mem:%.2f disk:%.2f net:%.2f] level %d→%d rate=%d/s",
		agentID, idx, zCpu, zMem, zDisk, zNet, prevLevel, candidateLevel, rateLimit)

	state.ActiveRuleLevel = candidateLevel
	state.LastPublishedIndex = idx
	state.LastPublished = time.Now()
	if candidateLevel < prevLevel {
		state.StableCount = 0
	}
}

// publishAdaptiveScaleRule sends a temporary rate-limit rule to agentID via
// policy.update.<agentID>. Uses the sentinel autoScaleRuleID so it can be
// cleanly replaced on the next level change.
func publishAdaptiveScaleRule(agentID string, threshold, level int) {
	rule := models.PolicyRule{
		ID:        autoScaleRuleID,
		Name:      fmt.Sprintf("adaptive-level%d-%s", level, agentID),
		Threshold: threshold,
		Action:    "rate_limit",
		Duration:  0,
		Topic:     agentID,
	}
	data, err := json.Marshal(rule)
	if err != nil {
		log.Printf("Adaptive: marshal error for agent %s: %v", agentID, err)
		return
	}
	if err := messaging.Publish("policy.update."+agentID, data); err != nil {
		log.Printf("Adaptive: publish error for agent %s: %v", agentID, err)
	}
}

// restoreManualRules fetches rules whose topic matches agentID from policy_rules
// and publishes each one to policy.update.<agentID>.
// Returns true if at least one manual rule was published.
// The caller is responsible for deleting the adaptive sentinel before calling this.
func restoreManualRules(agentID string) bool {
	rows, err := db.DB.Query(`
		SELECT id, name, threshold, action, duration, topic, created_at
		FROM policy_rules
		WHERE topic = $1
		ORDER BY created_at DESC`,
		agentID,
	)
	if err != nil {
		log.Printf("Adaptive: query manual rules for %s: %v", agentID, err)
		return false
	}
	defer rows.Close()

	var rules []models.PolicyRule
	for rows.Next() {
		var r models.PolicyRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Threshold, &r.Action, &r.Duration, &r.Topic, &r.CreatedAt); err != nil {
			continue
		}
		rules = append(rules, r)
	}

	if len(rules) == 0 {
		return false
	}

	for _, r := range rules {
		data, _ := json.Marshal(r)
		if err := messaging.Publish("policy.update."+agentID, data); err != nil {
			log.Printf("Adaptive: publish manual rule %d to %s: %v", r.ID, agentID, err)
		}
	}
	return true
}

// logScalingDecision inserts a scaling event into the scaling_decisions table.
func logScalingDecision(d ScalingDecision) {
	_, err := db.DB.Exec(`
		INSERT INTO scaling_decisions
			(time, agent_id, load_index, z_cpu, z_memory, z_disk, z_network, rate_limit, reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		d.Time, d.AgentID, d.LoadIndex,
		d.ZCpu, d.ZMemory, d.ZDisk, d.ZNetwork,
		d.RateLimit, d.Reason,
	)
	if err != nil {
		log.Printf("Adaptive: log decision for %s: %v", d.AgentID, err)
	}
}
